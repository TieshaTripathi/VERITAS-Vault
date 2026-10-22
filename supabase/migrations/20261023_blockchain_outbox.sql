-- Migration: 20261023_blockchain_outbox.sql
-- Description: Idempotent migration for durable audit batching, blockchain outbox queues,
--              atomic worker claiming (SKIP LOCKED), and strict Zero-Trust RLS.

begin;

-- =============================================================================
-- 1. Immutable Audit Batches
-- =============================================================================
create table if not exists public.audit_batches (
  batch_id text primary key,
  root_hash text not null,
  first_sequence bigint not null,
  last_sequence bigint not null,
  event_count integer not null,
  event_ids jsonb not null default '[]'::jsonb,
  leaf_hashes jsonb not null default '[]'::jsonb,
  created_at timestamptz not null default now()
);

create index if not exists idx_audit_batches_seq on public.audit_batches(first_sequence, last_sequence);
create index if not exists idx_audit_batches_root on public.audit_batches(root_hash);

-- Idempotent check constraints for audit batches
do $$
begin
  if not exists (
    select 1 from information_schema.table_constraints
    where constraint_name = 'chk_audit_batches_bounds'
      and table_schema = 'public'
      and table_name = 'audit_batches'
  ) then
    alter table public.audit_batches
      add constraint chk_audit_batches_bounds
      check (first_sequence >= 1 and last_sequence >= first_sequence and event_count >= 1);
  end if;
end $$;


-- =============================================================================
-- 2. Blockchain Outbox Jobs (Decoupled per target network)
-- =============================================================================
create table if not exists public.blockchain_outbox (
  job_id text primary key,
  network text not null,
  batch_id text not null references public.audit_batches(batch_id) on delete restrict,
  status text not null default 'PENDING',
  attempts integer not null default 0,
  max_retries integer not null default 5,
  lease_holder text,
  lease_expires_at timestamptz,
  next_attempt_at timestamptz not null default now(),
  last_error text,
  tx_hash text,
  block_number bigint,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);

-- Ensure all columns exist idempotently if table was pre-existing
alter table public.blockchain_outbox add column if not exists network text;
alter table public.blockchain_outbox add column if not exists batch_id text;
alter table public.blockchain_outbox add column if not exists status text default 'PENDING';
alter table public.blockchain_outbox add column if not exists attempts integer default 0;
alter table public.blockchain_outbox add column if not exists max_retries integer default 5;
alter table public.blockchain_outbox add column if not exists lease_holder text;
alter table public.blockchain_outbox add column if not exists lease_expires_at timestamptz;
alter table public.blockchain_outbox add column if not exists next_attempt_at timestamptz default now();
alter table public.blockchain_outbox add column if not exists last_error text;
alter table public.blockchain_outbox add column if not exists tx_hash text;
alter table public.blockchain_outbox add column if not exists block_number bigint;
alter table public.blockchain_outbox add column if not exists updated_at timestamptz default now();

-- Ensure foreign key constraint exists idempotently
do $$
begin
  if not exists (
    select 1 from information_schema.table_constraints
    where constraint_name = 'blockchain_outbox_batch_id_fkey'
      and table_schema = 'public'
      and table_name = 'blockchain_outbox'
  ) then
    alter table public.blockchain_outbox
      add constraint blockchain_outbox_batch_id_fkey
      foreign key (batch_id) references public.audit_batches(batch_id)
      on delete restrict;
  end if;
end $$;

-- Enforce exactly one active job per (network, batch_id)
create unique index if not exists idx_outbox_network_batch on public.blockchain_outbox(network, batch_id);

-- Composite indexes for high-throughput worker claiming and polling
create index if not exists idx_outbox_claim_pending on public.blockchain_outbox(network, status, next_attempt_at);
create index if not exists idx_outbox_claim_lease on public.blockchain_outbox(network, status, lease_expires_at);

-- Idempotent check constraints for outbox jobs
do $$
begin
  if not exists (
    select 1 from information_schema.table_constraints
    where constraint_name = 'chk_outbox_status'
      and table_schema = 'public'
      and table_name = 'blockchain_outbox'
  ) then
    alter table public.blockchain_outbox
      add constraint chk_outbox_status
      check (status in ('PENDING', 'SUBMITTED', 'CONFIRMED', 'RETRY', 'FAILED'));
  end if;

  if not exists (
    select 1 from information_schema.table_constraints
    where constraint_name = 'chk_outbox_network'
      and table_schema = 'public'
      and table_name = 'blockchain_outbox'
  ) then
    alter table public.blockchain_outbox
      add constraint chk_outbox_network
      check (network in ('sepolia', 'besu'));
  end if;

  if not exists (
    select 1 from information_schema.table_constraints
    where constraint_name = 'chk_outbox_attempts'
      and table_schema = 'public'
      and table_name = 'blockchain_outbox'
  ) then
    alter table public.blockchain_outbox
      add constraint chk_outbox_attempts
      check (attempts >= 0 and max_retries >= 1);
  end if;
end $$;


-- =============================================================================
-- 3. Row-Level Security: Zero Direct Browser Access
-- =============================================================================
alter table public.audit_batches enable row level security;
alter table public.blockchain_outbox enable row level security;

-- Revoke all access from public, anon, and authenticated roles
revoke all on public.audit_batches, public.blockchain_outbox from public, anon, authenticated;

-- Least privilege: backend service_role only
grant select, insert, update, delete on public.audit_batches, public.blockchain_outbox to service_role;


-- =============================================================================
-- 4. Database-Level Atomic Worker Claiming RPC (SKIP LOCKED)
-- =============================================================================
create or replace function public.claim_blockchain_outbox_jobs(
  p_network text,
  p_worker_id text,
  p_limit integer default 5,
  p_lease_seconds integer default 30
) returns setof public.blockchain_outbox
language plpgsql
security definer
set search_path = public, pg_temp
as $$
begin
  -- 1. Transition poison-pill expired jobs (attempts >= max_retries) to FAILED
  update public.blockchain_outbox
  set status = 'FAILED',
      lease_holder = null,
      lease_expires_at = null,
      last_error = coalesce(last_error, '') || ' [Lease expired after max retries]',
      updated_at = now()
  where network = lower(p_network)
    and status = 'SUBMITTED'
    and lease_expires_at < now()
    and attempts >= max_retries;

  -- 2. Atomically claim eligible jobs without worker collision
  return query
  with eligible as (
    select job_id
    from public.blockchain_outbox
    where network = lower(p_network)
      and (
        status = 'PENDING'
        or (status = 'RETRY' and next_attempt_at <= now())
        or (status = 'SUBMITTED' and lease_expires_at < now() and attempts < max_retries)
      )
    order by next_attempt_at asc, created_at asc
    limit p_limit
    for update skip locked
  )
  update public.blockchain_outbox o
  set status = 'SUBMITTED',
      lease_holder = p_worker_id,
      lease_expires_at = now() + (p_lease_seconds || ' seconds')::interval,
      attempts = o.attempts + 1,
      updated_at = now()
  from eligible e
  where o.job_id = e.job_id
  returning o.*;
end;
$$;

revoke all on function public.claim_blockchain_outbox_jobs(text, text, integer, integer) from public, anon, authenticated;
grant execute on function public.claim_blockchain_outbox_jobs(text, text, integer, integer) to service_role;


-- =============================================================================
-- 5. Expired Lease Recovery RPC
-- =============================================================================
create or replace function public.recover_expired_outbox_leases(
  p_network text default null
) returns integer
language plpgsql
security definer
set search_path = public, pg_temp
as $$
declare
  v_recovered integer;
begin
  -- Fail poison pills
  update public.blockchain_outbox
  set status = 'FAILED',
      lease_holder = null,
      lease_expires_at = null,
      last_error = coalesce(last_error, '') || ' [Lease expired after max retries]',
      updated_at = now()
  where (p_network is null or network = lower(p_network))
    and status = 'SUBMITTED'
    and lease_expires_at < now()
    and attempts >= max_retries;

  -- Recover expired submitted jobs back to PENDING
  with recovered as (
    update public.blockchain_outbox
    set status = 'PENDING',
        lease_holder = null,
        lease_expires_at = null,
        updated_at = now()
    where (p_network is null or network = lower(p_network))
      and status = 'SUBMITTED'
      and lease_expires_at < now()
      and attempts < max_retries
    returning 1
  )
  select count(*)::integer into v_recovered from recovered;

  return v_recovered;
end;
$$;

revoke all on function public.recover_expired_outbox_leases(text) from public, anon, authenticated;
grant execute on function public.recover_expired_outbox_leases(text) to service_role;

commit;
