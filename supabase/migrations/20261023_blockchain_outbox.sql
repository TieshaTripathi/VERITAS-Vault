-- Migration: 20261023_blockchain_outbox.sql
-- Description: Idempotent migration for durable audit batching and blockchain outbox queues with RLS.

-- 1. Immutable Audit Batches
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

-- 2. Blockchain Outbox Jobs (Decoupled per target network)
create table if not exists public.blockchain_outbox (
  job_id text primary key,
  network text not null,
  batch_id text not null references public.audit_batches(batch_id),
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

-- Ensure all columns exist idempotently if table already existed
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

create index if not exists idx_outbox_network_status on public.blockchain_outbox(network, status);
create index if not exists idx_outbox_sched on public.blockchain_outbox(status, next_attempt_at);
create index if not exists idx_outbox_lease on public.blockchain_outbox(lease_expires_at);

-- 3. Row-Level Security: Zero Direct Browser Access
alter table public.audit_batches enable row level security;
alter table public.blockchain_outbox enable row level security;

revoke all on public.audit_batches, public.blockchain_outbox from anon, authenticated;

-- 4. Least Privilege: Backend service_role access only
grant select, insert, update, delete on public.audit_batches, public.blockchain_outbox to service_role;
