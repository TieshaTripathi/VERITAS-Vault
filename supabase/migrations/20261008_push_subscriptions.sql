-- Migration: 20261008_push_subscriptions.sql
-- Description: Idempotent migration for Web Push subscriptions table with RLS and service role access.

create table if not exists public.push_subscriptions (
  id uuid primary key default gen_random_uuid(),
  user_id text,
  endpoint text unique not null,
  p256dh text not null,
  auth text not null,
  user_agent text,
  device_label text,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now(),
  enabled boolean not null default true
);

-- Ensure all columns exist even if an older push_subscriptions table was present
alter table public.push_subscriptions add column if not exists user_id text;
alter table public.push_subscriptions add column if not exists user_agent text;
alter table public.push_subscriptions add column if not exists device_label text;
alter table public.push_subscriptions add column if not exists updated_at timestamptz not null default now();
alter table public.push_subscriptions add column if not exists enabled boolean not null default true;

create index if not exists idx_push_subs_user on public.push_subscriptions(user_id);
create index if not exists idx_push_subs_enabled on public.push_subscriptions(enabled);

-- Enforce Row Level Security
alter table public.push_subscriptions enable row level security;

-- Zero Direct Browser Access: Revoke all from public/anon/authenticated
revoke all on public.push_subscriptions from anon, authenticated;

-- Least privilege: backend service_role only
grant select, insert, update, delete on public.push_subscriptions to service_role;
