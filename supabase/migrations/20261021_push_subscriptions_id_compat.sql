-- Migration: 20261021_push_subscriptions_id_compat.sql
-- Description: Idempotent compatibility safeguard for public.push_subscriptions id column.
-- Ensures that if the production table was created with an id column lacking a default expression,
-- a fallback default (gen_random_uuid()::text) is attached.
--
-- Note: The application layer (/api/push/subscribe) provides deterministic RFC 4122 UUIDv5
-- subscription IDs on all inserts and upserts. This database migration provides defense-in-depth
-- for direct SQL or third-party insertions without modifying or dropping any table or existing data.

do $$
begin
  -- Check if id column exists without a default
  if exists (
    select 1
    from information_schema.columns
    where table_schema = 'public'
      and table_name = 'push_subscriptions'
      and column_name = 'id'
      and column_default is null
  ) then
    -- If id is text or varchar, set default to gen_random_uuid()::text
    if exists (
      select 1
      from information_schema.columns
      where table_schema = 'public'
        and table_name = 'push_subscriptions'
        and column_name = 'id'
        and data_type in ('text', 'character varying')
    ) then
      alter table public.push_subscriptions alter column id set default gen_random_uuid()::text;
    -- If id is uuid, set default to gen_random_uuid()
    elsif exists (
      select 1
      from information_schema.columns
      where table_schema = 'public'
        and table_name = 'push_subscriptions'
        and column_name = 'id'
        and data_type = 'uuid'
    ) then
      alter table public.push_subscriptions alter column id set default gen_random_uuid();
    end if;
  end if;
end $$;
