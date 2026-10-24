-- Ejecutar en Supabase > SQL Editor
create table if not exists public.users (
  id            uuid primary key default gen_random_uuid(),
  username      text unique not null,
  password_hash text not null,
  totp_secret   text,
  mfa_status    text not null default 'DISABLED'
                check (mfa_status in ('DISABLED', 'PENDING_VERIFICATION', 'ACTIVE')),
  backup_codes  jsonb not null default '[]'::jsonb,
  created_at    timestamptz not null default now()
);

-- Sin políticas: solo el backend (service_role key) puede leer/escribir.
alter table public.users enable row level security;
