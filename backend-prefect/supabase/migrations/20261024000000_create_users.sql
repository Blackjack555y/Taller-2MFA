-- Aplicar con: supabase db push (o pegar en Supabase > SQL Editor)
create table if not exists public.users (
    id uuid primary key default gen_random_uuid(),
    username text unique not null,
    password_hash text not null,
    mfa_state text not null default 'DISABLED'
        check (mfa_state in ('DISABLED', 'PENDING_VERIFICATION', 'ACTIVE')),
    totp_secret text,
    backup_code_hashes jsonb not null default '[]'::jsonb,
    created_at timestamptz not null default now()
);

-- El backend usa la service_role key; se activa RLS sin políticas para
-- que la tabla no quede expuesta a la anon key.
alter table public.users enable row level security;
