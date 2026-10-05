-- ============================================================
-- 恋爱纪念站 · Supabase 初始化 SQL
-- 用法:在 Supabase 项目里打开 SQL Editor,整段粘贴运行一次即可
-- ============================================================

-- 1) 数据表:site 存整站数据,secrets 存两个密码的哈希
create table if not exists public.site (
  id text primary key default 'main',
  data jsonb not null default '{}'::jsonb,
  updated_at timestamptz default now()
);

create table if not exists public.secrets (
  id text primary key default 'main',
  access_hash text not null default '',
  admin_hash text not null default ''
);

-- 2) 行级安全
alter table public.site enable row level security;
alter table public.secrets enable row level security;

-- site 允许匿名读(整站数据公开读,和现状一致)
drop policy if exists site_public_read on public.site;
create policy site_public_read on public.site for select using (true);

-- secrets 不加任何策略 -> 匿名完全读不到

-- 3) 授权(新版 Supabase 需显式授权才能用 Data API)
grant usage on schema public to anon, authenticated;
grant select on public.site to anon, authenticated;

-- 4) 鉴权函数(全部 SECURITY DEFINER:匿名可执行,函数内部比对哈希)
create or replace function public.get_state()
returns table (has_access boolean, has_admin boolean)
language plpgsql security definer set search_path = public as $$
begin
  return query
    select
      coalesce((select access_hash <> '' from public.secrets where id = 'main'), false) as has_access,
      coalesce((select admin_hash  <> '' from public.secrets where id = 'main'), false) as has_admin;
end $$;

create or replace function public.check_access(p_hash text)
returns boolean language sql security definer set search_path = public as $$
  select coalesce((select access_hash = p_hash from public.secrets where id = 'main'), false);
$$;

create or replace function public.check_admin(p_hash text)
returns boolean language sql security definer set search_path = public as $$
  select coalesce((select admin_hash = p_hash from public.secrets where id = 'main'), false);
$$;

create or replace function public.set_access_hash(p_admin_hash text, p_new_hash text)
returns void language plpgsql security definer set search_path = public as $$
declare cur text;
begin
  insert into public.secrets(id) values('main') on conflict(id) do nothing;
  cur := (select admin_hash from public.secrets where id = 'main');
  if coalesce(cur,'') <> '' and coalesce(p_admin_hash,'') <> cur then
    raise exception '鉴权失败';
  end if;
  update public.secrets set access_hash = coalesce(p_new_hash,'') where id = 'main';
end $$;

create or replace function public.set_admin_hash(p_admin_hash text, p_new_hash text)
returns void language plpgsql security definer set search_path = public as $$
declare cur text;
begin
  insert into public.secrets(id) values('main') on conflict(id) do nothing;
  cur := (select admin_hash from public.secrets where id = 'main');
  if coalesce(cur,'') <> '' and coalesce(p_admin_hash,'') <> cur then
    raise exception '鉴权失败';
  end if;
  update public.secrets set admin_hash = coalesce(p_new_hash,'') where id = 'main';
end $$;

create or replace function public.save_site(p_admin_hash text, p_data jsonb)
returns void language plpgsql security definer set search_path = public as $$
begin
  if coalesce(p_admin_hash,'') = '' or p_admin_hash <> coalesce((select admin_hash from public.secrets where id='main'),'') then
    raise exception '鉴权失败';
  end if;
  insert into public.site(id, data, updated_at) values('main', p_data, now())
    on conflict(id) do update set data = excluded.data, updated_at = now();
end $$;

create or replace function public.bootstrap(p_access_hash text, p_admin_hash text, p_data jsonb)
returns void language plpgsql security definer set search_path = public as $$
begin
  insert into public.secrets(id, access_hash, admin_hash) values('main','','')
    on conflict(id) do nothing;
  if (select coalesce(access_hash,'') || coalesce(admin_hash,'') from public.secrets where id='main') <> '' then
    raise exception '已初始化过,不能重复同步';
  end if;
  update public.secrets set access_hash = coalesce(p_access_hash,''), admin_hash = coalesce(p_admin_hash,'') where id='main';
  insert into public.site(id, data, updated_at) values('main', p_data, now())
    on conflict(id) do update set data = excluded.data, updated_at = now();
end $$;

create or replace function public.reset_all(p_admin_hash text, p_data jsonb)
returns void language plpgsql security definer set search_path = public as $$
begin
  if coalesce(p_admin_hash,'') = '' or p_admin_hash <> coalesce((select admin_hash from public.secrets where id='main'),'') then
    raise exception '鉴权失败';
  end if;
  update public.secrets set access_hash='', admin_hash='' where id='main';
  insert into public.site(id, data, updated_at) values('main', p_data, now())
    on conflict(id) do update set data = excluded.data, updated_at = now();
end $$;

grant execute on function public.get_state() to anon, authenticated;
grant execute on function public.check_access(text) to anon, authenticated;
grant execute on function public.check_admin(text) to anon, authenticated;
grant execute on function public.set_access_hash(text,text) to anon, authenticated;
grant execute on function public.set_admin_hash(text,text) to anon, authenticated;
grant execute on function public.save_site(text,jsonb) to anon, authenticated;
grant execute on function public.bootstrap(text,text,jsonb) to anon, authenticated;
grant execute on function public.reset_all(text,jsonb) to anon, authenticated;

-- 5) 图片存储桶(公开读,允许匿名上传)
insert into storage.buckets (id, name, public) values ('images','images', true)
  on conflict (id) do nothing;

drop policy if exists images_public_read on storage.objects;
create policy images_public_read on storage.objects for select using (bucket_id = 'images');

drop policy if exists images_public_insert on storage.objects;
create policy images_public_insert on storage.objects for insert with check (bucket_id = 'images');
