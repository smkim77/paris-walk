-- 파리 산책하기 스코어보드 설정 (일반 / 하드 순위표)
-- Supabase 대시보드 → SQL Editor → New query 에 이 파일 전체를 붙여 넣고 Run 하세요.
-- 여러 번 실행해도 안전해요.
--
-- 구조
--   players : 브라우저마다 만든 플레이어 ID, 비밀값의 해시, 닉네임, 프로필 이모지
--   runs    : 한 판 한 판의 기록 (점수, 거리, 도착한 명소, 걸린 시간, 난이도 normal/hard)
--   게임은 아래 함수로만 읽고 써요. 테이블은 API로 직접 읽거나 쓸 수 없어요.
--     submit_run   : 기록 올리기 (비밀값 확인, 말이 안 되는 기록 거르기)
--     save_profile : 닉네임·이모지 저장
--     leaderboard  : 전체 / 이번 주 순위 (한 사람당 최고 기록 하나)
--   실제 검사·저장은 API로 공개되지 않는 private 스키마의 함수(security definer)가 맡고,
--   public 스키마에는 그 함수를 불러주기만 하는 얇은 창구(security invoker)만 둬요.

create extension if not exists pgcrypto with schema extensions;

-- 프로필 이모지 12가지 (게임 화면의 선택지와 같아야 해요)
create table if not exists public.players (
  id          uuid primary key,
  secret_hash text not null,
  nickname    text not null check (char_length(nickname) between 1 and 12),
  avatar      text check (avatar is null or avatar in ('🥖','🗼','🐕','🐦','👞','🥐','🧀','🍷','🎨','🚲','🐀','🎩')),
  created_at  timestamptz not null default now()
);

create table if not exists public.runs (
  id          bigint generated always as identity primary key,
  player_id   uuid not null references public.players(id) on delete cascade,
  score       integer not null check (score >= 0),
  dist        integer not null check (dist >= 0),
  place       smallint not null check (place between 0 and 4),
  duration_ms integer not null check (duration_ms >= 0),
  created_at  timestamptz not null default now()
);
create index if not exists runs_player_score_idx on public.runs (player_id, score desc);
-- 난이도 (하드 모드 순위표). 예전 기록은 모두 일반(normal)이에요.
alter table public.runs add column if not exists mode text not null default 'normal';
do $$ begin
  if not exists (select 1 from pg_constraint where conname = 'runs_mode_check') then
    alter table public.runs add constraint runs_mode_check check (mode in ('normal', 'hard'));
  end if;
end $$;
create index if not exists runs_mode_player_score_idx on public.runs (mode, player_id, score desc);
-- 난이도가 없던 예전 함수들은 지워요 (아래에서 난이도를 받는 새 함수로 다시 만들어요)
drop function if exists public.leaderboard(text, uuid);
drop function if exists public.submit_run(uuid, text, text, text, integer, integer, smallint, integer);
drop function if exists private.leaderboard(text, uuid);
drop function if exists private.submit_run(uuid, text, text, text, integer, integer, smallint, integer);
drop function if exists private.ranked(timestamptz);
create index if not exists runs_created_idx on public.runs (created_at);

alter table public.players enable row level security;
alter table public.runs    enable row level security;
revoke all on public.players, public.runs from anon, authenticated;
-- 일부러 아무도 통과 못 하는 정책을 둬요. 읽기·쓰기는 아래 함수로만 해요.
drop policy if exists "no direct api access" on public.players;
create policy "no direct api access" on public.players for all to anon, authenticated using (false) with check (false);
drop policy if exists "no direct api access" on public.runs;
create policy "no direct api access" on public.runs for all to anon, authenticated using (false) with check (false);

create schema if not exists private;
revoke all on schema private from public;
grant usage on schema private to anon, authenticated;

-- 출처 확인: 허용 목록의 주소(게임 페이지)에서 온 요청만 받아요.
create table if not exists private.allowed_origins (
  origin text primary key
);
alter table private.allowed_origins enable row level security;
revoke all on private.allowed_origins from public, anon, authenticated;
drop policy if exists "no api access" on private.allowed_origins;
create policy "no api access" on private.allowed_origins for all to anon, authenticated using (false) with check (false);
insert into private.allowed_origins (origin) values
  ('https://smkim77.github.io')   -- ← 게임이 올라가 있는 GitHub Pages 주소
on conflict do nothing;

-- 요청의 Origin 헤더가 허용 목록에 없으면 거부해요.
-- (SQL Editor처럼 API를 거치지 않는 관리자 실행, 그리고 내 PC의 localhost 테스트는 통과)
create or replace function private.check_origin()
returns void
language plpgsql
security definer
set search_path = ''
as $$
declare
  v_headers text := current_setting('request.headers', true);
  v_origin text;
begin
  if v_headers is null or v_headers = '' then
    return;
  end if;
  v_origin := lower(rtrim(coalesce(v_headers::json ->> 'origin', ''), '/'));
  if v_origin ~ '^http://(localhost|127\.0\.0\.1)(:[0-9]+)?$' then
    return;
  end if;
  if v_origin = '' or not exists (select 1 from private.allowed_origins a where lower(a.origin) = v_origin) then
    raise exception 'bad_origin';
  end if;
end;
$$;
revoke all on function private.check_origin() from public, anon, authenticated;

-- 공통 검증: 비밀값 확인, 닉네임·이모지 검사, 처음이면 플레이어 등록, 아니면 프로필 갱신
create or replace function private.check_player(p_player uuid, p_secret text, p_nickname text, p_avatar text)
returns void
language plpgsql
security definer
set search_path = public, extensions
as $$
declare
  v_hash text;
  v_nick text := btrim(coalesce(p_nickname, ''));
  v_existing public.players%rowtype;
begin
  perform private.check_origin();
  if p_player is null or p_secret is null or p_secret !~ '^[0-9a-f]{64}$' then
    raise exception 'bad_secret';
  end if;
  if char_length(v_nick) < 1 or char_length(v_nick) > 12 or v_nick ~ '[[:cntrl:]]' then
    raise exception 'bad_nickname';
  end if;
  if p_avatar is not null and p_avatar not in ('🥖','🗼','🐕','🐦','👞','🥐','🧀','🍷','🎨','🚲','🐀','🎩') then
    raise exception 'bad_avatar';
  end if;
  v_hash := encode(digest(p_secret, 'sha256'), 'hex');

  select * into v_existing from public.players where id = p_player;
  if not found then
    insert into public.players (id, secret_hash, nickname, avatar) values (p_player, v_hash, v_nick, p_avatar);
  elsif v_existing.secret_hash <> v_hash then
    raise exception 'bad_secret';
  else
    update public.players set nickname = v_nick, avatar = p_avatar
    where id = p_player and (nickname <> v_nick or avatar is distinct from p_avatar);
  end if;
end;
$$;
revoke all on function private.check_player(uuid, text, text, text) from public, anon, authenticated;

-- 이번 주의 시작 (한국 시간 월요일 0시)
create or replace function private.week_start()
returns timestamptz
language sql
stable
set search_path = ''
as $$
  select (date_trunc('week', now() at time zone 'Asia/Seoul')) at time zone 'Asia/Seoul';
$$;
revoke all on function private.week_start() from public, anon, authenticated;

-- 순위 계산: 그 난이도, 그 기간 안에서 플레이어마다 최고 기록 하나, 점수가 같으면 먼저 세운 기록이 위
create or replace function private.ranked(p_since timestamptz, p_mode text)
returns table (rank bigint, player_id uuid, score integer, dist integer, place smallint, created_at timestamptz)
language sql
stable
security definer
set search_path = ''
as $$
  with best as (
    select distinct on (r.player_id) r.player_id, r.score, r.dist, r.place, r.created_at
    from public.runs r
    where r.created_at >= p_since and r.mode = p_mode
    order by r.player_id, r.score desc, r.created_at asc
  )
  select row_number() over (order by b.score desc, b.created_at asc), b.player_id, b.score, b.dist, b.place, b.created_at
  from best b;
$$;
revoke all on function private.ranked(timestamptz, text) from public, anon, authenticated;

-- 순위표: 상위 10명 + (플레이어를 넘기면) 내 순위, 난이도별
create or replace function private.leaderboard(p_period text, p_player uuid, p_mode text)
returns jsonb
language plpgsql
stable
security definer
set search_path = ''
as $$
declare
  v_since timestamptz;
  v_top jsonb;
  v_me jsonb;
  v_total bigint;
begin
  if p_period = 'week' then
    v_since := private.week_start();
  elsif p_period = 'all' then
    v_since := '-infinity';
  else
    raise exception 'bad_period';
  end if;
  if p_mode is null or p_mode not in ('normal', 'hard') then
    raise exception 'bad_mode';
  end if;

  select coalesce(jsonb_agg(jsonb_build_object(
           'rank', t.rank, 'nickname', p.nickname, 'avatar', p.avatar,
           'score', t.score, 'dist', t.dist, 'place', t.place, 'mine', t.player_id = p_player
         ) order by t.rank), '[]'::jsonb)
  into v_top
  from private.ranked(v_since, p_mode) t
  join public.players p on p.id = t.player_id
  where t.rank <= 10;

  select count(*) into v_total from private.ranked(v_since, p_mode);

  select jsonb_build_object('rank', t.rank, 'score', t.score, 'dist', t.dist, 'place', t.place)
  into v_me
  from private.ranked(v_since, p_mode) t
  where t.player_id = p_player;

  return jsonb_build_object('period', p_period, 'mode', p_mode, 'top', v_top, 'me', v_me, 'total', v_total);
end;
$$;
revoke all on function private.leaderboard(text, uuid, text) from public;
grant execute on function private.leaderboard(text, uuid, text) to anon, authenticated;

-- 기록 올리기
--   말이 안 되는 기록은 거절해요:
--     점수는 거리의 2배(최고 속도 배율)를 넘을 수 없음
--     게임 속 최고 속도는 초당 약 21m라서, 걸린 시간보다 너무 멀리 간 기록은 거절
--     같은 플레이어가 3초 안에 다시 올리면 거절
create or replace function private.submit_run(
  p_player uuid, p_secret text, p_nickname text, p_avatar text,
  p_score integer, p_dist integer, p_place smallint, p_duration_ms integer, p_mode text
)
returns jsonb
language plpgsql
security definer
set search_path = public, extensions
as $$
declare
  v_all jsonb;
  v_week jsonb;
begin
  if p_score is null or p_dist is null or p_place is null or p_duration_ms is null
     or p_score < 0 or p_dist < 0 or p_dist > 200000 or p_place not between 0 and 4
     or p_duration_ms < 1000 or p_duration_ms > 21600000
     or p_score > p_dist * 2 + 5
     or p_dist > (p_duration_ms / 1000.0) * 25 + 20 then
    raise exception 'bad_score';
  end if;
  if p_mode is null or p_mode not in ('normal', 'hard') then
    raise exception 'bad_mode';
  end if;

  perform private.check_player(p_player, p_secret, p_nickname, p_avatar);

  if exists (select 1 from public.runs where player_id = p_player and created_at > now() - interval '3 seconds') then
    raise exception 'too_fast';
  end if;

  insert into public.runs (player_id, score, dist, place, duration_ms, mode)
  values (p_player, p_score, p_dist, p_place, p_duration_ms, p_mode);

  v_all := private.leaderboard('all', p_player, p_mode);
  v_week := private.leaderboard('week', p_player, p_mode);
  return jsonb_build_object('status', 'ok', 'all', v_all, 'week', v_week);
end;
$$;
revoke all on function private.submit_run(uuid, text, text, text, integer, integer, smallint, integer, text) from public;
grant execute on function private.submit_run(uuid, text, text, text, integer, integer, smallint, integer, text) to anon, authenticated;

create or replace function private.save_profile(p_player uuid, p_secret text, p_nickname text, p_avatar text)
returns jsonb
language plpgsql
security definer
set search_path = public, extensions
as $$
begin
  perform private.check_player(p_player, p_secret, p_nickname, p_avatar);
  return jsonb_build_object('status', 'ok');
end;
$$;
revoke all on function private.save_profile(uuid, text, text, text) from public;
grant execute on function private.save_profile(uuid, text, text, text) to anon, authenticated;

-- 게임이 부르는 공개 창구 (/rest/v1/rpc/…). p_mode를 안 보내면 일반 순위표예요.
create or replace function public.leaderboard(p_period text, p_player uuid default null, p_mode text default 'normal')
returns jsonb
language sql
stable
security invoker
set search_path = ''
as $$
  select private.leaderboard(p_period, p_player, p_mode);
$$;
revoke all on function public.leaderboard(text, uuid, text) from public;
grant execute on function public.leaderboard(text, uuid, text) to anon, authenticated;

create or replace function public.submit_run(
  p_player uuid, p_secret text, p_nickname text, p_avatar text,
  p_score integer, p_dist integer, p_place smallint, p_duration_ms integer, p_mode text default 'normal'
)
returns jsonb
language sql
security invoker
set search_path = ''
as $$
  select private.submit_run(p_player, p_secret, p_nickname, p_avatar, p_score, p_dist, p_place, p_duration_ms, p_mode);
$$;
revoke all on function public.submit_run(uuid, text, text, text, integer, integer, smallint, integer, text) from public;
grant execute on function public.submit_run(uuid, text, text, text, integer, integer, smallint, integer, text) to anon, authenticated;

create or replace function public.save_profile(p_player uuid, p_secret text, p_nickname text, p_avatar text)
returns jsonb
language sql
security invoker
set search_path = ''
as $$
  select private.save_profile(p_player, p_secret, p_nickname, p_avatar);
$$;
revoke all on function public.save_profile(uuid, text, text, text) from public;
grant execute on function public.save_profile(uuid, text, text, text) to anon, authenticated;

-- 프로젝트를 만들 때 "Enable automatic RLS"를 켜면 Supabase가 만드는 함수예요. 외부에서 부를 이유가 없으니 막아요.
do $$ begin
  if to_regprocedure('public.rls_auto_enable()') is not null then
    revoke execute on function public.rls_auto_enable() from public, anon, authenticated;
  end if;
end $$;

-- PostgREST가 새 함수를 바로 알아보도록 스키마 캐시를 새로 고쳐요.
notify pgrst, 'reload schema';

-- API가 바뀐 함수 목록을 바로 알아채도록
notify pgrst, 'reload schema';
