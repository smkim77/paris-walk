-- 순위표 데이터 옮기기 (예전 Supabase 프로젝트 → 새 프로젝트)
--
-- 1) 예전 프로젝트의 SQL Editor에서 이 파일 전체를 실행하세요.
--    결과는 migration_sql 칸 하나로 나와요. 그 칸의 내용(begin; … commit;)을 통째로 복사하세요.
-- 2) 새 프로젝트의 SQL Editor(setup.sql을 이미 실행한 곳)에 붙여 넣고 실행하세요.
--
-- 여러 번 실행해도 안전해요: 이미 있는 플레이어(같은 id)와 이미 옮긴 기록(같은 플레이어·같은 시각)은 건너뛰어요.
-- 그래서 게임을 새 프로젝트로 바꾼 뒤에도 예전 페이지를 열어 둔 사람이 예전 프로젝트에 남긴 기록을,
-- 나중에 한 번 더 실행해서 마저 옮길 수 있어요.
-- 플레이어의 비밀값은 해시(sha256)로만 저장돼 있어서 그대로 옮기면 돼요. 각자의 브라우저에 있는
-- 플레이어 정보로 새 프로젝트에서도 같은 닉네임·기록을 계속 쓸 수 있어요.

select
  'begin;' || E'\n'
  || coalesce((
    select string_agg(format(
      'insert into public.players (id, secret_hash, nickname, avatar, created_at) values (%L, %L, %L, %L, %L) on conflict (id) do nothing;',
      id, secret_hash, nickname, avatar, created_at), E'\n' order by created_at)
    from public.players), '')
  || E'\n'
  || coalesce((
    select string_agg(format(
      'insert into public.runs (player_id, score, dist, place, duration_ms, mode, created_at) select %L, %s, %s, %s, %s, %L, %L where not exists (select 1 from public.runs where player_id = %L and created_at = %L);',
      player_id, score, dist, place, duration_ms, mode, created_at, player_id, created_at), E'\n' order by created_at)
    from public.runs), '')
  || E'\n' || 'commit;' as migration_sql,
  (select count(*) from public.players) as players,
  (select count(*) from public.runs) as runs;

-- 옮긴 뒤 새 프로젝트에서 개수를 맞춰 보려면:
--   select (select count(*) from public.players) as players, (select count(*) from public.runs) as runs;
