-- ============================================================================
-- RowsAffected — FUNCTION-SURFACE DETECTORS (E1/E2/E3), companion to v3
-- ⚠️ SNAPSHOT, NOT THE SOURCE OF TRUTH. The RowsAffected repo holds the
--    authoritative copy. Diff against it before reusing this file — a stale
--    snapshot re-handed-off is how a fixed bug comes back.
-- ============================================================================
-- Same 8-column output shape as v3 so ONE formatter handles both. Column reuse
-- for function findings: table_name = the function's identity signature,
-- role_name = the grantee at fault, ungoverned_operation = EXECUTE|SEARCH_PATH.
-- COUNTING: exclude severity = 'INFO', exactly as v3.
--
-- E1  PUBLIC holds EXECUTE on a SECURITY DEFINER function.
--     Postgres grants EXECUTE to PUBLIC on EVERY new function, so a hit is
--     always a default nobody chose. SEVERITY SPLIT, and it is load-bearing:
--       * returns trigger  -> HYGIENE. A direct call raises regardless, so
--         there is no exploitable surface. Flagging it as high would cry wolf
--         and train people past the whole report.
--       * anything else    -> PRIVILEGE_ESCALATION_RISK. A definer function
--         runs as its owner; PUBLIC EXECUTE means any client role can invoke
--         it with the owner's rights.
--     ⚠️ REVOKE MUST NAME BOTH SOURCES. Measured on ClosetLink 2026-08-13:
--     fn_flag_message held EXECUTE via a PUBLIC row AND direct anon/authenticated
--     rows simultaneously. `revoke ... from public` alone leaves the direct
--     grants; `revoke ... from anon, authenticated` alone leaves PUBLIC.
--     The remediation text below therefore names all three.
--
-- E2  search_path stored as ONE quoted element containing a comma.
--     `SET search_path TO 'public, pg_temp'` names a single schema whose name
--     is literally "public, pg_temp". No such schema exists, so the effective
--     search path is EMPTY and the function fails at call time.
--     ⛔ DELIBERATELY BROAD: ANY function, ANY prokind, NO prosecdef filter. The
--     form is broken regardless of security mode — an INVOKER function with a
--     quoted-literal search_path is exactly as dead as a DEFINER one, and the bug
--     has nothing to do with privilege. NOT A STYLE CALL: ClosetLink's production
--     event trigger (appendix below) says so in its own Rule 2 comment — "Applies
--     to INVOKER functions too: the form is broken regardless of security mode,
--     and restricting it to DEFINER is exactly how five of these survived the last
--     sweep." Narrowing E2 to DEFINER reintroduces that miss and drops the
--     fn_invoker_quoted() fixture case.
--     PRODUCTION EVIDENCE: 3 casualties on ClosetLink, one an 11-MONTH silent
--     outage (every avatar upload failed from 2025-08-17). All three were found
--     while investigating something else; the list that described them as safe
--     had a detection rate of ZERO FOR THREE.
--     ⛔ SHIP THE PREVENTIVE TRIGGER WITH THE FINDING — see the appendix at the
--     bottom of this file. A DDL-time event trigger makes the bug impossible;
--     this scanner only finds damage already done.
--
-- E3  SECURITY DEFINER function with NO search_path pinned at all.
--     The canonical Supabase privilege-escalation vector: the caller controls
--     resolution, so an attacker-created object earlier in the path can be
--     executed with the owner's rights. Zero hits on ClosetLink BECAUSE an
--     event trigger enforces it — which is exactly why it is worth shipping.
--
-- 🚨 ONE OBJECT CAN TRIGGER SEVERAL DETECTORS — GROUP BY OBJECT WHEN RENDERING.
-- A definer function with an unpinned search_path AND PUBLIC EXECUTE is ONE
-- broken object that legitimately fires E1 and E3. Measured on the validation
-- fixture: 4 objects produced 6 findings. A formatter that lists rows will
-- report "6 problems" for 4 things to fix, which reads as inflation and is the
-- fastest way to lose a reader's trust in the whole report.
-- THIS IS NOT LEFT AS A COMMENT: the INFO banner row emits BOTH counts, so a
-- renderer claiming 6 problems is contradicted by its own header row.
-- ============================================================================
WITH findings AS (

SELECT 'E1_PUBLIC_EXECUTE_ON_DEFINER' AS finding_type,
       CASE WHEN p.prorettype = 'trigger'::regtype
            THEN 'HYGIENE' ELSE 'PRIVILEGE_ESCALATION_RISK' END AS severity,
       n.nspname AS schema_name,
       p.oid::regprocedure::text AS table_name,
       'PUBLIC' AS role_name,
       'EXECUTE' AS ungoverned_operation,
       format('SECURITY DEFINER function %s is EXECUTE-able by PUBLIC. Postgres grants EXECUTE to PUBLIC on every new function, so this is a default, not a decision. %s Remediate with: REVOKE EXECUTE ON FUNCTION %s FROM public, anon, authenticated;  -- NAME ALL THREE: the grant can live on PUBLIC and as direct role rows simultaneously, and revoking either alone is a silent no-op.',
              p.oid::regprocedure::text,
              CASE WHEN p.prorettype = 'trigger'::regtype
                   THEN 'This returns trigger, so a direct call raises regardless — a convention violation, not an exploitable surface.'
                   ELSE 'This is directly callable and runs as its owner, so any client role can invoke it with the owner''s rights.' END,
              p.oid::regprocedure::text) AS explanation,
       'LIMIT: this scan reports the CURRENT grant state. It cannot tell an intended grant from a forgotten default — confirm intent before revoking, and re-check by effect (has_function_privilege) rather than by the statement exiting 0.' AS caveat
  FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace
 WHERE p.prosecdef AND p.prokind = 'f'
   AND n.nspname NOT IN ('pg_catalog','information_schema')
   AND (COALESCE(current_setting('rowsaffected.include_system', true),'off') = 'on'
        OR n.nspname NOT IN ('auth','storage','cron','vault','realtime','_realtime','graphql',
                             'graphql_public','extensions','pgsodium','pgsodium_masks','net',
                             'supabase_functions','supabase_migrations','pgbouncer'))
   AND has_function_privilege('public', p.oid, 'EXECUTE')

UNION ALL

SELECT 'E2_SEARCH_PATH_QUOTED_LITERAL', 'BROKEN_SILENTLY',
       n.nspname, p.oid::regprocedure::text, NULL, 'SEARCH_PATH',
       format('%s sets search_path to a SINGLE QUOTED LITERAL containing a comma (%s). That names ONE schema of that literal name, which cannot exist, so the effective search path is EMPTY and the function fails at call time. Fix: SET search_path TO public, pg_temp;  -- bare identifiers, no quotes. PREVENTION BEATS DETECTION: apply the DDL-time event trigger in this file''s appendix so the bug cannot be reintroduced.',
              p.oid::regprocedure::text, cfg),
       'LIMIT: this scan reports the CURRENT grant state. It cannot tell an intended grant from a forgotten default — confirm intent before revoking, and re-check by effect (has_function_privilege) rather than by the statement exiting 0.'
  FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace,
       LATERAL unnest(COALESCE(p.proconfig,'{}')) cfg
 WHERE n.nspname NOT IN ('pg_catalog','information_schema')
   AND (COALESCE(current_setting('rowsaffected.include_system', true),'off') = 'on'
        OR n.nspname NOT IN ('auth','storage','cron','vault','realtime','_realtime','graphql',
                             'graphql_public','extensions','pgsodium','pgsodium_masks','net',
                             'supabase_functions','supabase_migrations','pgbouncer'))
   AND cfg LIKE 'search\_path=%'
   AND split_part(cfg,'=',2) LIKE '"%,%"'

UNION ALL

SELECT 'E3_DEFINER_WITHOUT_SEARCH_PATH', 'PRIVILEGE_ESCALATION_RISK',
       n.nspname, p.oid::regprocedure::text, NULL, 'SEARCH_PATH',
       format('SECURITY DEFINER function %s pins no search_path, so name resolution follows the CALLER''s path while the body runs with the OWNER''s rights. Fix by combining the clauses in one statement: ALTER FUNCTION %s SECURITY DEFINER SET search_path TO public, pg_temp;  -- two separate ALTERs leave a committed instant where the function is definer and unpinned.',
              p.oid::regprocedure::text, p.oid::regprocedure::text),
       'LIMIT: this scan reports the CURRENT grant state. It cannot tell an intended grant from a forgotten default — confirm intent before revoking, and re-check by effect (has_function_privilege) rather than by the statement exiting 0.'
  FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace
 WHERE p.prosecdef AND p.prokind = 'f'
   AND n.nspname NOT IN ('pg_catalog','information_schema')
   AND (COALESCE(current_setting('rowsaffected.include_system', true),'off') = 'on'
        OR n.nspname NOT IN ('auth','storage','cron','vault','realtime','_realtime','graphql',
                             'graphql_public','extensions','pgsodium','pgsodium_masks','net',
                             'supabase_functions','supabase_migrations','pgbouncer'))
   AND NOT EXISTS (SELECT 1 FROM unnest(COALESCE(p.proconfig,'{}')) c WHERE c LIKE 'search\_path=%')

)
SELECT * FROM (
SELECT * FROM findings

UNION ALL

SELECT 'SCAN_LIMITATIONS','INFO',NULL,NULL,NULL,NULL,
       format('RowsAffected function-surface scan complete: %s finding(s) across %s DISTINCT OBJECT(S). GROUP BY OBJECT WHEN RENDERING — one broken function can fire several detectors (an unpinned SECURITY DEFINER function with PUBLIC EXECUTE is ONE object that correctly trips both E1 and E3), so a row-per-line report overstates the amount of work. Read the caveat column before acting on — or dismissing — anything below.',
              (SELECT count(*) FROM findings), (SELECT count(DISTINCT table_name) FROM findings)),
       'LIMIT: E1 reports the CURRENT grant state and cannot distinguish an intended grant from a forgotten default. E2/E3 are structural and unambiguous, but detection is strictly weaker than the DDL-time event trigger in this file''s appendix — apply that too.'
) scan
ORDER BY (severity = 'INFO') DESC, finding_type, schema_name, table_name;

/* ============================================================================
 * APPENDIX — THE PREVENTIVE EVENT TRIGGER (ClosetLink production, verbatim)
 * ============================================================================
 * Pasted from the live catalog (pg_get_functiondef) and the migration that
 * created the trigger. NOT redrafted. This is the artifact that makes E2 and E3
 * impossible rather than merely findable, and it is why both return zero on
 * ClosetLink — it REFUSED an attempt to create the E2 bug on 2026-08-13, with an
 * error naming the exact failure.
 *
 * ⚠️ THE GUARD'S OWN search_path LOOKS LIKE THE BUG IT DETECTS AND IS NOT.
 *   SET search_path TO 'public', 'pg_temp'   <- TWO separately quoted literals: CORRECT
 *   SET search_path TO 'public, pg_temp'     <- ONE literal with a comma:       BROKEN
 * Do not "fix" the first form. E2's predicate distinguishes them correctly
 * (proven: it fires on the second and stays silent on the first).
 *
 * ⚠️ RULE 2's COMMENT IS THE EVIDENCE FOR E2's BROAD SCOPE. It says restricting
 * the check to DEFINER "is exactly how five of these survived the last sweep."
 * That is production experience, not a design preference.
 *
 * ⚠️ SCOPE OF THE GUARD ITSELF: the loop filters schema_name = 'public'. Objects
 * in other schemas (extensions, storage) never reach it. An adopter who wants
 * wider coverage must widen that filter — and should read the in_extension notes
 * below first, because they document the extension-upgrade escape hatch.
 *
 * ⚠️ The in_extension branch is UNEXERCISED end to end, per its own comment. Do
 * not treat a successful extension upgrade as evidence it works.
 *
 * APPLY IN THIS ORDER: function first, then the trigger.
 * ----------------------------------------------------------------------------
 * CREATE OR REPLACE FUNCTION public.enforce_definer_search_path()
 *  RETURNS event_trigger
 *  LANGUAGE plpgsql
 *  SET search_path TO 'public', 'pg_temp'
 * AS $function$
 * declare
 *   obj record;
 *   v_secdef boolean;
 *   v_cfg    text;
 * begin
 *   for obj in select * from pg_event_trigger_ddl_commands()
 *              where object_type = 'function' and schema_name = 'public'
 *   loop
 *     -- ┌──────────────────────────────────────────────────────────────────────────┐
 *     -- │ ⚠️ IF AN EXTENSION UPGRADE JUST FAILED, START HERE.                      │
 *     -- │ Symptom: CREATE/ALTER EXTENSION aborts with 42501 naming a function you  │
 *     -- │ did not write.                                                           │
 *     -- │                                                                          │
 *     -- │ ⚠️ CHECK THE SCHEMA FIRST — it is probably NOT this guard.               │
 *     -- │ The loop above only ever sees functions in `public`. An extension whose  │
 *     -- │ objects live anywhere else (PostGIS is in `extensions`) is filtered out  │
 *     -- │ before reaching the skip below, so this guard cannot be the cause.       │
 *     -- │ Verified 2026-07-29: PostGIS's 3 definer-unpinned functions (the         │
 *     -- │ st_estimatedextent overloads) are all in `extensions` — a PostGIS        │
 *     -- │ upgrade never reaches this code at all.                                  │
 *     -- │                                                                          │
 *     -- │ ⚠️ THE `obj.in_extension` BRANCH IS STILL UNEXERCISED END TO END. It is   │
 *     -- │ the documented-correct predicate (executing context, so it holds before  │
 *     -- │ the 'e' dependency links) and replaced a pg_depend test with a real      │
 *     -- │ timing hole. Proving it needs an extension that creates a definer        │
 *     -- │ function with an unpinned search_path IN `public`; we have no safe       │
 *     -- │ candidate, and PostGIS is NOT one — see the schema note above. Do not    │
 *     -- │ treat a successful PostGIS upgrade as evidence this branch works.        │
 *     -- │                                                                          │
 *     -- │ If an extension in `public` really does trip this:                       │
 *     -- │   (1) confirm in_extension is actually true for the failing statement;   │
 *     -- │   (2) unblock with ALTER EVENT TRIGGER trg_enforce_definer_search_path   │
 *     -- │       DISABLE, run the upgrade, then (3) FIX and re-enable — do not      │
 *     -- │       leave it off, or the class silently reopens.                       │
 *     -- └──────────────────────────────────────────────────────────────────────────┘
 *     if obj.in_extension
 *        or exists (select 1 from pg_depend d where d.objid = obj.objid and d.deptype = 'e') then
 *       continue;
 *     end if;
 *
 *     select p.prosecdef,
 *            (select cfg from unnest(coalesce(p.proconfig,'{}')) cfg where cfg like 'search_path=%')
 *       into v_secdef, v_cfg
 *     from pg_proc p where p.oid = obj.objid;
 *
 *     -- RULE 1 (20260729000005): DEFINER must declare a search_path.
 *     if v_secdef and v_cfg is null then
 *       raise exception
 *         'SECURITY DEFINER function % must declare an explicit search_path '
 *         '(use: SET search_path TO public, pg_temp).', obj.object_identity
 *         using errcode = '42501', detail = 'definer_search_path_required';
 *     end if;
 *
 *     -- RULE 2 (20260729000010): the quoted single-literal form is always wrong.
 *     -- `SET search_path TO 'public, pg_temp'` names ONE schema called
 *     -- "public, pg_temp", which cannot exist — the effective path is EMPTY. Applies to
 *     -- INVOKER functions too: the form is broken regardless of security mode, and
 *     -- restricting it to DEFINER is exactly how five of these survived the last sweep.
 *     if v_cfg is not null and v_cfg ~ '^search_path="[^"]*,[^"]*"$' then
 *       raise exception
 *         'Function % sets search_path to a SINGLE QUOTED LITERAL containing a comma '
 *         '(%). That names one schema of that literal name, which cannot exist, so the '
 *         'effective search path is EMPTY. Use bare identifiers: SET search_path TO '
 *         'public, pg_temp.', obj.object_identity, v_cfg
 *         using errcode = '42501', detail = 'search_path_quoted_literal';
 *     end if;
 *   end loop;
 * end;
 * $function$
 *
 * ---- and the trigger itself, verbatim from the migration ----
 *
 * create event trigger trg_enforce_definer_search_path
 *   on ddl_command_end
 *   when tag in ('CREATE FUNCTION', 'ALTER FUNCTION')
 *   execute function public.enforce_definer_search_path();
 *
 * ============================================================================ */
