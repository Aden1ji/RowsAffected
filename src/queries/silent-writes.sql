-- ============================================================================
-- RowsAffected — V1 detection logic (v3 — post UPDATE/DELETE field-test)
-- ============================================================================
--
-- WHAT CHANGED FROM v2, and every line of it came from running statements
-- against a real database rather than from reading documentation:
--
--   * OPEN QUESTION #1 IS RESOLVED. See "UPDATE / DELETE FINDINGS" below.
--     It did not resolve into either of the two answers the question
--     anticipated ("loud error, not our problem" / "silent, add to Case B").
--     It resolved into BOTH, split on a variable the question did not
--     contain, and it exposed a FALSE NEGATIVE in Case A.
--   * CASE C added — a hard 42501 whose error text points at the wrong fix.
--   * CASE D added — the Case A false negative: a missing SELECT policy
--     silently zeroes UPDATE/DELETE even when the write policy is perfect.
--   * Header corrected: RLS policy expressions are EXEMPT from the caller's
--     privilege check. v2 implied otherwise.
--   * policy_coverage: `p.roles = '{public}'` -> `'public' = any(p.roles)`,
--     so a policy declared TO public, authenticated is not missed.
--   * SCOPE: Supabase-managed schemas (auth, storage, cron, vault, realtime,
--     and friends) are EXCLUDED BY DEFAULT. Nobody using this tool can act on
--     a finding in storage.objects, and 12 of ClosetLink's deny-all hits came
--     from there — noise that trains people to ignore the output, which is the
--     one thing a tool like this cannot survive. Opt back in with:
--         SET rowsaffected.include_system = 'on';
--     Implemented as a runtime setting rather than a text placeholder ON
--     PURPOSE: an unsubstituted placeholder is a silent scope change, whereas
--     an unset GUC resolves to NULL and coalesces to the safe default.
--
-- ============================================================================
-- UPDATE / DELETE FINDINGS — measured, not inferred
-- ============================================================================
--
-- Setup for all of it: throwaway table, RLS on, role holds the write grant
-- and a permissive write policy. Only the SELECT side was varied.
--
-- (1) SELECT PRIVILEGE is required IFF THE STATEMENT TEXT READS A COLUMN.
--     Not "UPDATE requires SELECT" — it depends on the statement, not the
--     command:
--         UPDATE ... WHERE id = 1                 -> 42501, 0 rows, no change
--         UPDATE ... WHERE ... RETURNING          -> 42501, 0 rows, no change
--         UPDATE ... SET val = val || 'x'         -> 42501  (SET reads a column)
--         UPDATE ... SET val = 'literal'  (no WHERE, no RETURNING)
--                                                 -> SUCCESS, 1 row, CHANGED
--     Every shape a Supabase client can emit reads a column: .update().eq()
--     produces a WHERE, .update().select() adds RETURNING. So in practice
--     this is the LOUD path -> Case C, not Case B.
--
-- (2) RLS POLICY EXPRESSIONS ARE EXEMPT FROM THE CALLER'S PRIVILEGE CHECK.
--     A policy of USING (id > 0), with the caller holding NO privilege on
--     id, still evaluates and the statement succeeds. Policy expressions
--     are evaluated internally; only the user's own statement text is
--     privilege-checked. v2's header implied the opposite.
--
-- (3) A SELECT *POLICY* DOES NOT AFFECT THE 42501. Privileges are checked
--     before RLS runs, so no-grant/no-policy and no-grant/WITH-policy both
--     raise 42501 identically. This is why Case C keys on the PRIVILEGE
--     only. Including "and no SELECT policy" — as the original Case C
--     sketch did — would silently miss every table that has a SELECT policy
--     but no SELECT grant, which still hard-fails.
--
-- (4) THE ONE THAT MATTERS MOST: SELECT *POLICIES* APPLY TO UPDATE AND
--     DELETE THAT CARRY A WHERE CLAUSE. Full matrix on UPDATE ... WHERE,
--     with the UPDATE grant and a permissive UPDATE policy present the
--     whole time:
--
--         SELECT grant | SELECT policy | result
--         -------------|---------------|---------------------------------
--         no           | no            | 42501, unchanged        (Case C)
--         no           | YES           | 42501, unchanged        (Case C)
--         YES          | no            | NO ERROR, 0 ROWS, UNCHANGED  <== 
--         YES          | YES           | no error, 1 row, changed
--
--     The third row is the silent-write signature on a table whose write
--     grant AND write policy are both correct. Confirmed for DELETE by
--     removal, with a control: same statement, 0 rows affected / 2 rows
--     left without the SELECT policy; 1 row affected / 1 left with it.
--
--     ==> CASE A CANNOT SEE THIS. Case A asks "is there an UPDATE policy",
--         and here there is one. This is Case D, added below as its own
--         finding type rather than folded into Case A, so Case A's counts
--         and meaning are unchanged and reviewable.
--
-- ============================================================================
-- WHAT THIS FINDS
--
-- Case A  grant present, no permissive policy for that (role, command).
--         Write is authorized, RLS matches zero rows, no error.
-- Case B  RETIRED — premise measured false. Its claim ("the insert succeeds
--         but .select() comes back empty") does not happen: the statement
--         hard-fails 42501 and nothing is written. Folded into Case C. The
--         retraction and the measured matrix are kept at the Case B marker
--         below so it does not get silently re-proposed.
-- Case C  The write is authorized (grant + permissive policy for that
--         command) but the role lacks the SELECT PRIVILEGE, so any
--         client-shaped INSERT/UPDATE/DELETE hard-fails 42501. Loud, but the
--         message is "permission denied for table X" — the same SQLSTATE a
--         genuine RLS refusal produces, pointing at the table rather than at
--         the missing SELECT. The fix is GRANT SELECT; the developer will go
--         rewrite a policy that is already correct.
-- Case D  UPDATE/DELETE grant and policy are all correct, the role HAS the
--         SELECT privilege, but there is no permissive SELECT policy — so
--         the WHERE clause matches nothing and the write silently affects
--         zero rows.
--
-- *** THE TWO CAVEATS TRAVEL IN THE RESULT SET, BY DESIGN ***
-- Every row carries a `caveat` column, and one row with severity = 'INFO' is
-- ALWAYS emitted even when there are zero findings. This is deliberate: a
-- header comment cannot reach whoever writes the output formatter in another
-- file, and "documented" is not "checked". A formatter has to actively strip
-- the column to lose the text.
-- The INFO row matters MOST on a clean scan — zero findings is exactly when
-- someone over-reads the result, and it only ever meant "no ABSENT policies".
-- The INFO row therefore carries BOTH caveats, not just the LIMIT one, so
-- neither can go missing on the run where they are needed most. Case A's
-- deny-all branch repeats the heuristic caveat verbatim; the strings are
-- identical on purpose, so a formatter that de-duplicates prints each once.
-- COUNTING: exclude severity = 'INFO'. It is exactly one row, always present.
--
-- *** LIMITATION — ALSO STATED IN THE CLI BANNER ***
-- This detects policy ABSENCE, not policy USELESSNESS. A policy written as
-- WITH CHECK (false), or with a condition no real row satisfies, produces
-- the identical silent zero-row write and is invisible to an existence
-- check. "RowsAffected" implicitly promises both; this catches the first.
-- ============================================================================

WITH target_roles AS (
    SELECT r.rolname AS role_name, r.oid AS role_oid
    FROM pg_roles r
    WHERE r.rolname IN ('anon', 'authenticated')
      AND r.rolbypassrls = false
      AND r.rolsuper = false
),
-- Platform-managed schemas. Findings here are real but unactionable by the
-- application developer, so they are excluded unless explicitly asked for.
system_schemas AS (
    SELECT unnest(ARRAY['auth','storage','cron','vault','realtime','_realtime',
                        'graphql','graphql_public','extensions','pgsodium',
                        'pgsodium_masks','net','supabase_functions',
                        'supabase_migrations','pgbouncer']) AS nspname
),
target_tables AS (
    SELECT n.nspname AS schema_name, c.relname AS table_name,
           c.oid AS table_oid, c.relowner AS owner_oid
    FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
    WHERE c.relkind = 'r' AND c.relrowsecurity = true
      AND n.nspname NOT IN ('pg_catalog', 'information_schema')
      AND (COALESCE(current_setting('rowsaffected.include_system', true), 'off') = 'on'
           OR n.nspname NOT IN (SELECT nspname FROM system_schemas))
),
table_role_pairs AS (
    SELECT t.schema_name, t.table_name, t.table_oid, tr.role_name, tr.role_oid
    FROM target_tables t CROSS JOIN target_roles tr
    WHERE tr.role_oid <> t.owner_oid
),
grants AS (
    SELECT trp.schema_name, trp.table_name, trp.role_name, trp.table_oid,
           priv.privilege_type
    FROM table_role_pairs trp
    CROSS JOIN LATERAL unnest(ARRAY['SELECT','INSERT','UPDATE','DELETE']) AS priv(privilege_type)
    WHERE has_table_privilege(trp.role_name, trp.table_oid, priv.privilege_type)
),
policy_counts AS (
    SELECT p.schemaname AS schema_name, p.tablename AS table_name, count(*) AS total_policies
    FROM pg_policies p GROUP BY p.schemaname, p.tablename
),
policy_coverage AS (
    SELECT p.schemaname AS schema_name, p.tablename AS table_name, role_name, covered_cmd
    FROM pg_policies p
    CROSS JOIN LATERAL (
        SELECT unnest(
            CASE WHEN 'public' = any(p.roles) THEN ARRAY['anon','authenticated']
                 ELSE p.roles::text[] END) AS role_name) roles_expanded
    CROSS JOIN LATERAL (
        SELECT unnest(
            CASE WHEN p.cmd = 'ALL' THEN ARRAY['SELECT','INSERT','UPDATE','DELETE']
                 ELSE ARRAY[p.cmd] END) AS covered_cmd) cmds_expanded
    WHERE p.permissive = 'PERMISSIVE' AND role_name IN ('anon','authenticated')
)

-- The UNION is wrapped so the ORDER BY can float the INFO banner to the top:
-- Postgres only allows result column NAMES in a UNION's ORDER BY, not expressions.
SELECT * FROM (

-- ===================== CASE A =====================
SELECT 'CASE_A_SILENT_ZERO_ROWS' AS finding_type,
       CASE WHEN COALESCE(pcount.total_policies,0)=0
            THEN 'LIKELY_INTENTIONAL_DENY_ALL' ELSE 'PARTIAL_POLICY_GAP' END AS severity,
       g.schema_name, g.table_name, g.role_name,
       g.privilege_type AS ungoverned_operation,
       format('Role "%s" can %s on %s.%s (grant present) with no matching RLS policy. %s',
              g.role_name, g.privilege_type, g.schema_name, g.table_name,
              CASE WHEN COALESCE(pcount.total_policies,0)=0
                   THEN 'This table has zero policies at all, which usually means "service-role only by design" — confirm that''s intentional, don''t assume it.'
                   ELSE 'This table has other policies but none for this operation — writes will silently affect 0 rows, no error, success reported to the client.' END) AS explanation,
       CASE WHEN COALESCE(pcount.total_policies,0)=0
            THEN 'HEURISTIC, NOT A VERDICT: ''zero policies'' is equally consistent with ''service-role only by design'' and ''nobody has written any policies yet''. This scan cannot tell those apart. Confirm before dismissing. LIMIT: this scan detects policy ABSENCE, not policy USELESSNESS. A policy that exists but is written WITH CHECK (false), or with a condition no real row satisfies, produces the identical silent zero-row write and is invisible to an existence check. A CLEAN SCAN IS NOT PROOF OF NO SILENT WRITES.' ELSE 'LIMIT: this scan detects policy ABSENCE, not policy USELESSNESS. A policy that exists but is written WITH CHECK (false), or with a condition no real row satisfies, produces the identical silent zero-row write and is invisible to an existence check. A CLEAN SCAN IS NOT PROOF OF NO SILENT WRITES.' END AS caveat
FROM grants g
LEFT JOIN policy_counts pcount ON pcount.schema_name=g.schema_name AND pcount.table_name=g.table_name
WHERE g.privilege_type IN ('INSERT','UPDATE','DELETE')
  AND NOT EXISTS (SELECT 1 FROM policy_coverage pc
                   WHERE pc.schema_name=g.schema_name AND pc.table_name=g.table_name
                     AND pc.role_name=g.role_name AND pc.covered_cmd=g.privilege_type)

-- ===================== CASE B — RETIRED, PREMISE FALSIFIED =====================
-- v2's Case B claimed: "the insert succeeds, but .select() on the response comes
-- back empty — looking exactly like a blocked write." MEASURED, AND IT IS WRONG.
-- With INSERT grant + permissive INSERT policy in place, varying only SELECT:
--     SELECT grant | SELECT policy | INSERT      | INSERT ... RETURNING
--     no  | no   | success, 1 row | 42501, 0 rows inserted
--     no  | YES  | success, 1 row | 42501, 0 rows inserted
--     YES | no   | success, 1 row | 42501, 0 rows inserted
--     YES | YES  | success, 1 row | success, row returned
-- The insert does NOT succeed: the whole statement fails and NOTHING is written.
-- That is Case C's shape (a loud, misleading 42501), not a silent success — so
-- Case B is folded into Case C below rather than kept as its own finding type.
-- Note also that v2's predicate required table-grant AND column-grant AND policy
-- to all be absent; the matrix shows EITHER a missing privilege OR a missing
-- policy is sufficient, so it under-reported by two of the three failing cells.
UNION ALL
-- ===================== CASE C =====================
-- Keys on the SELECT PRIVILEGE ONLY. A SELECT policy is deliberately NOT in
-- this predicate: measured finding (3) — privileges are checked before RLS,
-- so the 42501 fires whether or not a SELECT policy exists. Requiring
-- "no SELECT policy" here would miss every grant-absent/policy-present table.
SELECT 'CASE_C_MISLEADING_PERMISSION_ERROR', 'BROKEN_HARD_FAILURE',
       g.schema_name, g.table_name, g.role_name, g.privilege_type,
       format('Role "%s" has %s on %s.%s with a permissive %s policy, but NO SELECT privilege (neither table-level nor column-level). Any statement that reads a column hard-fails 42501 "permission denied for table %s" — and every client-shaped write reads one: .update()/.delete() with a filter emit a WHERE, and .insert().select()/.update().select() add RETURNING. Measured: the statement fails and NOTHING is written. THE FIX IS "GRANT SELECT", NOT A POLICY CHANGE — 42501 is the same SQLSTATE a genuine RLS refusal produces and the message names the table, so this reads as a broken %s policy. That policy is fine.',
              g.role_name, g.privilege_type, g.schema_name, g.table_name, g.privilege_type, g.table_name, g.privilege_type),
       'LIMIT: this scan detects policy ABSENCE, not policy USELESSNESS. A policy that exists but is written WITH CHECK (false), or with a condition no real row satisfies, produces the identical silent zero-row write and is invisible to an existence check. A CLEAN SCAN IS NOT PROOF OF NO SILENT WRITES.'
FROM grants g
WHERE g.privilege_type IN ('INSERT','UPDATE','DELETE')
  AND EXISTS (SELECT 1 FROM policy_coverage pc WHERE pc.schema_name=g.schema_name
                AND pc.table_name=g.table_name AND pc.role_name=g.role_name AND pc.covered_cmd=g.privilege_type)
  AND NOT has_table_privilege(g.role_name, g.table_oid, 'SELECT')
  AND NOT has_any_column_privilege(g.role_name, g.table_oid, 'SELECT')

UNION ALL
-- ===================== CASE D =====================
-- The Case A false negative. Write grant and write policy are both correct;
-- the SELECT privilege is held; but no permissive SELECT policy exists, so
-- the WHERE clause matches nothing and the write silently affects 0 rows.
SELECT 'CASE_D_MISSING_SELECT_POLICY_ZEROES_WRITE', 'PARTIAL_POLICY_GAP',
       g.schema_name, g.table_name, g.role_name, g.privilege_type,
       format('Role "%s" has %s on %s.%s WITH a permissive %s policy — that half is correct — and holds the SELECT privilege, but there is NO permissive SELECT policy. SELECT policies are applied to UPDATE/DELETE that carry a WHERE clause, so the statement matches zero rows and returns success with no error. (Asymmetry, measured: the same gap on INSERT ... RETURNING raises 42501 instead — for INSERT there is no pre-existing row set for the policy to narrow.) Case A cannot see this: it checks for a %s policy, and one exists. Fix: add a SELECT policy covering this role.',
              g.role_name, g.privilege_type, g.schema_name, g.table_name, g.privilege_type, g.privilege_type),
       'LIMIT: this scan detects policy ABSENCE, not policy USELESSNESS. A policy that exists but is written WITH CHECK (false), or with a condition no real row satisfies, produces the identical silent zero-row write and is invisible to an existence check. A CLEAN SCAN IS NOT PROOF OF NO SILENT WRITES.'
FROM grants g
WHERE g.privilege_type IN ('UPDATE','DELETE')
  AND has_table_privilege(g.role_name, g.table_oid, 'SELECT')
  AND EXISTS (SELECT 1 FROM policy_coverage pc WHERE pc.schema_name=g.schema_name
                AND pc.table_name=g.table_name AND pc.role_name=g.role_name AND pc.covered_cmd=g.privilege_type)
  AND NOT EXISTS (SELECT 1 FROM policy_coverage pc WHERE pc.schema_name=g.schema_name
                AND pc.table_name=g.table_name AND pc.role_name=g.role_name AND pc.covered_cmd='SELECT')

UNION ALL
-- ===================== ALWAYS-PRESENT SCAN BANNER =====================
-- Emitted unconditionally so the caveats survive a zero-finding scan, which is
-- the run most likely to be over-read. Exclude severity='INFO' from counts.
-- CARRIES BOTH CAVEATS, not just the LIMIT one. Earlier this row carried LIMIT
-- alone, on the reasoning that the deny-all heuristic only matters when a
-- deny-all row is present to attach it to. That reasoning is wrong in the case
-- that matters most: on a zero-finding scan there are no Case A rows, so the
-- heuristic caveat would vanish from exactly the run where someone is most
-- likely to conclude "clean" — and "we found no deny-all tables" is itself a
-- claim the heuristic qualifies. Identical string to the Case A deny-all branch
-- above, so a formatter that de-duplicates caveats prints each one once.
SELECT 'SCAN_LIMITATIONS', 'INFO', NULL, NULL, NULL, NULL,
       'RowsAffected scan complete. Read the caveat column before acting on — or dismissing — anything below.',
       'HEURISTIC, NOT A VERDICT: ''zero policies'' is equally consistent with ''service-role only by design'' and ''nobody has written any policies yet''. This scan cannot tell those apart. Confirm before dismissing. LIMIT: this scan detects policy ABSENCE, not policy USELESSNESS. A policy that exists but is written WITH CHECK (false), or with a condition no real row satisfies, produces the identical silent zero-row write and is invisible to an existence check. A CLEAN SCAN IS NOT PROOF OF NO SILENT WRITES.'

) scan
ORDER BY (severity = 'INFO') DESC, finding_type, schema_name, table_name, role_name, ungoverned_operation;
