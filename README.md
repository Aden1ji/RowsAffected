# RowsAffected

Finds database writes that report success but silently affect zero rows, and the `SECURITY DEFINER` functions that quietly hand out the owner's rights.

```
npx rowsaffected scan
```

## The problem

In Postgres, and therefore in Supabase, a write gets checked twice.

First, table grants: does this role have `UPDATE` on this table at all? Second, Row Level Security: is there a policy that lets this role update these specific rows?

If the grant exists but no policy covers that role and that command, the write isn't rejected. It just matches zero rows and returns successfully.

```js
const { error } = await supabase
  .from('orders')
  .update({ status: 'shipped' })
  .eq('id', orderId);

// error is null. The row did not change.
```

No exception. Nothing in the logs. The client reports success. You find out when a customer asks why their order still says "pending."

This is a different question from the one existing Supabase security scanners ask. They check whether your data is too exposed. RowsAffected checks whether your app is lying to you about whether writes worked.

## Install

Nothing to install. Run it directly:

```bash
npx rowsaffected scan
```

Or add it to a project:

```bash
npm install --save-dev rowsaffected
```

Requires Node 18 or newer.

Two commands: `scan` reports what's wrong, `prevention` prints an event trigger that stops two of the findings being reintroduced at all.

## Usage

Give it a Postgres connection string. The `DATABASE_URL` environment variable is the recommended way, since a connection string passed as an argument ends up sitting in your shell history.

```bash
export DATABASE_URL='postgresql://postgres:...@db.xxxx.supabase.co:5432/postgres'
npx rowsaffected scan
```

On Supabase, that string lives under **Project Settings → Database → Connection string**. Use the `postgres` role. RowsAffected reads grants and policies from the system catalogs, and a lower privileged role can only see its own, so a restricted connection produces a quiet, incomplete report rather than an error.

The scan runs inside a `READ ONLY` transaction and touches only catalog metadata. It never reads, writes, or modifies your data, and it doesn't send anything anywhere.

### Which roles it checks

RowsAffected checks the two roles a Supabase client actually authenticates as: **`anon`** and **`authenticated`**. Roles that bypass RLS, superusers, and the owner of each table are skipped, since RLS doesn't constrain them and they can't produce this class of bug.

If your database has no `anon` or `authenticated` role, every scan comes back clean because there was nothing in scope to check, not because your policies are correct. The tool is Supabase shaped today.

### Options

| Option | Description |
| --- | --- |
| `-d, --db <url>` | Connection string (or `DATABASE_URL`, or a bare argument) |
| `--include-system` | Also scan `auth`, `storage`, `cron`, `vault`, `realtime`, and friends |
| `--json` | Emit the raw result rows as JSON |
| `--fail-on <sev>` | Exit 1 on findings at or above a severity, see below |
| `--no-ssl` | Disable TLS (on by default; hosted Postgres requires it) |
| `--no-color` | Plain output |

By default the Supabase managed schemas are out of scope. They generate real but unactionable findings (you don't own those policies), and enough of them to train you into ignoring the output, which is the one thing a tool like this can't survive.

### Severities

Six, plus an informational banner, listed lowest first:

| Severity | Meaning |
| --- | --- |
| `HYGIENE` | E1 on a trigger function. A convention violation with no exploitable surface. |
| `LIKELY_INTENTIONAL_DENY_ALL` | Case A on a table with zero policies. Might be deliberate. A question, not a verdict. |
| `PARTIAL_POLICY_GAP` | A confirmed silent zero row write: Case A on a table that has other policies, or Case D. |
| `BROKEN_HARD_FAILURE` | Case C. The write is failing loudly right now, with an error that points at the wrong fix. |
| `BROKEN_SILENTLY` | E2. The function is failing right now and nothing says so. |
| `PRIVILEGE_ESCALATION_RISK` | E1 on a callable function, or E3. A crossed security boundary, not a correctness bug. |
| `INFO` | The always present scan banner carrying the caveats. Never a finding. |

`--fail-on` accepts any of those names (`--fail-on partial-policy-gap`), plus `any` and `never`. `INFO` never fails a build.

The ordering between them is a call this tool makes, not one the detection logic makes. `BROKEN_SILENTLY` sits above `BROKEN_HARD_FAILURE` because silence is what evades detection, which is the whole premise of the tool: E2's production evidence is an eleven month outage nobody noticed. If you disagree, `--fail-on any` sidesteps the ordering entirely and is the better CI setting anyway.

### Findings are grouped by object

One broken object can trip several detectors at once. A `SECURITY DEFINER` function with no pinned `search_path` and `PUBLIC` `EXECUTE` is one thing to fix that correctly produces both an E1 and an E3 finding.

So the report groups by object and tells you both numbers: `11 findings across 10 objects`. A row-per-line report would claim eleven problems for ten things to fix, and inflated counts are the fastest way to lose trust in a report.

### In CI

```bash
npx rowsaffected scan --fail-on any
```

Exit codes: `0` clean, `1` findings met the `--fail-on` threshold, `2` the scan couldn't run (bad arguments, connection failure, query error).

## What it finds

### Case A: write grant, no matching policy

A role can `INSERT`/`UPDATE`/`DELETE` on a table, RLS is enabled, and no permissive policy covers that command for that role.

Every such write silently affects zero rows. This is the core case.

**Fix:** add a policy for that role and command, or revoke the grant if the role was never meant to write there.

If the table has no policies at all, the finding drops to `LIKELY_INTENTIONAL_DENY_ALL`. Zero policies can mean this table is deliberately service role only, or it can mean someone enabled RLS and forgot. Both look identical from the catalogs, so RowsAffected flags it rather than hiding it. You know which one yours is.

### Case C: write authorized, but no SELECT privilege

The role has the write grant and a permissive write policy, but no `SELECT` **privilege** on the table, neither table level nor column level.

This one isn't silent. Postgres raises `42501 permission denied for table X`. It's on the list because the error points at the wrong fix: `42501` is the same SQLSTATE a genuine RLS refusal produces, and the message names the table, so it reads as a broken write policy. The write policy is fine. The fix is `GRANT SELECT`.

Any statement that reads a column triggers it, which means every shape a Supabase client emits: `.update().eq()` produces a `WHERE`, `.insert().select()` adds `RETURNING`. The statement fails and nothing is written.

Note this keys on the SELECT privilege alone, on purpose. A `SELECT` policy doesn't prevent the error, since privileges are checked before RLS runs.

**Fix:** `GRANT SELECT` on the table to that role.

### Case D: write policy correct, SELECT policy missing

The write grant is there. The write policy is there. The `SELECT` privilege is there. Everything you'd think to check looks right. But there's no `SELECT` **policy**, so the `WHERE` clause matches nothing and the write silently affects zero rows.

`SELECT` policies apply to `UPDATE` and `DELETE` that carry a `WHERE` clause, which is what `.update().eq()` and `.delete().eq()` compile to. Case A can't see this, because it only asks whether an `UPDATE` policy exists, and one does.

This applies to `UPDATE` and `DELETE` only. The same gap on `INSERT ... RETURNING` raises `42501` instead, since there's no pre-existing row set for a `SELECT` policy to narrow.

**Fix:** add a `SELECT` policy covering that role.

The three cases above are about tables. The three below are about functions, where the same theme shows up in a different place: something looks configured, and isn't.

### E1: PUBLIC can execute a SECURITY DEFINER function

Postgres grants `EXECUTE` to `PUBLIC` on every new function. That's the default, so a hit here is never a decision anyone made.

A `SECURITY DEFINER` function runs as its owner. If `PUBLIC` can execute it, any client role can invoke it with the owner's rights.

Severity splits on the return type. A function returning `trigger` raises on a direct call regardless, so there's no exploitable surface and it lands at `HYGIENE`. Anything else is `PRIVILEGE_ESCALATION_RISK`.

**Fix:** `REVOKE EXECUTE ON FUNCTION <fn> FROM public, anon, authenticated;`

Name all three. The grant can live on `PUBLIC` and as direct role rows at the same time, and revoking either one alone is a silent no-op. Re-check by effect with `has_function_privilege`, not by the statement exiting 0.

### E2: search_path set as a quoted literal

`SET search_path TO 'public, pg_temp'` doesn't name two schemas. It names one schema whose name is literally `public, pg_temp`. No such schema exists, so the effective search path is empty and the function fails at call time.

This is the one with the worst track record in production: three casualties on one database, one of them an eleven month silent outage where every avatar upload failed. All three were found while investigating something else.

**Fix:** `SET search_path TO public, pg_temp;` with bare identifiers, no quotes.

Better than fixing it: prevent it. See [Prevention](#prevention) below.

### E3: SECURITY DEFINER with no search_path

The canonical Supabase privilege escalation vector. The caller controls name resolution while the body runs with the owner's rights, so an object created earlier in the caller's path gets executed as the owner.

**Fix:** `ALTER FUNCTION <fn> SECURITY DEFINER SET search_path TO public, pg_temp;`

Combine both clauses in one statement. Two separate `ALTER`s leave a committed instant where the function is definer and unpinned.

## Prevention

E2 and E3 don't have to be found. They can be made impossible.

```bash
npx rowsaffected prevention
```

That prints a DDL-time event trigger which refuses both at `CREATE FUNCTION` / `ALTER FUNCTION` time. It's the production trigger from the database RowsAffected was developed against, pasted from the live catalog rather than redrafted, and it's why E3 returns zero hits there.

Read it before applying it — it's commented, and two of those comments matter:

- **Its own `search_path` looks like the bug it detects, and isn't.** `SET search_path TO 'public', 'pg_temp'` is two separately quoted literals and is correct. `SET search_path TO 'public, pg_temp'` is one literal containing a comma and is broken. Postgres normalises the first to the same stored form as bare identifiers, which is exactly why E2 fires on one and stays silent on the other.
- **The guard only covers the `public` schema.** Objects elsewhere never reach it. Widen the loop's filter if you want more, but read its notes on extension upgrades first.

Apply the function first, then the trigger. Piping straight to `psql` works:

```bash
npx rowsaffected prevention | psql "$DATABASE_URL"
```

Detection is strictly weaker than prevention. The scanner only finds damage already done.

## What it does not find

These limits are carried in the queries' own `caveat` column rather than living only in documentation, so they print with every scan result, including, and especially, a clean one.

**The deny-all severity is a heuristic, not a verdict.** Zero policies is equally consistent with "service role only by design" and "nobody has written any policies yet." This scan can't tell those apart. Confirm before dismissing.

**This tool detects policy absence, not policy uselessness.** A policy that exists but permits nothing, like `WITH CHECK (false)`, or a condition no real row satisfies, produces the identical silent zero row write and is invisible to an existence check. Catching that would mean evaluating policy expressions against real rows, which this tool doesn't do.

**E1 reports the current grant state, not intent.** It can't tell a deliberate grant from a forgotten default. Confirm before revoking.

**Detection is weaker than prevention for E2 and E3.** Both are structural and unambiguous, so the scanner finds them reliably, but it only finds damage already done. See [Prevention](#prevention).

So a clean scan means "no missing policies, no unpinned definer functions." It isn't proof of no silent writes. The name promises both; this catches the first.

## License

MIT