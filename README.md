# RowsAffected

Finds database writes that report success but silently affect zero rows.

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

There are three, plus an informational banner, listed lowest first:

| Severity | Meaning |
| --- | --- |
| `LIKELY_INTENTIONAL_DENY_ALL` | Case A on a table with zero policies. Might be deliberate. A question, not a verdict. |
| `PARTIAL_POLICY_GAP` | A confirmed silent zero row write: Case A on a table that has other policies, or Case D. |
| `BROKEN_HARD_FAILURE` | Case C. The write is failing loudly right now, with an error that points at the wrong fix. |
| `INFO` | The always present scan banner carrying the caveats. Never a finding. |

`--fail-on` accepts any of those names (`--fail-on partial-policy-gap`), plus `any` and `never`. `INFO` never fails a build.

Ranking `BROKEN_HARD_FAILURE` above `PARTIAL_POLICY_GAP` is a call this tool makes, not one the detection logic makes. A hard failure is breaking right now, where a policy gap is breaking quietly. If you disagree, `--fail-on any` sidesteps the ordering entirely and is the better CI setting anyway.

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

## What it does not find

Two limits. They're carried in the query's own `caveat` column rather than living only in documentation, so they print with every scan result, including, and especially, a clean one.

**The deny-all severity is a heuristic, not a verdict.** Zero policies is equally consistent with "service role only by design" and "nobody has written any policies yet." This scan can't tell those apart. Confirm before dismissing.

**This tool detects policy absence, not policy uselessness.** A policy that exists but permits nothing, like `WITH CHECK (false)`, or a condition no real row satisfies, produces the identical silent zero row write and is invisible to an existence check. Catching that would mean evaluating policy expressions against real rows, which this tool doesn't do.

So a clean scan means "no missing policies." It isn't proof of no silent writes. The name promises both; this catches the first.

## License

MIT