import { readFile } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';
import { render, renderJson } from './render.js';

// Each detection query emits the same 8 columns and its own INFO banner row.
const QUERIES = [
  { name: 'silent-writes', path: fileURLToPath(new URL('./queries/silent-writes.sql', import.meta.url)) },
  { name: 'functions', path: fileURLToPath(new URL('./queries/functions.sql', import.meta.url)) },
];
const PKG_PATH = fileURLToPath(new URL('../package.json', import.meta.url));

// The severity vocabulary is the query's, not ours — these are the exact
// values it emits. Listed low to high. INFO is the always-present caveat
// banner rather than a finding, so it ranks lowest and never trips --fail-on.
//
// The relative ordering is a judgement call the queries do not make. Rationale,
// lowest to highest:
//   HYGIENE                    E1 on a trigger function — the query itself says
//                              there is no exploitable surface here.
//   LIKELY_INTENTIONAL_DENY_ALL a heuristic that may be a deliberate design.
//   PARTIAL_POLICY_GAP         a confirmed silent zero-row write.
//   BROKEN_HARD_FAILURE        failing loudly right now (Case C).
//   BROKEN_SILENTLY            failing silently right now (E2). Ranked above
//                              the loud failure because silence is what evades
//                              detection — E2's production evidence is an
//                              11-month outage nobody noticed.
//   PRIVILEGE_ESCALATION_RISK  a crossed security boundary, not a correctness
//                              bug. Top of the list.
// Reasonable people could reorder these; --fail-on any sidesteps the question
// entirely and is the better CI default.
export const SEVERITY_ORDER = [
  'info',
  'hygiene',
  'likely_intentional_deny_all',
  'partial_policy_gap',
  'broken_hard_failure',
  'broken_silently',
  'privilege_escalation_risk',
];
const FAIL_ON_CHOICES = SEVERITY_ORDER.filter((s) => s !== 'info');

// Accept 'broken-hard-failure' as readily as 'BROKEN_HARD_FAILURE'.
export function normalizeSeverity(value) {
  return String(value ?? '').trim().toLowerCase().replace(/-/g, '_');
}

const HELP = `
rowsaffected — find writes that report success but affect zero rows

USAGE
  npx rowsaffected scan [connection-string] [options]
  npx rowsaffected prevention

  The connection string may also come from --db or the DATABASE_URL
  environment variable. Prefer the environment variable: a connection
  string on the command line lands in your shell history.

COMMANDS
  scan        Scan a database for silent write failures and for
              SECURITY DEFINER functions that leak the owner's rights.
  prevention  Print the DDL-time event trigger that makes the two
              search_path findings (E2, E3) impossible to reintroduce.
              Detection only finds damage already done; this prevents it.
              Pipe it to psql, or read it first — it is commented.

OPTIONS
  -d, --db <url>          Postgres connection string
      --include-system    Also scan auth/storage/cron/vault/realtime schemas.
                          Off by default: those are Supabase-managed and you
                          usually cannot act on findings there.
      --json              Emit raw findings as JSON (one object per row)
      --fail-on <sev>     Exit 1 if any finding is at or above this severity.
                          Lowest to highest:
                            hygiene, likely-intentional-deny-all,
                            partial-policy-gap, broken-hard-failure,
                            broken-silently, privilege-escalation-risk
                          Also accepts 'any' (any finding at all) and 'never'
                          (the default). 'any' is the sensible CI setting.
      --no-ssl            Disable TLS. TLS is on by default; hosted Postgres
                          (Supabase included) requires it.
      --no-color          Plain output, no ANSI escapes
  -h, --help              Show this help
  -v, --version           Show version

EXIT CODES
  0  scan completed (and no finding met --fail-on)
  1  scan completed, findings met the --fail-on threshold
  2  could not run: bad arguments, connection failure, query error

EXAMPLES
  export DATABASE_URL='postgresql://...'
  npx rowsaffected scan
  npx rowsaffected scan --include-system
  npx rowsaffected scan --json > findings.json
  npx rowsaffected scan --fail-on any       # for CI
`.trimStart();

export function parseArgs(argv) {
  const opts = {
    command: null,
    db: process.env.DATABASE_URL || null,
    includeSystem: false,
    json: false,
    failOn: 'never',
    ssl: true,
    color: process.stdout.isTTY && !process.env.NO_COLOR,
    help: false,
    version: false,
  };

  for (let i = 0; i < argv.length; i++) {
    const arg = argv[i];
    const next = () => {
      const v = argv[++i];
      if (v === undefined) throw new Error(`${arg} requires a value`);
      return v;
    };

    switch (arg) {
      case '-h': case '--help': opts.help = true; break;
      case '-v': case '--version': opts.version = true; break;
      case '-d': case '--db': opts.db = next(); break;
      case '--include-system': case '--include-system-schemas': opts.includeSystem = true; break;
      case '--json': opts.json = true; break;
      case '--fail-on': opts.failOn = normalizeSeverity(next()); break;
      case '--no-ssl': opts.ssl = false; break;
      case '--no-color': opts.color = false; break;
      case '--color': opts.color = true; break;
      default:
        if (arg.startsWith('-')) throw new Error(`unknown option: ${arg}`);
        if (!opts.command) opts.command = arg;
        else if (!opts.db || argvLooksLikeUrl(arg)) opts.db = arg;
        else throw new Error(`unexpected argument: ${arg}`);
    }
  }

  if (!['never', 'any'].includes(opts.failOn) && !FAIL_ON_CHOICES.includes(opts.failOn)) {
    // Both spellings are accepted; show the hyphenated one so this matches --help.
    const shown = FAIL_ON_CHOICES.map((s) => s.replace(/_/g, '-')).join(', ');
    throw new Error(`--fail-on must be one of: any, ${shown}, never (got '${opts.failOn}')`);
  }

  return opts;
}

function argvLooksLikeUrl(s) {
  return s.startsWith('postgres://') || s.startsWith('postgresql://');
}

export async function main(argv) {
  const opts = parseArgs(argv);

  if (opts.version) {
    const pkg = JSON.parse(await readFile(PKG_PATH, 'utf8'));
    console.log(pkg.version);
    return 0;
  }

  if (opts.help || !opts.command) {
    console.log(HELP);
    return opts.help ? 0 : 2;
  }

  if (opts.command === 'prevention') {
    console.log(await loadPrevention());
    return 0;
  }

  if (opts.command !== 'scan') {
    throw new Error(`unknown command: ${opts.command}. Expected 'scan' or 'prevention'.`);
  }

  if (!opts.db) {
    throw new Error(
      'no connection string. Pass one as an argument, via --db, or set DATABASE_URL.'
    );
  }

  const queries = await loadQueries();
  // Loaded here rather than at module scope so --help and --version still work
  // if the pg dependency is missing or broken.
  const { runScan } = await import('./db.js');
  const rows = await runScan({
    connectionString: opts.db,
    ssl: opts.ssl,
    queries,
    includeSystem: opts.includeSystem,
  });

  if (opts.json) {
    renderJson(rows);
  } else {
    render(rows, { color: opts.color, includeSystem: opts.includeSystem });
  }

  return meetsThreshold(rows, opts.failOn) ? 1 : 0;
}

/**
 * The preventive event trigger ships inside the functions query, as a trailing
 * block comment. It is read back out of there rather than duplicated here, so
 * there is exactly one copy of that DDL in the package and it stays whatever
 * the catalog it was pasted from says.
 */
async function loadPrevention() {
  const { path } = QUERIES.find((q) => q.name === 'functions');
  const sql = await readFile(path, 'utf8');
  const start = sql.indexOf('/* ===');
  if (start === -1) {
    throw new Error(`no prevention appendix found in ${path}`);
  }
  const lines = sql
    .slice(start)
    .replace(/^\/\*/, '')
    .replace(/\*\/\s*$/, '')
    .split('\n')
    .map((line) => line.replace(/^\s*\*\s?/, ''))
    .map((line) => line.replace(/\s+$/, ''));

  // Everything above the long dashed rule is commentary; the DDL follows it and
  // carries its own -- comments. Comment the commentary so the whole thing is
  // valid SQL and can go straight into psql.
  const rule = lines.findIndex((l) => /^-{20,}$/.test(l.trim()));
  const body = lines.map((line, i) => {
    const isDdl = rule !== -1 && i > rule;
    if (!isDdl || /^={20,}$/.test(line.trim())) {
      return line.trim() === '' ? '' : `-- ${line}`;
    }
    // The function definition is pasted from pg_get_functiondef, which never
    // emits a statement terminator. Without one, psql runs the function and the
    // event trigger together as a single malformed statement. Add it back — the
    // only edit made to the DDL, and it changes nothing about what it does.
    if (/^\$function\$\s*$/.test(line)) return `${line.trimEnd()};`;
    return line;
  });

  return body.join('\n').trim();
}

async function loadQueries() {
  return Promise.all(
    QUERIES.map(async ({ name, path }) => {
      const sql = await readFile(path, 'utf8');
      if (sql.includes('__QUERY_NOT_INSTALLED__')) {
        throw new Error(`the ${name} detection query has not been installed yet (${path} is a placeholder).`);
      }
      return { name, sql };
    })
  );
}

function meetsThreshold(rows, failOn) {
  if (failOn === 'never') return false;
  // 'any' means any real finding. The INFO banner is always present and is
  // never a finding, so it can never fail a build.
  const floor = failOn === 'any' ? 1 : SEVERITY_ORDER.indexOf(failOn);
  return rows.some((r) => {
    const rank = SEVERITY_ORDER.indexOf(normalizeSeverity(r.severity));
    return rank >= floor && rank > 0;
  });
}
