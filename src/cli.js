import { readFile } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';
import { render, renderJson } from './render.js';

const QUERY_PATH = fileURLToPath(new URL('./queries/silent-writes.sql', import.meta.url));
const PKG_PATH = fileURLToPath(new URL('../package.json', import.meta.url));

// The severity vocabulary is the query's, not ours — these are the exact
// values it emits. Listed low to high. INFO is the always-present caveat
// banner rather than a finding, so it ranks lowest and never trips --fail-on.
//
// The ordering of the top two is a judgement call the query does not make:
// BROKEN_HARD_FAILURE (Case C) is ranked above PARTIAL_POLICY_GAP (Cases A
// and D) because the operation is failing outright right now, where a policy
// gap fails silently. Reasonable people could flip these; --fail-on any
// sidesteps the question entirely and is the better CI default.
export const SEVERITY_ORDER = [
  'info',
  'likely_intentional_deny_all',
  'partial_policy_gap',
  'broken_hard_failure',
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

  The connection string may also come from --db or the DATABASE_URL
  environment variable. Prefer the environment variable: a connection
  string on the command line lands in your shell history.

OPTIONS
  -d, --db <url>          Postgres connection string
      --include-system    Also scan auth/storage/cron/vault/realtime schemas.
                          Off by default: those are Supabase-managed and you
                          usually cannot act on findings there.
      --json              Emit raw findings as JSON (one object per row)
      --fail-on <sev>     Exit 1 if any finding is at or above this severity:
                            any                          any finding at all
                            likely-intentional-deny-all  ...and above
                            partial-policy-gap           ...and above
                            broken-hard-failure          only these
                            never                        (default)
                          'any' is the sensible CI setting.
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

  if (opts.command !== 'scan') {
    throw new Error(`unknown command: ${opts.command}. Did you mean 'scan'?`);
  }

  if (!opts.db) {
    throw new Error(
      'no connection string. Pass one as an argument, via --db, or set DATABASE_URL.'
    );
  }

  const sql = await loadQuery();
  // Loaded here rather than at module scope so --help and --version still work
  // if the pg dependency is missing or broken.
  const { runScan } = await import('./db.js');
  const rows = await runScan({
    connectionString: opts.db,
    ssl: opts.ssl,
    sql,
    includeSystem: opts.includeSystem,
  });

  if (opts.json) {
    renderJson(rows);
  } else {
    render(rows, { color: opts.color, includeSystem: opts.includeSystem });
  }

  return meetsThreshold(rows, opts.failOn) ? 1 : 0;
}

async function loadQuery() {
  const sql = await readFile(QUERY_PATH, 'utf8');
  if (sql.includes('__QUERY_NOT_INSTALLED__')) {
    throw new Error(
      `the detection query has not been installed yet (src/queries/silent-writes.sql is a placeholder).`
    );
  }
  return sql;
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
