/**
 * Output formatting.
 *
 * The queries own the words. This file decides where they go — it never
 * substitutes its own wording for an `explanation` or `caveat` a query
 * supplied, so that improving the prose is a SQL edit and nothing more.
 *
 * FINDINGS ARE GROUPED BY OBJECT, NOT BY FINDING TYPE. One broken object can
 * legitimately trip several detectors at once — a SECURITY DEFINER function
 * with no pinned search_path and PUBLIC EXECUTE is ONE thing to fix that
 * correctly produces both an E1 and an E3 row. Listing rows would report it as
 * two problems and overstate how much is actually wrong, so the object is the
 * unit of the report and the detectors that fired are listed underneath it.
 * The counts line says both numbers, which is also what the queries' own INFO
 * banner rows assert.
 */

// Short headings per finding_type. The detail under each is the query's own
// `explanation`; these only have to be scannable in a list.
const CASE_TITLES = {
  A: 'Write grant with no matching RLS policy',
  C: 'Write authorized, no SELECT privilege — misleading 42501',
  D: 'Write policy correct, SELECT policy missing',
  E1: 'PUBLIC holds EXECUTE on a SECURITY DEFINER function',
  E2: 'search_path is a quoted literal — function is broken',
  E3: 'SECURITY DEFINER function with no search_path',
};

// Keyed on the severity values the queries actually emit.
const SEVERITY_STYLE = {
  privilege_escalation_risk: ['\x1b[1;97;41m', 'ESCALATION'],
  broken_silently: ['\x1b[1;95m', 'BROKEN-SILENT'],
  broken_hard_failure: ['\x1b[1;31m', 'BROKEN'],
  partial_policy_gap: ['\x1b[1;31m', 'GAP'],
  likely_intentional_deny_all: ['\x1b[1;33m', 'DENY-ALL'],
  hygiene: ['\x1b[1;36m', 'HYGIENE'],
  info: ['\x1b[1;34m', 'INFO'],
};

const SEVERITY_RANK = [
  'info',
  'hygiene',
  'likely_intentional_deny_all',
  'partial_policy_gap',
  'broken_hard_failure',
  'broken_silently',
  'privilege_escalation_risk',
];

const sev = (v) => String(v ?? '').trim().toLowerCase().replace(/-/g, '_');

const RESET = '\x1b[0m';
const DIM = '\x1b[2m';
const BOLD = '\x1b[1m';

// Column-name variants tolerated on the way in.
const FIELDS = {
  type: ['finding_type', 'finding', 'case', 'case_name', 'pattern', 'check'],
  severity: ['severity', 'level'],
  schema: ['schema_name', 'schema', 'table_schema', 'nspname'],
  table: ['table_name', 'table', 'relname', 'object_name'],
  role: ['role_name', 'role', 'grantee', 'rolname'],
  command: ['ungoverned_operation', 'command', 'cmd', 'privilege_type', 'privilege', 'operation'],
  explanation: ['explanation', 'detail', 'description', 'message'],
  caveat: ['caveat', 'caveats', 'note'],
  title: ['title', 'finding_title', 'headline'],
};

function pick(row, names) {
  for (const n of names) {
    if (row[n] !== undefined && row[n] !== null && row[n] !== '') return row[n];
  }
  return null;
}

function normalize(row) {
  const out = {};
  for (const [key, names] of Object.entries(FIELDS)) out[key] = pick(row, names);
  out._raw = row;
  return out;
}

export function renderJson(rows) {
  console.log(JSON.stringify(rows, null, 2));
}

export function render(rows, { color = false, includeSystem = false } = {}) {
  const c = (code, s) => (color ? `${code}${s}${RESET}` : s);
  const out = [];

  const findings = [];
  const infos = [];
  for (const raw of rows) {
    const row = normalize(raw);
    if (sev(row.severity) === 'info') infos.push(row);
    else findings.push(row);
  }

  out.push('');
  out.push(c(BOLD, 'rowsaffected') + c(DIM, ' — silent failure scan'));
  out.push('');

  if (findings.length === 0) {
    out.push('  No findings.');
    out.push(c(DIM, '  No role holds a write grant without a policy covering it, none is'));
    out.push(c(DIM, '  missing the SELECT access its writes depend on, and no SECURITY'));
    out.push(c(DIM, '  DEFINER function is left unpinned or PUBLIC-executable.'));
  } else {
    const objects = [...groupBy(findings, objectKey)].sort(
      (a, b) =>
        SEVERITY_RANK.indexOf(highestSeverity(b[1])) - SEVERITY_RANK.indexOf(highestSeverity(a[1])) ||
        target(a[1][0]).localeCompare(target(b[1][0]))
    );

    for (const [, group] of objects) {
      const worst = highestSeverity(group);
      const count = group.length;
      out.push(
        `  ${badge(worst, color)} ${c(BOLD, target(group[0]))}` +
          (count > 1 ? c(DIM, `  (${count} issues on this object)`) : '')
      );

      const ordered = [...group].sort(
        (a, b) => SEVERITY_RANK.indexOf(sev(b.severity)) - SEVERITY_RANK.indexOf(sev(a.severity))
      );

      for (const row of ordered) {
        const meta = [
          row.role && `role ${row.role}`,
          row.command && `on ${row.command}`,
        ].filter(Boolean);
        out.push(
          `      ${severityTag(row.severity, color)} ${titleFor(row)}` +
            (meta.length ? c(DIM, `  ·  ${meta.join('  ·  ')}`) : '')
        );
        if (row.explanation) {
          for (const line of wrap(row.explanation, 68)) out.push(c(DIM, `         ${line}`));
        }
      }
      out.push('');
    }

    // Both numbers, always. A row count alone overstates the work when one
    // object trips several detectors.
    const objectCount = objects.length;
    out.push(
      c(
        DIM,
        `  ${findings.length} finding${findings.length === 1 ? '' : 's'} across ` +
          `${objectCount} object${objectCount === 1 ? '' : 's'}.`
      )
    );
  }

  // E2 and E3 are preventable at DDL time, and the queries' own text points at
  // an appendix the CLI user has no way to open. Point at the command instead.
  if (findings.some((r) => /^E[23]\b/.test(String(r.type ?? '').toUpperCase()))) {
    out.push('');
    out.push(c(DIM, '  These search_path findings are preventable, not just fixable. Run'));
    out.push(`  ${c(BOLD, 'rowsaffected prevention')}${c(DIM, ' for an event trigger that refuses them at DDL time.')}`);
  }

  if (!includeSystem) {
    out.push(
      c(
        DIM,
        '  Scope: user schemas only. Re-run with --include-system to add auth/storage/cron/vault/realtime.'
      )
    );
  }

  // Caveats always render, findings or not — they qualify what a clean
  // result means just as much as what a finding means.
  const caveats = uniqueCaveats([...findings, ...infos]);
  if (caveats.length) {
    out.push('');
    out.push(`  ${badge('info', color)} ${c(BOLD, 'Read this before acting on — or dismissing — anything above.')}`);
    for (const caveat of caveats) {
      const lines = wrap(caveat, 72);
      out.push(c(DIM, `      • ${lines[0]}`));
      for (const line of lines.slice(1)) out.push(c(DIM, `        ${line}`));
    }
  }

  out.push('');
  console.log(out.join('\n'));
}

/**
 * The identity of the thing to fix. A table finding and a function finding can
 * never collide here: function rows carry a signature ending in ')'.
 */
function objectKey(row) {
  return `${row.schema ?? ''}\u0000${row.table ?? ''}`;
}

function target(row) {
  const name = row.table;
  if (!name) return '(database-wide)';
  // Function rows arrive as `oid::regprocedure::text`, which is already
  // schema-qualified whenever the function is not visible on the search_path.
  // Prefixing schema_name again would render `auth.auth.fn()`.
  const alreadyQualified = /^[^(]*\./.test(name);
  if (alreadyQualified || !row.schema) return name;
  return `${row.schema}.${name}`;
}

function titleFor(row) {
  if (row.title) return row.title;
  const key = String(row.type ?? '').trim().toUpperCase();
  // finding_type arrives as CASE_A_SILENT_ZERO_ROWS or E1_PUBLIC_EXECUTE_ON_DEFINER.
  const label =
    key.match(/^CASE[_\s]*([A-Z])(?=[_\s]|$)/)?.[1] ?? key.match(/^(E\d+)(?=[_\s]|$)/)?.[1];
  if (label && CASE_TITLES[label]) {
    const prefix = /^E\d+$/.test(label) ? label : `Case ${label}`;
    return `${prefix} — ${CASE_TITLES[label]}`;
  }
  // Unknown type: show it as-is rather than inventing a description for it.
  return key.toLowerCase().replace(/_/g, ' ');
}

// The queries pack more than one caveat into a single `caveat` string, joined by
// ALL-CAPS labels ("HEURISTIC, NOT A VERDICT: ...", "LIMIT: ..."), and the same
// caveat recurs on many rows. Split on those labels — only where one begins a
// sentence, so a label containing its own capitals is not torn apart — then
// dedupe, so each distinct caveat is stated exactly once.
const CAVEAT_SPLIT = /\n{2,}|(?<=^|[.!?]\s)(?=[A-Z][A-Z0-9 ,'’-]{2,}:\s)/;

function uniqueCaveats(rows) {
  const seen = new Set();
  for (const row of rows) {
    if (!row.caveat) continue;
    for (const part of String(row.caveat).split(CAVEAT_SPLIT)) {
      const text = part.trim();
      if (text) seen.add(text);
    }
  }
  return [...seen];
}

function highestSeverity(group) {
  let best = group[0] ? sev(group[0].severity) : 'info';
  for (const row of group) {
    if (SEVERITY_RANK.indexOf(sev(row.severity)) > SEVERITY_RANK.indexOf(best)) {
      best = sev(row.severity);
    }
  }
  return best;
}

function badge(severity, color) {
  const [code, label] = SEVERITY_STYLE[sev(severity)] ?? [BOLD, String(severity).toUpperCase()];
  const text = ` ${label} `;
  return color ? `${code}${text}${RESET}` : `[${label}]`;
}

function severityTag(severity, color) {
  const [code, label] = SEVERITY_STYLE[sev(severity)] ?? [BOLD, String(severity ?? '?').toUpperCase()];
  const padded = label.padEnd(13);
  return color ? `${code}${padded}${RESET}` : padded;
}

function groupBy(items, keyFn) {
  const map = new Map();
  for (const item of items) {
    const key = keyFn(item);
    if (!map.has(key)) map.set(key, []);
    map.get(key).push(item);
  }
  return map;
}

function wrap(text, width) {
  const lines = [];
  for (const paragraph of String(text).split('\n')) {
    let line = '';
    for (const word of paragraph.trim().split(/\s+/)) {
      if (!word) continue;
      if (line && line.length + 1 + word.length > width) {
        lines.push(line);
        line = word;
      } else {
        line = line ? `${line} ${word}` : word;
      }
    }
    lines.push(line);
  }
  return lines.filter((l, i, a) => l !== '' || (i > 0 && i < a.length - 1));
}
