/**
 * Output formatting.
 *
 * The query owns the words. This file decides where they go — it never
 * substitutes its own wording for an `explanation` or `caveat` the query
 * supplied, so that improving the prose is a SQL edit and nothing more.
 */

// Short headings for the query's finding_type values. The one-line summary
// under each heading is the query's own `explanation`; these only have to be
// scannable in a list.
const CASE_TITLES = {
  A: 'Write grant with no matching RLS policy',
  C: 'Write authorized, but no SELECT privilege — misleading 42501',
  D: 'Write policy correct, SELECT policy missing',
};

// Keyed on the severity values the query actually emits.
const SEVERITY_STYLE = {
  broken_hard_failure: ['\x1b[1;97;41m', 'BROKEN'],
  partial_policy_gap: ['\x1b[1;31m', 'GAP'],
  likely_intentional_deny_all: ['\x1b[1;33m', 'DENY-ALL'],
  info: ['\x1b[1;34m', 'INFO'],
};

const SEVERITY_RANK = [
  'info',
  'likely_intentional_deny_all',
  'partial_policy_gap',
  'broken_hard_failure',
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
  out.push(c(BOLD, 'rowsaffected') + c(DIM, ' — silent write failure scan'));
  out.push('');

  if (findings.length === 0) {
    out.push('  No findings.');
    out.push(
      c(DIM, '  No role holds a write grant without a policy covering it, and none is')
    );
    out.push(c(DIM, '  missing the SELECT access its writes depend on.'));
  } else {
    const groups = [...groupBy(findings, (r) => r.type ?? 'other')].sort(
      (a, b) => SEVERITY_RANK.indexOf(highestSeverity(b[1])) - SEVERITY_RANK.indexOf(highestSeverity(a[1]))
    );

    for (const [type, group] of groups) {
      const worst = highestSeverity(group);
      out.push(
        `  ${badge(worst, color)} ${c(BOLD, titleFor(type, group))}  ${c(
          DIM,
          `(${group.length} ${group.length === 1 ? 'finding' : 'findings'})`
        )}`
      );

      const shared = sharedExplanation(group);
      if (shared) {
        for (const line of wrap(shared, 74)) out.push(c(DIM, `      ${line}`));
      }
      out.push('');

      // Case A mixes deny-all and partial-gap rows; worst first within the group.
      const ordered = [...group].sort(
        (a, b) =>
          SEVERITY_RANK.indexOf(sev(b.severity)) - SEVERITY_RANK.indexOf(sev(a.severity)) ||
          target(a).localeCompare(target(b))
      );

      for (const row of ordered) {
        out.push(`      ${severityTag(row.severity, color)} ${c(BOLD, target(row))}`);
        const meta = [
          row.role && `role ${row.role}`,
          row.command && `on ${row.command}`,
        ].filter(Boolean);
        if (meta.length) out.push(c(DIM, `         ${meta.join('  ·  ')}`));
        if (!shared && row.explanation) {
          for (const line of wrap(row.explanation, 70)) out.push(c(DIM, `         ${line}`));
        }
      }
      out.push('');
    }

    out.push(c(DIM, `  ${findings.length} finding(s) total.`));
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
    const heading =
      infos.find((r) => r.explanation)?.explanation ?? 'Read this before acting on the result.';
    out.push('');
    out.push(`  ${badge('info', color)} ${c(BOLD, wrap(heading, 70)[0])}`);
    for (const line of wrap(heading, 70).slice(1)) out.push(c(BOLD, `      ${line}`));
    for (const caveat of caveats) {
      const lines = wrap(caveat, 72);
      out.push(c(DIM, `      • ${lines[0]}`));
      for (const line of lines.slice(1)) out.push(c(DIM, `        ${line}`));
    }
  }

  out.push('');
  console.log(out.join('\n'));
}

function target(row) {
  const parts = [row.schema, row.table].filter(Boolean);
  return parts.length ? parts.join('.') : '(database-wide)';
}

function titleFor(type, group) {
  const fromQuery = group.find((r) => r.title)?.title;
  if (fromQuery) return fromQuery;
  const key = String(type).trim().toUpperCase();
  // finding_type arrives as e.g. CASE_A_SILENT_ZERO_ROWS.
  const letter = key.match(/^CASE[_\s]*([A-Z])(?=[_\s]|$)/)?.[1] ?? key;
  if (CASE_TITLES[letter]) return `Case ${letter} — ${CASE_TITLES[letter]}`;
  // Unknown type: show it as-is rather than inventing a description for it.
  return key.toLowerCase().replace(/_/g, ' ');
}

function sharedExplanation(group) {
  const first = group[0]?.explanation;
  if (!first) return null;
  return group.every((r) => r.explanation === first) ? first : null;
}

// The query packs more than one caveat into a single `caveat` string, joined by
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
  const padded = label.padEnd(8);
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
