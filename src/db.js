import pg from 'pg';

const { Client } = pg;

/**
 * Connect, run the detection query, disconnect.
 *
 * Scope is controlled by the `rowsaffected.include_system` runtime setting
 * rather than a bind parameter — that is the query's own design, so that an
 * unset value coalesces to the safe default instead of silently widening
 * scope. We always set it explicitly (never leave it to whatever the session
 * inherited) and set it transaction-locally, which keeps it correct on
 * Supabase's transaction pooler where session state does not persist between
 * statements.
 */
export async function runScan({ connectionString, ssl, queries, includeSystem }) {
  const client = new Client({
    connectionString,
    ssl: resolveSsl(connectionString, ssl),
    // A scan is read-only catalog work; it should never sit and hang.
    connectionTimeoutMillis: 15_000,
    statement_timeout: 60_000,
    application_name: 'rowsaffected',
  });

  try {
    await client.connect();
  } catch (err) {
    throw new Error(`could not connect: ${err.message}`);
  }

  let inTransaction = false;
  try {
    // READ ONLY is belt-and-braces: the query only reads catalogs, and this
    // makes that a guarantee the server enforces rather than a claim we make.
    await client.query('BEGIN READ ONLY');
    inTransaction = true;
    await client.query("SELECT set_config('rowsaffected.include_system', $1, true)", [
      includeSystem ? 'on' : 'off',
    ]);
    // Every detection query runs inside the one transaction, so all of them see
    // the same catalog snapshot and the same include_system setting. Rows are
    // concatenated: each query emits the same 8 columns, so one formatter
    // handles them all.
    const rows = [];
    for (const { name, sql } of queries) {
      try {
        const result = await client.query(sql);
        rows.push(...result.rows);
      } catch (err) {
        throw new Error(`${name} query failed: ${err.message}`);
      }
    }
    await client.query('COMMIT');
    inTransaction = false;
    return rows;
  } catch (err) {
    if (inTransaction) await client.query('ROLLBACK').catch(() => {});
    throw err instanceof Error && / query failed: /.test(err.message)
      ? err
      : new Error(`scan failed: ${err.message}`);
  } finally {
    await client.end().catch(() => {});
  }
}

function resolveSsl(connectionString, sslEnabled) {
  if (!sslEnabled) return false;
  // An explicit sslmode in the URL is the user's decision; let pg honour it.
  if (/[?&]sslmode=/.test(connectionString)) return undefined;
  // Supabase and most hosted Postgres terminate TLS with a cert chain that is
  // not in Node's default trust store. Encrypt, but do not verify the chain.
  return { rejectUnauthorized: false };
}
