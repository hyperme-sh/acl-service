// Called with parsed, verified, canonically deduplicated rows under the graph fence.
export function enforceStatementQuota(held, novel, owner, principals) {
  if (!novel.length) return;
  const members = new Set(principals);
  if (!members.has(owner)) throw Error('unknown-statement-owner');
  const attributed = row => row.record.owner === owner && (
    (['object', 'see'].includes(row.kind) && row.record.object.startsWith('stmt_')) ||
    (['object', 'see', 'post'].includes(row.kind) && row.record.object.startsWith('room_')));
  const retained = held.filter(attributed), added = novel.filter(attributed);
  if (added.length !== novel.length) throw Error('invalid-statement-owner');
  const rows = [...retained, ...added];
  if (new Set(rows.filter(row => row.kind === 'object' && row.record.object.startsWith('room_')).map(row => row.record.object)).size > 32)
    throw Error('room-owner-capacity');
  const rowLimit = Math.min(128, Math.floor(512 / members.size));
  const byteLimit = Math.min(256 * 1024, Math.floor(2 * 1024 * 1024 / members.size));
  const bytes = rows.reduce((sum, {kind, soul, record}) => sum + Buffer.byteLength(JSON.stringify({kind, soul, record})), 0);
  if (rows.length > rowLimit || bytes > byteLimit) throw Error('statement-owner-capacity');
}
