// Signature parsing and current identity verification happen before this policy.
// The parent forum is fixed by the protected scope, never by request JSON.
export function authorizeAppObjectAppend(proposed, held, allowed, now) {
  if (!proposed.length) return;
  const {object, owner} = proposed[0].record;
  const room = object.startsWith('room_'), statement = object.startsWith('stmt_');
  if ((!room && !statement) || proposed.some(row => row.record.object !== object || row.record.owner !== owner ||
      (statement && row.kind === 'post')) || !allowed('see', owner) || !allowed('post', owner))
    throw Error('statement-denied');
  if (room && ![...held, ...proposed].some(row => row.kind === 'object' && row.record.object === object && row.record.owner === owner))
    throw Error('missing-room-owner');
  for (const row of proposed) if (row.kind === 'see' || row.kind === 'post') {
    if (row.record.until > now + 3600 || (row.record.stated === 1 &&
        (!allowed('see', row.record.accessor) || (row.kind === 'post' && !allowed('post', row.record.accessor)))))
      throw Error('reader-denied');
  }
}
