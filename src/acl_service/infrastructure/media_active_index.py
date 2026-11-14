"""Explicit bounded installation of the independent active-media index."""
import json
from acl_service.domain.media_checkpoint import media_checkpoint_digest
from acl_service.infrastructure.postgres_history_store import PostgresHistoryStore


def install_active_media_index(url,*,history_schema,checkpoint_schema,tenant,source):
    """Verify at most 64 old objects before installing; never rebuild an index."""
    store=PostgresHistoryStore(url,history_schema=history_schema,checkpoint_schema=checkpoint_schema,
        tenant=tenant,source=source)
    try:
        with store._transaction(write=False) as db:
            objects=db.execute('SELECT object FROM (SELECT object FROM media_sources UNION SELECT object FROM freshness.media_checkpoints) AS candidates ORDER BY object LIMIT 65').fetchall()
            if len(objects)>64:raise ValueError('media upgrade capacity')
            active=[]
            for (object,) in objects:
                row=db.execute('SELECT revision,nonce,document FROM media_sources WHERE object=?',(object,)).fetchone()
                checkpoint=db.execute('SELECT digest FROM freshness.media_checkpoints WHERE object=?',(object,)).fetchone()
                if row is None or len(row[2])>6*1024*1024 or checkpoint!=(media_checkpoint_digest(tenant,object,*row),):
                    raise ValueError('media upgrade checkpoint mismatch')
                doc=json.loads(row[2])
                if type(doc) is not dict:raise ValueError('invalid media document')
                deleted=doc.get('deletion')
                if type(deleted) is dict and deleted.get('cleanupComplete') is True:
                    if not all(key in deleted for key in ('owner','command','proofDigest','claims')):
                        raise ValueError('invalid completed deletion')
                else:active.append(object)
            db.execute('CREATE TABLE freshness.media_active (object TEXT PRIMARY KEY REFERENCES freshness.media_checkpoints(object))')
            for object in active:db.execute('INSERT INTO freshness.media_active VALUES(?)',(object,))
            # Old processes must refuse subsequent writes instead of omitting index updates.
            for prefix in ('','freshness.'):
                db.execute(f'ALTER TABLE {prefix}source_marker DROP CONSTRAINT source_marker_version_check')
                db.execute(f'UPDATE {prefix}source_marker SET version=2 WHERE id=1')
                db.execute(f'ALTER TABLE {prefix}source_marker ADD CONSTRAINT source_marker_version_check CHECK(version=2)')
    finally:store.close()
