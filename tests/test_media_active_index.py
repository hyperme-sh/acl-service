"""Pure installation and stable checkpoint checks with mocked SQL."""
from contextlib import contextmanager
import hashlib
import json
from unittest.mock import Mock

import pytest
from acl_service.domain.media_checkpoint import media_checkpoint_digest
from acl_service.infrastructure import media_active_index as module


def test_checkpoint_preserves_original_format():
    encoded=lambda x:json.dumps(x,sort_keys=True,separators=(',',':'),allow_nan=False).encode()
    expected=hashlib.sha256(encoded(['private-media-v1','tenant','object'])+
        hashlib.sha256(encoded(3)+b'nonce'+b'document').digest()).digest()
    assert media_checkpoint_digest('tenant','object',3,b'nonce',b'document')==expected


@pytest.mark.parametrize('failure',[None,'missing','checkpoint','oversized','document','deletion','capacity'])
def test_explicit_index_installation_checks_every_retained_checkpoint(monkeypatch,failure):
    store=Mock();db=Mock();writes=[]
    docs=[{}, {'deletion':{'cleanupComplete':True,'owner':'owner','command':'command','proofDigest':'digest','claims':{}}}]
    if failure=='document':docs[0]=[]
    if failure=='deletion':docs[1]={'deletion':{'cleanupComplete':True}}
    rows=[(0,b'nonce',json.dumps(doc).encode()) for doc in docs]
    if failure=='oversized':rows[0]=(0,b'nonce',b' '*(6*1024*1024+1))
    def execute(sql,args=()):
        result=Mock()
        if sql.startswith('SELECT object FROM ('):
            result.fetchall.return_value=[(str(i),) for i in range(65 if failure=='capacity' else 2)]
        elif sql.startswith('SELECT revision'):
            result.fetchone.return_value=None if failure=='missing' else rows[int(args[0])]
        elif sql.startswith('SELECT digest'):
            result.fetchone.return_value=(b'wrong',) if failure=='checkpoint' else (media_checkpoint_digest('tenant',args[0],*rows[int(args[0])]),)
        else:writes.append((sql,args))
        return result
    db.execute.side_effect=execute
    @contextmanager
    def transaction(**options):
        assert options=={'write':False}
        yield db
    store._transaction=transaction
    monkeypatch.setattr(module,'PostgresHistoryStore',Mock(return_value=store))
    def install():module.install_active_media_index('private',history_schema='acl_h',checkpoint_schema='acl_c',tenant='tenant',source='source')
    if failure:
        with pytest.raises(ValueError):install()
        assert writes==[]
    else:
        install()
        assert [args for sql,args in writes if sql.startswith('INSERT')]==[('0',)]
        assert sum('SET version=2' in sql for sql,args in writes)==2
    store.close.assert_called_once()
