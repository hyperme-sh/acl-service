"""Private, fixed PostgreSQL media source configuration."""
from dataclasses import dataclass, field
import json
from uuid import UUID
from sqlalchemy.engine import make_url

from acl_service.infrastructure.postgres_history_store import PostgresHistoryStore, scope_name
from acl_service.infrastructure.statement_bindings import _private_file, _unique


@dataclass(frozen=True)
class PostgresMediaSettings:
    database_url: str = field(repr=False)
    history_schema: str
    checkpoint_schema: str
    tenant: str
    source: str

    def open(self):
        return PostgresHistoryStore(self.database_url, history_schema=self.history_schema,
            checkpoint_schema=self.checkpoint_schema, tenant=self.tenant, source=self.source)


def read_postgres_settings(path, tenant):
    with _private_file(path) as stream:
        raw=stream.read(8193)
    if len(raw)>8192:
        raise ValueError('PostgreSQL configuration capacity')
    value=json.loads(raw,object_pairs_hook=_unique)
    if type(value) is not dict or set(value)!={'version','databaseUrl','historySchema','checkpointSchema','tenant','source'}:
        raise ValueError('invalid PostgreSQL source configuration')
    if type(value['version']) is not int or value['version']!=1 or value['tenant']!=str(tenant):
        raise ValueError('invalid PostgreSQL source binding')
    source=value['source']
    if type(source) is not str or str(UUID(source))!=source or not UUID(source).int:
        raise ValueError('invalid source identifier')
    history,checkpoint=scope_name(value['historySchema']),scope_name(value['checkpointSchema'])
    if history==checkpoint:
        raise ValueError('independent schemas required')
    if type(value['databaseUrl']) is not str:
        raise ValueError('invalid PostgreSQL address')
    url=make_url(value['databaseUrl'])
    if url.drivername!='postgresql+psycopg' or not url.host or not url.database or not url.username:
        raise ValueError('explicit PostgreSQL address required')
    return PostgresMediaSettings(value['databaseUrl'],history,checkpoint,str(tenant),source)
