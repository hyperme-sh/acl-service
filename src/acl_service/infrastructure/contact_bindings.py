"""Explicit subjects, existing PostgreSQL sources and time-bounded contact trust."""
from dataclasses import dataclass
import copy
import importlib.util
import json
import os
from pathlib import Path
import re
import sys
from uuid import UUID

from acl_service.domain.history_store import AdmissionRejected
from acl_service.infrastructure.contact_journal import PRINCIPAL
from acl_service.infrastructure.media_postgres_settings import read_postgres_settings
from acl_service.infrastructure.statement_bindings import _path, _private_file, _unique

CONFIG_NAME='SOCIACL_CONTACT_BINDINGS_FILE'


@dataclass(frozen=True)
class ContactSettings:
    tenant: UUID
    subject: str
    principal: str
    postgres_file: Path
    policy_file: Path


def parse_settings(raw):
    if len(raw)>65536:raise ValueError('contact configuration capacity')
    value=json.loads(raw,object_pairs_hook=_unique)
    if (type(value) is not dict or set(value)!={'version','bindings'} or type(value['version']) is not int
            or value['version']!=1 or type(value['bindings']) is not list or not 1<=len(value['bindings'])<=64):raise ValueError('invalid contact bindings')
    result,seen=[],set()
    for row in value['bindings']:
        if type(row) is not dict or set(row)!={'tenant','subject','principal','postgresFile','policyFile'}:raise ValueError('invalid contact binding')
        tenant=UUID(row['tenant'])
        if not tenant.int or str(tenant)!=row['tenant']:raise ValueError('canonical tenant required')
        if type(row['subject']) is not str or not re.fullmatch(r'[\x21-\x7e]{1,256}',row['subject']):raise ValueError('invalid contact subject')
        if type(row['principal']) is not str or PRINCIPAL.fullmatch(row['principal']) is None:raise ValueError('invalid contact principal')
        key=(tenant,row['subject'])
        if key in seen:raise ValueError('duplicate contact subject')
        seen.add(key)
        result.append(ContactSettings(tenant,row['subject'],row['principal'],_path(row['postgresFile']),_path(row['policyFile'])))
    return tuple(result)


def read_trust(path):
    with _private_file(path) as stream:raw=stream.read(65537)
    if len(raw)>65536:raise ValueError('contact policy capacity')
    value=json.loads(raw,object_pairs_hook=_unique)
    if (type(value) is not dict or set(value)!={'version','from','until','trust'} or type(value['version']) is not int or value['version']!=1
            or type(value['from']) is not int or type(value['until']) is not int or not 0<=value['from']<value['until']<=9007199254740991
            or type(value['trust']) is not dict or set(value['trust'])!={'jwks','policy','pinnedIss'}):raise ValueError('invalid contact trust')
    def trust_at(at):
        if type(at) is not int or not value['from']<=at<value['until']:raise AdmissionRejected('contact trust expired')
        return copy.deepcopy(value['trust'])
    return trust_at


def _source(settings,trust_at):
    for name in ('history_admission','statement_source','contact_source'):
        path=Path('/opt/acl-admission')/(name+'.py')
        if name in sys.modules:
            if Path(sys.modules[name].__file__)!=path:raise ValueError('unexpected contact verifier module')
            continue
        spec=importlib.util.spec_from_file_location(name,path)
        module=importlib.util.module_from_spec(spec)
        sys.modules[name]=module
        try:spec.loader.exec_module(module)
        except BaseException:
            sys.modules.pop(name,None)
            raise
    store=settings.open()
    try:return sys.modules['contact_source'].ContactSource(store,trust_at=trust_at)
    except BaseException:
        store.close()
        raise


def load_contact_bindings(environ=None, *, source_factory=None):
    configured=(os.environ if environ is None else environ).get(CONFIG_NAME)
    if configured is None:return None
    sources={}
    try:
        with _private_file(_path(configured)) as stream:rows=parse_settings(stream.read(65537))
        from acl_service.interfaces.api.contact_routes import ContactBinding
        result,policies={},{}
        for row in rows:
            settings=read_postgres_settings(row.postgres_file,row.tenant)
            key=(settings.tenant,settings.source,settings.history_schema,settings.checkpoint_schema,settings.database_url)
            if key in policies and policies[key]!=row.policy_file:raise ValueError('conflicting contact trust')
            policies[key]=row.policy_file
            if key not in sources:sources[key]=(source_factory or _source)(settings,read_trust(row.policy_file))
            result[(row.tenant,row.subject)]=ContactBinding(row.principal,sources[key])
        return result
    except Exception:
        for source in sources.values():source.store.close()
        raise ValueError('Invalid contact source configuration') from None
