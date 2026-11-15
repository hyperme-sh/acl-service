"""Explicit PostgreSQL-backed group wrap subjects; missing configuration disables."""
import json
import os
import re
from acl_service.infrastructure.media_bindings import parse_settings, _prepare_settings, _provisioned, _source, _same_source
from acl_service.infrastructure.statement_bindings import _path, _private_file, _unique
from acl_service.infrastructure.group_allocation_bindings import _group_ready
from acl_service.interfaces.api.private_wrap_routes import PrivateWrapBinding
from acl_service.infrastructure.group_wrap_store import GroupWrapStore


def load_group_wrap_bindings(environ=None,*,allocation_bindings=None,source_factory=None,store_factory=None):
    configured=(os.environ if environ is None else environ).get('SOCIACL_GROUP_WRAP_FILE')
    if configured is None:return None
    try:
        with _private_file(_path(configured)) as stream:raw=stream.read(65537)
        value=json.loads(raw,object_pairs_hook=_unique)
        if type(value) is not dict or type(value.get('version')) is not int or value['version']!=2:raise ValueError()
        settings=_prepare_settings(parse_settings(raw))
        allocated={}
        for binding in (allocation_bindings or {}).values():
            spec=(binding.authority,binding.client.origin)
            if binding.tenant in allocated and allocated[binding.tenant]!=spec:raise ValueError()
            allocated[binding.tenant]=spec
        prepared={}
        for row in settings:
            if row.tenant in prepared:continue
            _provisioned(row,allow_empty=True)
            with _private_file(row.key_file) as stream:key=stream.read(4097).decode('ascii')
            if re.fullmatch(r'[\x21-\x7e]{1,4096}',key) is None:raise ValueError()
            spec=allocated.get(str(row.tenant))
            if spec:
                authority,origin=spec
                if origin!=row.origin or not _same_source(row,authority.store):raise ValueError()
            else:authority=(source_factory or _source)(row)
            if not authority.production_ready or authority.tenant!=str(row.tenant):raise ValueError()
            _group_ready(authority)
            prepared[row.tenant]=(authority,key,row.origin)
        stores={tenant:(store_factory or GroupWrapStore)(origin,str(tenant),key)
                for tenant,(authority,key,origin) in prepared.items()}
        return {(row.tenant,row.subject):PrivateWrapBinding(str(row.tenant),row.reader,
                    prepared[row.tenant][0],stores[row.tenant]) for row in settings}
    except Exception:
        raise ValueError('Invalid private group wrap configuration') from None
