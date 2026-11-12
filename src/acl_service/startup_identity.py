"""Explicit startup grants in the existing tenant-scoped policy store."""
from uuid import UUID
from ._startup_contract import validate, fingerprint


def desired(config, person):
    config=validate(config)
    if (person.get('schema_version') != 1 or person.get('mapping_sha256') != fingerprint(config) or
        person.get('status') != 'bound' or person.get('tenant_id') != config['owner']['tenant_id'] or
        person.get('network_id') != config['owner']['network_id'] or person.get('permissions') != []):
        raise ValueError('Auth startup mapping differs')
    person_id = str(UUID(person['person_id']))
    subject = person.get('broker_subject')
    if not isinstance(subject,str) or not subject.strip() or len(subject)>255:
        raise ValueError('Bound broker subject required')
    organizations = person.get('organizations',[])
    expected = [{'slug':slug, 'id':org['organization_id'], 'tenant_id':org['tenant_id'], 'roles':org['roles']}
                for slug,org in sorted(config['binding']['organizations'].items())]
    if organizations != expected or any(o['tenant_id'] != config['owner']['tenant_id'] for o in organizations):
        raise ValueError('Explicit organization scopes and roles required')
    sea=config['binding']['sea_public_key']
    grants=[('p',[sea,'/platform/'+platform,'admin'])
            for platform,enabled in sorted(config['binding']['platform_admin'].items()) if enabled]
    grants += [('p',[sea,'/organizations/'+org['id'],role]) for org in organizations for role in org['roles']]
    # SEA remains the account identity. This explicit login alias is not a role
    # wildcard, Keycloak administration, or an email-derived identity.
    grants.append(('g',['user:'+subject,sea]))
    marker=('startup_binding',['startup-v1',fingerprint(config),person_id,sea,subject])
    return marker,grants


def plan(config,person,rows):
    marker,grants=desired(config,person)
    def key(row):
        values=[getattr(row,'v'+str(i)) for i in range(6)]
        while values and values[-1] is None: values.pop()
        return row.ptype,tuple(values)
    existing={key(row) for row in rows}
    markers={value for value in existing if value[0]=='startup_binding'}
    expected=(marker[0],tuple(marker[1]))
    if markers:
        if markers!={expected}: raise ValueError('Stored startup policy mapping conflicts')
        if any((ptype,tuple(rule)) not in existing for ptype,rule in grants):
            raise ValueError('Stored startup grant is missing; refusing implicit restoration')
        return []
    return [marker,*[(ptype,rule) for ptype,rule in grants if (ptype,tuple(rule)) not in existing]]
