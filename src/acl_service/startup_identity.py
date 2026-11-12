"""Explicit startup grants in the existing tenant-scoped policy store."""
from uuid import UUID
from ._startup_contract import validate, fingerprint


def desired(config, person):
    validate(config)
    if (person.get('schema_version') != 1 or person.get('mapping_sha256') != fingerprint(config) or
        person.get('status') != 'bound' or person.get('tenant_id') != config['tenant_id'] or
        person.get('network_id') != config['network_id'] or person.get('permissions') != []):
        raise ValueError('Auth startup mapping differs')
    person_id = str(UUID(person['person_id']))
    subject = person.get('broker_subject')
    if not isinstance(subject,str) or not subject.strip() or len(subject)>255:
        raise ValueError('Bound broker subject required')
    organizations = person.get('organizations',[])
    if [o['slug'] for o in organizations] != config['organizations']:
        raise ValueError('Organization scope inventory differs')
    ids=[str(UUID(o['id'])) for o in organizations]
    if len(set(ids)) != 3 or any(o['roles'] != ['owner','admin'] for o in organizations):
        raise ValueError('Explicit owner/admin memberships required')
    sea=config['sea_public_key']
    grants=[('p',[sea,'/platform/spanopticon','admin']), ('p',[sea,'/platform/hyperme.sh','admin'])]
    grants += [('p',[sea,'/organizations/'+oid,role]) for oid in ids for role in ['owner','admin']]
    # SEA remains the account identity. This explicit login alias is not a role
    # wildcard, Keycloak administration, or an email-derived identity.
    grants.append(('g',[subject,sea]))
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
