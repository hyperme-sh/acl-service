"""Classify hosted paths in reachable historical objects."""
import re

def is_wheel_excluded(name):
    return False

OWNERS = ('api/', 'acl_service/')
FORBIDDEN = re.compile(r'(^|/)(stripe|controlplane_billing|payment_service)([/.\-]|$)|^api/[^\n]*(billing|payment|stripe)', re.I)


def check_member(name, data):
    if is_wheel_excluded(name) or FORBIDDEN.search(name):
        raise ValueError('Hosted implementation in ' + name)
    if name.startswith(OWNERS) and name.endswith(('.py', '.json', '.toml')):
        if re.search(rb'\bstripe\b', data, re.I):
            raise ValueError('Provider implementation in ' + name)
    if name.endswith('.dist-info/METADATA') and re.search(rb'^Requires-Dist: (stripe|controlplane-billing|payment-service)\b', data, re.M | re.I):
        raise ValueError('Hosted dependency in ' + name)

