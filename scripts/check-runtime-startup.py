#!/usr/bin/env python3
"""Start an already-loaded image with owned, isolated synthetic dependencies."""
import argparse
from pathlib import Path
import re
import secrets
import subprocess
import uuid


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('image_id', help='Exact local image ID; tags and remote references are refused')
    args = parser.parse_args()
    if not re.fullmatch(r'sha256:[0-9a-f]{64}', args.image_id):
        parser.error('An exact local image ID is required')
    subprocess.run(['docker', 'image', 'inspect', args.image_id], check=True, capture_output=True)
    # The dependency image is pulled before creating the internal network.
    if subprocess.run(['docker', 'image', 'inspect', 'postgres:16-alpine'], capture_output=True).returncode:
        subprocess.run(['docker', 'pull', 'postgres:16-alpine'], check=True, timeout=180)
    prefix = 'acl-startup-' + uuid.uuid4().hex
    network, database, app, probe = (prefix + suffix for suffix in ('-net', '-db', '-app', '-probe'))
    password = secrets.token_hex(24)
    url = f'postgresql+psycopg://postgres:{password}@{database}:5432/postgres'
    fixture = {'DATABASE_URL': url, 'FIXTURE_ACL_URL': f'http://{app}:8000',
               **{name: str(uuid.uuid4()) for name in ('FIXTURE_TENANT_A', 'FIXTURE_TENANT_B',
                                                     'FIXTURE_USER_A', 'FIXTURE_USER_B', 'FIXTURE_USER_C')}}
    mount = f'type=bind,src={Path(__file__).resolve().parents[1] / "tests/runtime_startup_probe.py"},dst=/checks/probe.py,readonly'
    def docker(*command, timeout=180):
        result = subprocess.run(['docker', *command], text=True,
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=timeout)
        if result.returncode:
            print(result.stdout, result.stderr)
            result.check_returncode()
        return result.stdout
    def run_probe(phase):
        flags = [argument for name, value in fixture.items() for argument in ('--env', name + '=' + value)]
        print(docker('run', '--rm', '--name', probe, '--network', network,
                     '--read-only', '--tmpfs', '/tmp', '--mount', mount, *flags,
                     args.image_id, 'python', '-I', '/checks/probe.py', phase), end='')
    try:
        docker('network', 'create', '--internal', network)
        docker('run', '--detach', '--name', database, '--network', network,
               '--env', 'POSTGRES_PASSWORD=' + password, 'postgres:16-alpine')
        run_probe('initialize')
        docker('run', '--detach', '--name', app, '--network', network, '--read-only', '--tmpfs', '/tmp',
               '--env', 'DATABASE_URL=' + url, '--env', 'SERVICE_NAME=acl-service',
               '--env', 'FASTAPI_ENV=production', '--env', 'JWT_SECRET=' + secrets.token_hex(32),
               '--env', 'REFRESH_TOKEN_SECRET=' + secrets.token_hex(32), args.image_id)
        run_probe('exercise')
        docker('restart', '--time', '15', app)
        run_probe('restarted')
        print('Owned runtime startup and restart smoke checks passed')
    except (subprocess.SubprocessError, OSError):
        # Only the synthetic service's log; no host credentials are passed in.
        logs = subprocess.run(['docker', 'logs', '--tail', '80', app], capture_output=True, text=True)
        print(logs.stdout, logs.stderr)
        raise
    finally:
        for name in (probe, app, database):
            subprocess.run(['docker', 'rm', '--force', '--volumes', name], capture_output=True, timeout=30)
        subprocess.run(['docker', 'network', 'rm', network], capture_output=True, timeout=30)


if __name__ == '__main__':
    main()
