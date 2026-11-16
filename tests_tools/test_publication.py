import importlib.util
import json
from pathlib import Path
from types import SimpleNamespace

import pytest

spec = importlib.util.spec_from_file_location('publication', Path(__file__).resolve().parents[1] / 'scripts/publish_container.py')
publication = importlib.util.module_from_spec(spec)
spec.loader.exec_module(publication)
REVISION = 'a' * 40
IMAGE = 'sha256:' + 'b' * 64


def test_test_is_a_moving_channel():
    plan = publication.publication_plan(REVISION, IMAGE, 'test')
    assert plan['targets'] == ['ghcr.io/hyperme-sh/acl-service/runtime:test']


@pytest.mark.parametrize('channel,version', [('test', '0.1.0'), ('latest', None), ('release', None),
    ('release', '0.24.0'), ('release', '../escape'), ('release', '$(command)'), ('release', 'main')])
def test_unsafe_or_unauthorized_tag_forms_fail(channel, version):
    with pytest.raises(ValueError): publication.publication_plan(REVISION, IMAGE, channel, version)


@pytest.mark.parametrize('change', [None, 'id', 'revision', 'push', 'remote'])
def test_publish_checks_identity_and_cleans_local_tag(change):
    calls = []
    def run(args, **kwargs):
        calls.append(args)
        if args[1:3] == ['image', 'inspect']:
            return SimpleNamespace(stdout=json.dumps([{'Id': IMAGE if change != 'id' and not (change == 'remote' and args[-1] != IMAGE) else 'wrong',
                'Config': {'Labels': {'org.opencontainers.image.revision': REVISION if change != 'revision' else 'wrong'}}}]))
        if args[1] == 'push' and change == 'push': raise RuntimeError('push refused')
    plan = publication.publication_plan(REVISION, IMAGE, 'test')
    if change:
        with pytest.raises((ValueError, RuntimeError)): publication.publish(plan, run)
    else: publication.publish(plan, run)
    if change in ('id', 'revision'):
        assert len(calls) == 1
    else:
        assert calls[1] == ['docker', 'tag', IMAGE, plan['targets'][0]]
        assert calls[-1] == ['docker', 'image', 'rm', plan['targets'][0]]


