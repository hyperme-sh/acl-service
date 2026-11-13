"""Isolated configuration units: no database, HTTP or verifier operations."""
import io
import json
from types import SimpleNamespace
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
from acl_service.infrastructure.statement_bindings import (
    CONFIG_NAME, MAX_CONFIG_BYTES, _private_file, load_statement_bindings, parse_settings,
)

TENANT = 'a5ed86d0-cb50-4404-a5ac-410aab086a82'


def row(**changes):
    return dict(tenant=TENANT, subject='s3rch-service', scope='forum',
                historyFile='/private/history.db', freshnessFile='/private/checkpoint.db', **changes)


def encode(rows=None):
    return json.dumps({'version': 1, 'bindings': rows if rows is not None else [row()]}).encode()


class BindingSettingsTests(unittest.TestCase):
    def test_default_off_and_invalid_configuration_are_fail_closed(self):
        self.assertIsNone(load_statement_bindings({}))
        for value in ['', 'relative', '/nonexistent-private-binding-file']:
            with self.subTest(value=value), self.assertRaisesRegex(RuntimeError, '^Invalid statement source binding configuration$'):
                load_statement_bindings({CONFIG_NAME: value})

    def test_exact_binding_and_shared_store_for_separate_subjects(self):
        other = row(); other['subject'] = 'another-service'
        settings = parse_settings(encode([row(), other]))
        self.assertEqual(str(settings[0].tenant), TENANT)
        self.assertEqual(settings[0].history, Path('/private/history.db'))
        self.assertEqual(len(settings), 2)

    def test_reject_invalid_envelopes_and_duplicate_json_fields(self):
        for data in [b'{}', b'[]', b'null', b'\xff', b'{',
                     b'{"version":1,"version":1,"bindings":[]}',
                     encode([]), encode([row()] * 65), b' ' * (MAX_CONFIG_BYTES + 1),
                     b'{"version":true,"bindings":[]}',
                     b'{"version":1,"bindings":{},"extra":1}']:
            with self.subTest(data=data[:80]), self.assertRaises((ValueError, UnicodeError)):
                parse_settings(data)

    def test_reject_invalid_identity_and_path_fields(self):
        cases = {'tenant': [None, 1, '', '00000000-0000-0000-0000-000000000000', TENANT.upper()],
                 'subject': [None, '', 'space subject', 'x' * 257, 'é'],
                 'scope': [None, '', '../forum', 'a/b', 'x' * 129],
                 'historyFile': [None, '', 'relative', '/a/../b', '/a//b', '/a/./b', '/' + 'x' * 4096]}
        for field, values in cases.items():
            for value in values:
                item = row(); item[field] = value
                with self.subTest(field=field, value=value), self.assertRaises(ValueError):
                    parse_settings(encode([item]))
        for item in [None, {}, dict(row(), extra=True)]:
            with self.assertRaises(ValueError): parse_settings(encode([item]))

    def test_reject_duplicate_bindings_and_conflicting_store_ownership(self):
        with self.assertRaises(ValueError): parse_settings(encode([row(), row()]))
        for changes in [{'freshnessFile': '/private/history.db'},
                        {'tenant': 'b5ed86d0-cb50-4404-a5ac-410aab086a82'},
                        {'subject': 'other', 'freshnessFile': '/private/other.db'},
                        {'subject': 'other', 'historyFile': '/private/checkpoint.db', 'freshnessFile': '/private/history.db'}]:
            item = row(); item.update(changes)
            with self.subTest(changes=changes), self.assertRaises(ValueError):
                parse_settings(encode([row(), item]))

    def test_private_file_rejects_public_permissions_symlinks_and_directories(self):
        # Model trusted root metadata; sandbox mounts may map uid 0 to nobody.
        original_stat = Path.stat
        def trusted_root_stat(path, *args, **kwargs):
            info = original_stat(path, *args, **kwargs)
            if path in (Path('/'), Path(tempfile.gettempdir())):
                return SimpleNamespace(st_uid=0, st_mode=info.st_mode)
            return info
        with tempfile.TemporaryDirectory() as directory, patch.object(Path, 'stat', trusted_root_stat):
            path = Path(directory) / 'binding.json'; path.write_bytes(encode()); path.chmod(0o600)
            with _private_file(path) as stream: self.assertEqual(stream.read(), encode())
            link = Path(directory) / 'link'; link.symlink_to(path)
            with self.assertRaises(ValueError): _private_file(link)
            path.chmod(0o640)
            with self.assertRaises(ValueError): _private_file(path)
            with self.assertRaises(ValueError): _private_file(Path(directory))
            path.chmod(0o600); Path(directory).chmod(0o777)
            try:
                with self.assertRaises(ValueError): _private_file(path)
            finally: Path(directory).chmod(0o700)

    def test_configuration_is_bounded_and_errors_do_not_expose_contents(self):
        stream = io.BytesIO(b'private-subject' * MAX_CONFIG_BYTES)
        with patch('acl_service.infrastructure.statement_bindings._private_file', return_value=stream), \
                patch('acl_service.infrastructure.statement_bindings._provisioned') as provisioned:
            with self.assertRaisesRegex(RuntimeError, '^Invalid statement source binding configuration$'):
                load_statement_bindings({CONFIG_NAME: '/private/config.json'})
            provisioned.assert_not_called()
        self.assertTrue(stream.closed)


if __name__ == '__main__': unittest.main()
