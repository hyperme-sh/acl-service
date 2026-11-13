"""Isolated adapter units; native signature contracts run separately in CI."""
import ctypes
from unittest import TestCase
from unittest.mock import Mock, patch

from acl_service.infrastructure.epoch_verifier import (
    EpochStatusVerifier, EpochManifestVerifier, LIBRARY, MAX_DOCUMENT, MAX_SAFE, MAX_MANIFEST_DOCUMENT,
)


class EpochVerifierTests(TestCase):
    def setUp(self):
        self.native = Mock(return_value=1)
        self.library = Mock(sociacl_verify_epoch_status=self.native)
        with patch('acl_service.infrastructure.epoch_verifier.ctypes.CDLL', return_value=self.library) as load:
            self.verifier = EpochStatusVerifier()
            load.assert_called_once_with(LIBRARY)

    def call(self, proof=b'{}', expected=b'{}', **policy):
        return self.verifier.matches_status(proof, expected,
            **{**dict(now_ms=100, skew_ms=0, policy_max_age_ms=1000), **policy})

    def test_preserves_exact_buffers_and_only_native_one_matches(self):
        raw = b'{"epoch":1,"epoch":2}'
        self.assertTrue(self.call(raw, b'{"expected":true}'))
        args = self.native.call_args.args
        self.assertEqual(ctypes.string_at(args[0], args[1]), raw)
        self.assertEqual(ctypes.string_at(args[2], args[3]), b'{"expected":true}')
        self.assertEqual(args[4:], (100, 0, 1000))
        for result in [0, -1, 2]:
            self.native.return_value = result
            self.assertFalse(self.call())

    def test_invalid_buffers_never_reach_native_code(self):
        for value in [None, '', bytearray(b'{}'), b'', b'x' * (MAX_DOCUMENT + 1)]:
            self.assertFalse(self.call(value))
            self.assertFalse(self.call(expected=value))
        self.native.assert_not_called()

    def test_invalid_integer_policy_never_wraps_ctypes_values(self):
        for field in ['now_ms', 'skew_ms', 'policy_max_age_ms']:
            for value in [True, -1, 1.5, '1', MAX_SAFE + 1]:
                policy = dict(now_ms=100, skew_ms=0, policy_max_age_ms=1000)
                policy[field] = value
                self.assertFalse(self.verifier.matches_status(b'{}', b'{}', **policy))
        self.native.assert_not_called()

    def test_native_failures_refuse_and_unavailable_library_does_not_fallback(self):
        for error in [OSError(), ValueError(), ctypes.ArgumentError()]:
            self.native.side_effect = error
            self.assertFalse(self.call())
        with patch('acl_service.infrastructure.epoch_verifier.ctypes.CDLL', side_effect=OSError()):
            with self.assertRaises(OSError):
                EpochStatusVerifier()
        with patch('acl_service.infrastructure.epoch_verifier.ctypes.CDLL', return_value=object()):
            with self.assertRaises(AttributeError):
                EpochStatusVerifier()


class EpochManifestVerifierTests(TestCase):
    def setUp(self):
        self.native = Mock(return_value=1)
        with patch('acl_service.infrastructure.epoch_verifier.ctypes.CDLL',
                   return_value=Mock(sociacl_verify_epoch_manifest=self.native)) as load:
            self.verifier = EpochManifestVerifier()
            load.assert_called_once_with(LIBRARY)

    def test_raw_documents_and_native_results(self):
        raw = b'{"epoch":1,"epoch":2}'
        self.assertTrue(self.verifier.matches_manifest(raw, b'{"expected":true}'))
        args = self.native.call_args.args
        self.assertEqual(ctypes.string_at(args[0], args[1]), raw)
        self.assertEqual(ctypes.string_at(args[2], args[3]), b'{"expected":true}')
        self.assertEqual(len(args), 4)
        for result in [0, -1, 2]:
            self.native.return_value = result
            self.assertFalse(self.verifier.matches_manifest(b'{}', b'{}'))

    def test_invalid_buffers_refuse_before_native(self):
        for value in [None, '', bytearray(b'{}'), b'', b'x' * (MAX_MANIFEST_DOCUMENT + 1)]:
            self.assertFalse(self.verifier.matches_manifest(value, b'{}'))
            self.assertFalse(self.verifier.matches_manifest(b'{}', value))
        self.native.assert_not_called()

    def test_failures_do_not_fallback(self):
        for error in [OSError(), ValueError(), ctypes.ArgumentError()]:
            self.native.side_effect = error
            self.assertFalse(self.verifier.matches_manifest(b'{}', b'{}'))
        with patch('acl_service.infrastructure.epoch_verifier.ctypes.CDLL', side_effect=OSError()):
            with self.assertRaises(OSError):
                EpochManifestVerifier()
        with patch('acl_service.infrastructure.epoch_verifier.ctypes.CDLL', return_value=object()):
            with self.assertRaises(AttributeError):
                EpochManifestVerifier()
