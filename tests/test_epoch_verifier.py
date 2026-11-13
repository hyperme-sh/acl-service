"""Isolated adapter units; native signature contracts run separately in CI."""
import ctypes
from unittest import TestCase
from unittest.mock import Mock, patch

from acl_service.infrastructure.epoch_verifier import (
    EpochStatusVerifier, EpochManifestVerifier, LIBRARY, MAX_DOCUMENT, MAX_SAFE, MAX_MANIFEST_DOCUMENT,
    SettledEpochVerifier, MAX_EPOCH_HISTORY, PrivateGrantVerifier, EpochHistoryVerifier,
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


class SettledEpochVerifierTests(TestCase):
    def setUp(self):
        self.native = Mock(return_value=1)
        with patch('acl_service.infrastructure.epoch_verifier.ctypes.CDLL',
                   return_value=Mock(sociacl_match_settled_epoch=self.native)) as load:
            self.verifier = SettledEpochVerifier()
            load.assert_called_once_with(LIBRARY)

    def test_raw_bytes_and_exact_success(self):
        raw = b'{"epoch":1,"epoch":2}'
        self.assertTrue(self.verifier.matches_settled(raw))
        args = self.native.call_args.args
        self.assertEqual(ctypes.string_at(args[0], args[1]), raw)
        for result in [0,-1,2]:
            self.native.return_value = result
            self.assertFalse(self.verifier.matches_settled(raw))

    def test_bounds_and_types_refuse_before_native(self):
        for value in [None, '', bytearray(b'{}'), b'', b'x' * (MAX_EPOCH_HISTORY + 1)]:
            self.assertFalse(self.verifier.matches_settled(value))
        self.native.assert_not_called()

    def test_native_failure_and_missing_library_refuse(self):
        for error in [OSError(), ValueError(), ctypes.ArgumentError()]:
            self.native.side_effect = error
            self.assertFalse(self.verifier.matches_settled(b'{}'))
        with patch('acl_service.infrastructure.epoch_verifier.ctypes.CDLL', side_effect=OSError()):
            with self.assertRaises(OSError):
                SettledEpochVerifier()
        with patch('acl_service.infrastructure.epoch_verifier.ctypes.CDLL', return_value=object()):
            with self.assertRaises(AttributeError):
                SettledEpochVerifier()


class PrivateGrantVerifierTests(TestCase):
    def setUp(self):
        self.native = Mock(return_value=1)
        with patch('acl_service.infrastructure.epoch_verifier.ctypes.CDLL',
                   return_value=Mock(sociacl_verify_private_grant=self.native)) as load:
            self.verifier = PrivateGrantVerifier()
            load.assert_called_once_with(LIBRARY)

    def test_exact_buffers_and_only_one_matches(self):
        raw = b'{"grantBytes":"a","grantBytes":"b"}'
        self.assertTrue(self.verifier.matches_grant(raw, b'{"expected":true}'))
        args = self.native.call_args.args
        self.assertEqual(ctypes.string_at(args[0], args[1]),raw)
        self.assertEqual(ctypes.string_at(args[2], args[3]),b'{"expected":true}')
        for result in [0,-1,2]:
            self.native.return_value=result
            self.assertFalse(self.verifier.matches_grant(b'{}',b'{}'))

    def test_invalid_buffers_do_not_call_native(self):
        for value in [None,'',bytearray(b'{}'),b'',b'x'*(MAX_MANIFEST_DOCUMENT+1)]:
            self.assertFalse(self.verifier.matches_grant(value,b'{}'))
            self.assertFalse(self.verifier.matches_grant(b'{}',value))
        self.native.assert_not_called()

    def test_native_errors_or_absent_verifier_do_not_fallback(self):
        for error in [OSError(),ValueError(),ctypes.ArgumentError()]:
            self.native.side_effect=error
            self.assertFalse(self.verifier.matches_grant(b'{}',b'{}'))
        with patch('acl_service.infrastructure.epoch_verifier.ctypes.CDLL',side_effect=OSError()):
            with self.assertRaises(OSError): PrivateGrantVerifier()
        with patch('acl_service.infrastructure.epoch_verifier.ctypes.CDLL',return_value=object()):
            with self.assertRaises(AttributeError): PrivateGrantVerifier()


class EpochHistoryVerifierTests(TestCase):
    def test_history_admission_is_bounded_and_has_no_selection_method(self):
        native=Mock(return_value=1)
        with patch('acl_service.infrastructure.epoch_verifier.ctypes.CDLL',return_value=Mock(sociacl_verify_epoch_history=native)):
            verifier=EpochHistoryVerifier()
        self.assertFalse(hasattr(verifier,'matches_settled'))
        raw=b'{"epoch":1,"epoch":2}'
        self.assertTrue(verifier.verifies_history(raw))
        args=native.call_args.args
        self.assertEqual(ctypes.string_at(args[0],args[1]),raw)
        for value in [None,b'',bytearray(raw),b'x'*(MAX_EPOCH_HISTORY+1)]:
            self.assertFalse(verifier.verifies_history(value))
        native.return_value=0
        self.assertFalse(verifier.verifies_history(raw))
        native.side_effect=OSError()
        self.assertFalse(verifier.verifies_history(raw))
