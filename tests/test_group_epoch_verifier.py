"""Mock-only adapter units. Native cross-language contracts run in CI."""
import ctypes
from unittest import TestCase
from unittest.mock import Mock, patch

from acl_service.infrastructure.group_epoch_verifier import (
    GroupEpochVerifier, LIBRARY, MAX_MANIFEST_DOCUMENT, MAX_GROUP_HISTORY,
)

MODULE = 'acl_service.infrastructure.group_epoch_verifier.ctypes.CDLL'


class GroupEpochVerifierTests(TestCase):
    def setUp(self):
        self.manifest, self.history, self.settled = [Mock(return_value=1) for _ in range(3)]
        self.library = Mock(sociacl_verify_group_epoch_manifest=self.manifest,
            sociacl_verify_group_epoch_history=self.history,
            sociacl_match_settled_group_epoch=self.settled)
        with patch(MODULE, return_value=self.library) as load:
            self.verifier = GroupEpochVerifier()
            load.assert_called_once_with(LIBRARY)

    def test_preserves_original_bytes_and_separates_admission_from_selection(self):
        raw = b'{"epoch":1,"epoch":2}'
        expected = b'{"ownerPub":"trusted"}'
        self.assertTrue(self.verifier.matches_manifest(raw, expected))
        args = self.manifest.call_args.args
        self.assertEqual(ctypes.string_at(args[0], args[1]), raw)
        self.assertEqual(ctypes.string_at(args[2], args[3]), expected)
        self.assertEqual(self.manifest.restype, ctypes.c_int)
        self.assertEqual(len(self.manifest.argtypes), 4)
        for call, native in [(self.verifier.verifies_history, self.history),
                             (self.verifier.matches_settled, self.settled)]:
            self.assertTrue(call(raw))
            args = native.call_args.args
            self.assertEqual(ctypes.string_at(args[0], args[1]), raw)
            self.assertEqual(native.argtypes, [ctypes.c_void_p, ctypes.c_size_t])
            self.assertEqual(native.restype, ctypes.c_int)
        self.history.assert_called_once()
        self.settled.assert_called_once()

    def test_only_native_one_is_success(self):
        for result in [0, -1, 2]:
            self.manifest.return_value = self.history.return_value = self.settled.return_value = result
            self.assertFalse(self.verifier.matches_manifest(b'{}', b'{}'))
            self.assertFalse(self.verifier.verifies_history(b'{}'))
            self.assertFalse(self.verifier.matches_settled(b'{}'))

    def test_types_and_bounds_refuse_before_native(self):
        for value in [None, '', bytearray(b'{}'), b'', b'x' * (MAX_MANIFEST_DOCUMENT + 1)]:
            self.assertFalse(self.verifier.matches_manifest(value, b'{}'))
            self.assertFalse(self.verifier.matches_manifest(b'{}', value))
        for value in [None, '', bytearray(b'{}'), b'', b'x' * (MAX_GROUP_HISTORY + 1)]:
            self.assertFalse(self.verifier.verifies_history(value))
            self.assertFalse(self.verifier.matches_settled(value))
        for native in [self.manifest, self.history, self.settled]:
            native.assert_not_called()

    def test_native_errors_refuse(self):
        for error in [OSError(), ValueError(), ctypes.ArgumentError()]:
            self.manifest.side_effect = self.history.side_effect = self.settled.side_effect = error
            self.assertFalse(self.verifier.matches_manifest(b'{}', b'{}'))
            self.assertFalse(self.verifier.verifies_history(b'{}'))
            self.assertFalse(self.verifier.matches_settled(b'{}'))

    def test_missing_library_or_symbol_never_falls_back(self):
        with patch(MODULE, side_effect=OSError()):
            with self.assertRaises(OSError): GroupEpochVerifier()
        for symbol in ['sociacl_verify_group_epoch_manifest',
                       'sociacl_verify_group_epoch_history', 'sociacl_match_settled_group_epoch']:
            library = Mock(spec=['sociacl_verify_group_epoch_manifest',
                                'sociacl_verify_group_epoch_history', 'sociacl_match_settled_group_epoch'])
            delattr(library, symbol)
            with patch(MODULE, return_value=library):
                with self.assertRaises(AttributeError): GroupEpochVerifier()
