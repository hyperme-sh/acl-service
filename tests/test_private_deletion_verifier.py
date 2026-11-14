"""Isolated deletion adapter units; native contracts run in CI."""
import ctypes
from unittest import TestCase
from unittest.mock import Mock,patch
from acl_service.infrastructure.private_deletion_verifier import PrivateDeletionVerifier
from acl_service.infrastructure.epoch_verifier import LIBRARY,MAX_SAFE

class DeletionVerifierTests(TestCase):
    def test_exact_bytes_results_and_bounds(self):
        native=Mock(return_value=1)
        with patch('acl_service.infrastructure.private_deletion_verifier.ctypes.CDLL',return_value=Mock(sociacl_verify_private_deletion=native)) as load:
            verifier=PrivateDeletionVerifier();load.assert_called_once_with(LIBRARY)
        raw=b'{"duplicate":1,"duplicate":2}'
        self.assertTrue(verifier.matches_deletion(raw,b'{}',now_ms=100))
        args=native.call_args.args
        self.assertEqual(ctypes.string_at(args[0],args[1]),raw)
        self.assertEqual(ctypes.string_at(args[2],args[3]),b'{}');self.assertEqual(args[4],100)
        for result in [0,-1,2]:
            native.return_value=result;self.assertFalse(verifier.matches_deletion(raw,b'{}',now_ms=100))
        for error in [OSError(),ValueError(),ctypes.ArgumentError()]:
            native.side_effect=error;self.assertFalse(verifier.matches_deletion(raw,b'{}',now_ms=100))
        native.reset_mock()
        for bad in [None,'',bytearray(b'{}'),b'',b'x'*8193]:
            self.assertFalse(verifier.matches_deletion(bad,b'{}',now_ms=100))
            self.assertFalse(verifier.matches_deletion(b'{}',bad,now_ms=100))
        for bad in [True,-1,1.5,'1',MAX_SAFE+1]:
            self.assertFalse(verifier.matches_deletion(b'{}',b'{}',now_ms=bad))
        native.assert_not_called()
        for result in [object(),None]:
            with patch('acl_service.infrastructure.private_deletion_verifier.ctypes.CDLL',return_value=result):
                with self.assertRaises(AttributeError):PrivateDeletionVerifier()
