"""Fixed native adapter for explicit owner deletion intent."""
import ctypes
from acl_service.infrastructure.epoch_verifier import LIBRARY, MAX_SAFE


class PrivateDeletionVerifier:
    def __init__(self):
        self._library=ctypes.CDLL(LIBRARY)
        self._verify=self._library.sociacl_verify_private_deletion
        self._verify.argtypes=[ctypes.c_void_p,ctypes.c_size_t,ctypes.c_void_p,ctypes.c_size_t,ctypes.c_uint64]
        self._verify.restype=ctypes.c_int

    def matches_deletion(self, proof: bytes, expected: bytes, *, now_ms: int) -> bool:
        if any(type(value) is not bytes or not 0<len(value)<=8192 for value in (proof,expected)):
            return False
        if type(now_ms) is not int or not 0<=now_ms<=MAX_SAFE:
            return False
        held=ctypes.create_string_buffer(proof);context=ctypes.create_string_buffer(expected)
        try:
            return self._verify(held,len(proof),context,len(expected),now_ms)==1
        except (OSError,ValueError,ctypes.ArgumentError):
            return False
