"""Bounded adapter to the installed SociACL Rust epoch-status verifier."""
import ctypes

LIBRARY = '/opt/acl-admission/libsociacl.so'
MAX_DOCUMENT = 16_384
MAX_SAFE = 9_007_199_254_740_991
MAX_MANIFEST_DOCUMENT = 65_536
MAX_EPOCH_HISTORY = 524_288


class EpochStatusVerifier:
    """Matches signed status to independently trusted context; never grants access.

    A matching cancellation also returns True. Callers retain current Check,
    enrollment, epoch selection and rollback protection. Neither input may
    manufacture the trusted context from a request's claimed values.
    """

    def __init__(self):
        # Fixed, root-owned image location. No environment/PATH library search.
        self._library = ctypes.CDLL(LIBRARY)
        self._verify = self._library.sociacl_verify_epoch_status
        self._verify.argtypes = [ctypes.c_void_p, ctypes.c_size_t,
                                 ctypes.c_void_p, ctypes.c_size_t,
                                 ctypes.c_uint64, ctypes.c_uint64, ctypes.c_uint64]
        self._verify.restype = ctypes.c_int

    def matches_status(self, proof: bytes, expected: bytes, *, now_ms: int,
                       skew_ms: int, policy_max_age_ms: int) -> bool:
        if any(type(value) is not bytes or not 0 < len(value) <= MAX_DOCUMENT
               for value in (proof, expected)):
            return False
        if any(type(value) is not int or not 0 <= value <= MAX_SAFE
               for value in (now_ms, skew_ms, policy_max_age_ms)):
            return False
        # Copies remain alive for the entire synchronous native call. JSON is
        # passed unchanged so Rust rejects duplicate fields instead of losing them.
        proof_buffer = ctypes.create_string_buffer(proof)
        expected_buffer = ctypes.create_string_buffer(expected)
        try:
            return self._verify(proof_buffer, len(proof), expected_buffer, len(expected),
                                now_ms, skew_ms, policy_max_age_ms) == 1
        except (OSError, ValueError, ctypes.ArgumentError):
            return False


class EpochManifestVerifier:
    """Authenticates a snapshot and manifest; does not select current history.

    The expected owner key, object, epoch and revision must come from trusted
    state. An old correctly signed manifest can match. Check, settlement and
    independent rollback protection remain the consumer's responsibility.
    """

    def __init__(self):
        self._library = ctypes.CDLL(LIBRARY)
        self._verify = self._library.sociacl_verify_epoch_manifest
        self._verify.argtypes = [ctypes.c_void_p, ctypes.c_size_t,
                                ctypes.c_void_p, ctypes.c_size_t]
        self._verify.restype = ctypes.c_int

    def matches_manifest(self, document: bytes, expected: bytes) -> bool:
        if any(type(value) is not bytes or not 0 < len(value) <= MAX_MANIFEST_DOCUMENT
               for value in (document, expected)):
            return False
        document_buffer = ctypes.create_string_buffer(document)
        expected_buffer = ctypes.create_string_buffer(expected)
        try:
            return self._verify(document_buffer, len(document),
                                expected_buffer, len(expected)) == 1
        except (OSError, ValueError, ctypes.ArgumentError):
            return False


class SettledEpochVerifier:
    """Matches a proposed settled read key against protected complete history.

    The history, owner-key bindings, current ACL, clock, first-seen times, anchor
    and floor must all come from the trusted source. Never pass a client body
    directly. A match is not Check or permission to deliver reader wraps.
    """
    def __init__(self):
        self._library = ctypes.CDLL(LIBRARY)
        self._verify = self._library.sociacl_match_settled_epoch
        self._verify.argtypes = [ctypes.c_void_p, ctypes.c_size_t]
        self._verify.restype = ctypes.c_int

    def matches_settled(self, history: bytes) -> bool:
        if type(history) is not bytes or not 0 < len(history) <= MAX_EPOCH_HISTORY:
            return False
        buffer = ctypes.create_string_buffer(history)
        try:
            return self._verify(buffer, len(history)) == 1
        except (OSError, ValueError, ctypes.ArgumentError):
            return False
