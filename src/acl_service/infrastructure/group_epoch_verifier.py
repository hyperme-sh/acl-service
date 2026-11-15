"""Bounded native group-key adapters; protected callers supply all authority."""
import ctypes

from acl_service.infrastructure.epoch_verifier import LIBRARY, MAX_MANIFEST_DOCUMENT

MAX_GROUP_HISTORY = 4 * 1024 * 1024


class GroupEpochVerifier:
    """Authenticate group history or select its current settled key.

    A match is not permission to read media. The protected source supplies
    complete history, enrolled owner/member keys, the current cohort, policy,
    clock, first-seen times and independent rollback floors. Request bodies
    must never supply that trusted context directly.
    """
    def __init__(self):
        self._library = ctypes.CDLL(LIBRARY)
        self._manifest = self._library.sociacl_verify_group_epoch_manifest
        self._manifest.argtypes = [ctypes.c_void_p, ctypes.c_size_t,
                                   ctypes.c_void_p, ctypes.c_size_t]
        self._manifest.restype = ctypes.c_int
        self._history = self._library.sociacl_verify_group_epoch_history
        self._settled = self._library.sociacl_match_settled_group_epoch
        for function in (self._history, self._settled):
            function.argtypes = [ctypes.c_void_p, ctypes.c_size_t]
            function.restype = ctypes.c_int

    def matches_manifest(self, document: bytes, expected: bytes) -> bool:
        if any(type(value) is not bytes or not 0 < len(value) <= MAX_MANIFEST_DOCUMENT
               for value in (document, expected)):
            return False
        document_buffer = ctypes.create_string_buffer(document)
        expected_buffer = ctypes.create_string_buffer(expected)
        try:
            return self._manifest(document_buffer, len(document),
                                  expected_buffer, len(expected)) == 1
        except (OSError, ValueError, ctypes.ArgumentError):
            return False

    @staticmethod
    def _call(function, history: bytes) -> bool:
        if type(history) is not bytes or not 0 < len(history) <= MAX_GROUP_HISTORY:
            return False
        # Preserve original JSON so duplicate fields reach the strict parser.
        buffer = ctypes.create_string_buffer(history)
        try:
            return function(buffer, len(history)) == 1
        except (OSError, ValueError, ctypes.ArgumentError):
            return False

    def verifies_history(self, history: bytes) -> bool:
        """Signature admission only; pending history may authenticate."""
        return self._call(self._history, history)

    def matches_settled(self, history: bytes) -> bool:
        """Match the latest settled key against the current protected cohort."""
        return self._call(self._settled, history)
