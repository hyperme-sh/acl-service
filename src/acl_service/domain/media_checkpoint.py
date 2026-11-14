"""Stable private-media checkpoint format shared by runtime and explicit setup."""
import hashlib
import json


def media_checkpoint_digest(tenant,object,revision,nonce,document):
    def encoded(value):return json.dumps(value,sort_keys=True,separators=(',',':'),allow_nan=False).encode()
    inner=hashlib.sha256(encoded(revision)+nonce+document).digest()
    return hashlib.sha256(encoded(['private-media-v1',tenant,object])+inner).digest()
