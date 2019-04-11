import six

from _cext import lib


def secure_hash(msg):
    if isinstance(msg, six.string_types):
        msg = msg.encode()
    hash_bytes = bytes(32)
    lib.waves_secure_hash(msg, len(msg), hash_bytes)
    return hash_bytes
