import six

from _cext import lib
from .base import _Base58BytesError, _Base58Bytes
from .public_key import PublicKey
from .signature import Signature


class PrivateKeyError(_Base58BytesError):
    def __init__(self, message, _bytes=None, b58=None):
        super(PrivateKeyError, self).__init__(message, bytes=_bytes, b58=b58)


class PrivateKey(_Base58Bytes):
    value_name = 'private key'
    error_cls = PrivateKeyError
    bytes_len = 32
    b58_len = 45

    def __init__(self, value):
        super(PrivateKey, self).__init__(value)

    def gen_public_key(self):
        public_key_bytes = bytes(PublicKey.bytes_len)
        lib.waves_gen_public_key(public_key_bytes, self._value_bytes)
        return PublicKey(public_key_bytes)

    def sign(self, msg, _random=None):
        if isinstance(msg, six.string_types):
            msg = msg.encode()
        sig_bytes = bytes(Signature.bytes_len)
        if _random:
            if isinstance(_random, six.string_types):
                _random = _random.encode()
            ret = lib.waves_sign_message_custom_random(self._value_bytes, msg, len(msg), sig_bytes, _random)
        else:
            ret = lib.waves_sign_message(self._value_bytes, msg, len(msg), sig_bytes)
        if not ret:
            return None
        return Signature(sig_bytes)
