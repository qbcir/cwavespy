import six

from ._cext import lib

from .base import _Base58BytesError, _Base58Bytes
from .address import Address
from .signature import Signature


class PublicKeyError(_Base58BytesError):
    def __init__(self, message, _bytes=None, b58=None):
        super(PublicKeyError, self).__init__(message, bytes=_bytes, b58=b58)


class PublicKey(_Base58Bytes):
    value_name = 'public_key'
    error_cls = PublicKeyError
    bytes_len = 32
    b58_len = 45

    def __init__(self, value):
        super(PublicKey, self).__init__(value)

    def verify_signature(self, msg, sig):
        if isinstance(msg, six.string_types):
            msg = msg.encode()
        if isinstance(sig, six.string_types):
            sig = Signature(sig).bytes
        return lib.waves_verify_message(self._value_bytes, msg, len(msg), sig)

    def to_address(self, network):
        address_bytes = bytes(Address.bytes_len)
        lib.waves_public_key_to_address(self._value_bytes, ord(network), address_bytes)
        return Address(address_bytes)

    @classmethod
    def from_private_key(cls, pk):
        public_key_bytes = bytes(cls.bytes_len)
        lib.waves_gen_public_key(public_key_bytes, pk.bytes)
        return cls(public_key_bytes)
