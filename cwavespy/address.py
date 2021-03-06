import six

from ._cext import ffi, lib
from .base import _Base58BytesError, _Base58Bytes


class AddressError(_Base58BytesError):
    def __init__(self, message, _bytes=None, b58=None):
        super(AddressError, self).__init__(message, bytes=_bytes, b58=b58)


class Address(_Base58Bytes):
    value_name = 'address'
    error_cls = AddressError
    bytes_len = 26
    b58_len = 36

    def __init__(self, value):
        super(Address, self).__init__(value)

    @classmethod
    def from_public_key(cls, pk, network):
        address_bytes = bytes(cls.bytes_len)
        lib.waves_public_key_to_address(pk.bytes, network, address_bytes)
        return cls(address_bytes)
