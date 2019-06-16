import six

from ._cext import ffi, lib


def base58_encode(value):
    buf = ffi.new("char[]", len(value) * 2)
    ret = lib.base58_encode(buf, value, len(value))
    return ffi.string(buf).decode()[0:ret]


def base58_decode(value):
    if isinstance(value, six.string_types):
        value = value.encode()
    buf = ffi.new("char[]", len(value))
    ret = lib.base58_decode(buf, value)
    return ffi.string(buf)[0:ret]
