import six

from _cext import ffi, lib


class Base58DecodeError(Exception):
    def __init__(self, b58str, pos):
        message = "Base58 parse error at %d: " % pos
        if pos < 10:
            message += b58str[:10]
        else:
            message += b58str[:3] + "..." + b58str[pos:pos+3]
        super(Base58DecodeError, self).__init__(message)
        self.b58str = b58str
        self.pos = pos


class _Base58BytesError(Exception):
    def __init__(self, message, bytes=None, b58=None):
        super(_Base58BytesError, self).__init__(message)
        self._bytes = bytes
        self._b58 = b58


class _Base58Bytes(object):
    value_name = 'base'
    error_cls = _Base58BytesError
    bytes_len = 0
    b58_len = 0

    def __init__(self, value):
        if isinstance(value, bytes):
            if len(value) != self.bytes_len:
                raise self.error_cls("%s should be exactly %d bytes" % (self.value_name, self.bytes_len),
                                     bytes=value)
            self._value_bytes = value
            buf = ffi.new("char[]", self.b58_len)
            lib.base58_encode(buf, self._value_bytes, len(self._value_bytes))
            self._value_b58 = ffi.string(buf).decode()
        elif isinstance(value, six.string_types):
            self._value_bytes = bytes(self.bytes_len)
            self._value_b58 = value
            ret = lib.base58_decode(self._value_bytes, self._value_b58.encode())
            if ret < 0:
                raise Base58DecodeError(value, -ret+1)
        else:
            raise TypeError("address should be 'bytes' or string type")

    @property
    def bytes(self):
        return self._value_bytes

    @property
    def b58_str(self):
        return self._value_b58
