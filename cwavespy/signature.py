from .base import _Base58BytesError, _Base58Bytes


class SignatureError(_Base58BytesError):
    def __init__(self, message, _bytes=None, b58=None):
        super(SignatureError, self).__init__(message, bytes=_bytes, b58=b58)


class Signature(_Base58Bytes):
    value_name = 'signature'
    error_cls = SignatureError
    bytes_len = 64
    b58_len = 89

    def __init__(self, value):
        super(Signature, self).__init__(value)
