import inspect
import sys
import binascii
import base64
import weakref

import six

from ._cext import ffi, lib

_g_weakrefs = weakref.WeakKeyDictionary()


def _add_strbuf(tx, val):
    buf = ffi.new("char []", val)
    if not _g_weakrefs.get(tx, None):
        _g_weakrefs[tx] = []
    _g_weakrefs[tx].append(buf)
    return buf


class TransactionField(object):
    def __init__(self, name):
        self.name = name

    def validate(self, val):
        return False

    def to_json(self, val):
        return val

    def serialize(self, tx, val):
        return val

    def deserialize(self, val):
        return val


def _check_uint(val, bits):
    return isinstance(val, int) and 0 <= val < (1 << bits)


class OptionField(TransactionField):
    def __init__(self, field, name):
        super(OptionField, self).__init__(name)
        if not isinstance(field, TransactionField):
            raise TypeError("Expected type TransactionField, got %s" % type(field).__name__)
        self.field = field

    def validate(self, val):
        if val is None:
            return True
        return self.field.validate(val)


class StructField(TransactionField):
    fields = []

    def __init__(self, name):
        super(StructField, self).__init__(name)

    def validate(self, val):
        for field in self.fields:
            if not field.validate(val.get(field.name)):
                return False
        return True

    def serialize(self, tx, val):
        raw = {}
        for field in self.fields:
            fval_raw = field.serialize(tx, val.get(field.name))
            raw[field.name] = fval_raw
        return raw

    def deserialize(self, val):
        data = {}
        for field in self.fields:
            fval_raw = field.deserialize(getattr(val, field.name))
            data[field.name] = fval_raw
        return data


class ArrayField(TransactionField):
    def __init__(self, dtype, name):
        super(ArrayField, self).__init__(name)
        self.dtype = dtype

    def validate(self, val):
        for v in val:
            if not self.dtype.validate(v):
                return False
        return True

    def serialize(self, tx, val):
        data = []
        for v in val:
            data.append(self.dtype.serialize(tx, v))
        return {
            'array': ffi.new("", data),
            'len': len(data)
        }

    def deserialize(self, val):
        data = []
        for i in range(val.len):
            fval = self.dtype.deserialze(val.array[i])
            data.append(fval)
        return data


class Base58Field(TransactionField):
    def __init__(self, width, name):
        super(Base58Field, self).__init__(name)
        self.width = width

    def validate(self, val):
        if not isinstance(val, six.string_types):
            return False
        value_bytes = bytes(self.width)
        ret = lib.base58_decode(value_bytes, val.encode())
        return ret == self.width

    def serialize(self, tx, val):
        return {
            'data': _add_strbuf(tx, val.encode()),
            'encoded_len': len(val),
            'decoded_len': self.width
        }

    def deserialize(self, val):
        return ffi.string(val.data).decode()


class AssetIdField(Base58Field):
    def __init__(self, name='asset_id'):
        super(AssetIdField, self).__init__(32, name)


class LeaseIdField(Base58Field):
    def __init__(self, name='lease_id'):
        super(LeaseIdField, self).__init__(32, name)


class SenderPublicKeyField(Base58Field):
    def __init__(self, name='sender_public_key'):
        super(SenderPublicKeyField, self).__init__(32, name)


class BoolField(TransactionField):
    def __init__(self, name):
        super(BoolField, self).__init__(name)

    def validate(self, val):
        return isinstance(val, bool)

    def serialize(self, tx, val):
        return 1 if val else 0

    def deserialize(self, val):
        return False if val == 0 else True


class ByteField(TransactionField):
    def __init__(self, name):
        super(ByteField, self).__init__(name)

    def validate(self, val):
        return _check_uint(val, 8)


class ShortField(TransactionField):
    def __init__(self, name):
        super(ShortField, self).__init__(name)

    def validate(self, val):
        return _check_uint(val, 16)


class IntField(TransactionField):
    def __init__(self, name):
        super(IntField, self).__init__(name)

    def validate(self, val):
        return _check_uint(val, 32)


class LongField(TransactionField):
    def __init__(self, name):
        super(LongField, self).__init__(name)

    def validate(self, val):
        return _check_uint(val, 64)


class StringField(TransactionField):
    def validate(self, val):
        return isinstance(val, str)

    def serialize(self, tx, val):
        val_ = val.encode()
        return {
            'data': _add_strbuf(tx, val_),
            'len': len(val_)
        }

    def deserialize(self, val):
        return ffi.string(val.data).decode()


class ChainIdField(ByteField):
    def __init__(self, name='chain_id'):
        super(ChainIdField, self).__init__(name)


class DecimalsField(ByteField):
    def __init__(self, name='decimals'):
        super(DecimalsField, self).__init__(name)


class TimestampField(LongField):
    def __init__(self, name='timestamp'):
        super(TimestampField, self).__init__(name)


class FeeField(LongField):
    def __init__(self, name='fee'):
        super(FeeField, self).__init__(name)


class QuantityField(LongField):
    def __init__(self, name='quantity'):
        super(QuantityField, self).__init__(name)


class ReissuableField(BoolField):
    def __init__(self, name='reissuable'):
        super(ReissuableField, self).__init__(name)


class AmountField(LongField):
    def __init__(self, name='amount'):
        super(AmountField, self).__init__(name)


class AliasField(StructField):
    fields = [
        ChainIdField(),
        StringField('alias')
    ]

    def __init__(self, name='alias'):
        super(AliasField, self).__init__(name)


class ScriptField(StringField):
    def __init__(self, name="script"):
        super(ScriptField, self).__init__(name)

    def validate(self, val):
        return val is None or isinstance(val, str) or isinstance(val, bytes)

    def to_json(self, val):
        if isinstance(val, bytes):
            return val.decode()
        return val

    def serialize(self, tx, val):
        if val is None:
            return {
                'data': 0,
                'encoded_len': 0,
                'decode_len': 0
            }
        val_ = base64.b64decode(val)
        return {
            'data': _add_strbuf(tx, val.encode()),
            'encoded_len': len(val),
            'decoded_len': len(val_)
        }

    def deserialize(self, val):
        if val.encoded_len == 0:
            return None
        return ffi.string(val.data).decode()


class DeserializeError(Exception):
    pass


class Transaction(object):
    tx_type = 0
    fields = []
    tx_name = None

    def to_dict(self):
        data = {}
        for field in self.fields:
            fval = getattr(self, field.name)
            data[field.name] = fval
        return data

    @staticmethod
    def from_dict(data):
        tx_type = data.get('type')
        if tx_type is None:
            raise ValueError("Transaction type is not defined")
        tx_cls = _tx_types[tx_type]
        tx = tx_cls()
        for field in tx_cls.fields:
            fval = data.get(field.name)
            if not field.validate(fval):
                raise ValueError("Invalid value for field %s" % field.name)
            setattr(tx, field.name, field.to_json(fval))
        return tx

    def serialize(self):
        tx = ffi.new("tx_bytes_t*")
        tx.type = self.tx_type
        tx_data = ffi.addressof(tx.data, self.tx_name)
        for field in self.fields:
            fval = getattr(self, field.name)
            fval_raw = field.serialize(tx, fval)
            setattr(tx_data, field.name, fval_raw)
        buf_size = lib.waves_tx_buffer_size(tx)
        tx_buf = bytes(buf_size)
        lib.waves_tx_to_bytes(tx_buf, tx)
        return tx_buf

    @staticmethod
    def deserialize(buf):
        tx_type = int(buf[0])
        tx_cls = _tx_types.get(tx_type)
        if tx_cls is None:
            raise DeserializeError("No such transaction type: %d" % tx_type)
        tx = tx_cls()
        tx_bytes = ffi.new("tx_bytes_t*")
        tx_data = ffi.addressof(tx_bytes.data, tx_cls.tx_name)
        tx_bytes.type = tx_type
        ret = lib.waves_tx_from_bytes(tx_bytes, buf)
        if ret < 0:
            raise DeserializeError("Can't deserialize '%s' transaction" % tx_cls.tx_name)
        for field in tx_cls.fields:
            fval_raw = getattr(tx_data, field.name)
            fval = field.deserialize(fval_raw)
            setattr(tx, field.name, fval)
        return tx


class TransactionIssue(Transaction):
    tx_type = 3
    tx_name = 'issue'
    fields = (
        ChainIdField(),
        SenderPublicKeyField(),
        StringField('name'),
        StringField('description'),
        QuantityField(),
        DecimalsField(),
        ReissuableField(),
        FeeField(),
        TimestampField(),
        ScriptField()
    )


class TransactionTransfer(Transaction):
    # TODO
    tx_type = 4
    tx_name = 'transfer'


class TransactionReissue(Transaction):
    tx_type = 5
    tx_name = 'reissue'
    fields = [
        ChainIdField(),
        SenderPublicKeyField(),
        AssetIdField(),
        QuantityField(),
        ReissuableField(),
        FeeField(),
        TimestampField()
    ]


class TransactionBurn(Transaction):
    tx_type = 6
    tx_name = 'burn'
    fields = (
        ChainIdField(),
        SenderPublicKeyField(),
        AssetIdField(),
        QuantityField(),
        FeeField(),
        TimestampField()
    )


class TransactionExchange(Transaction):
    # TODO
    tx_type = 7
    tx_name = 'exchange'


class TransactionLease(Transaction):
    # TODO
    tx_type = 8
    tx_name = 'lease'


class TransactionLeaseCancel(Transaction):
    tx_type = 9
    tx_name = 'lease_cancel'
    fields = (
        ChainIdField(),
        SenderPublicKeyField(),
        FeeField(),
        TimestampField(),
        LeaseIdField()
    )


class TransactionAlias(Transaction):
    tx_type = 10
    tx_name = 'alias'
    fields = [
        SenderPublicKeyField(),
        AliasField(),
        FeeField(),
        TimestampField()
    ]


class TransactionMassTransfer(Transaction):
    # TODO
    tx_type = 11
    tx_name = 'mass_transfer'


class TransactionData(Transaction):
    # TODO
    tx_type = 12
    tx_name = 'data'


class TransactionSetScript(Transaction):
    tx_type = 13
    tx_name = 'set_script'
    fields = (
        ChainIdField(),
        SenderPublicKeyField(),
        ScriptField(),
        FeeField(),
        TimestampField()
    )


class TransactionSponsorship(Transaction):
    tx_type = 14
    tx_name = 'sponsorship'
    fields = (
        SenderPublicKeyField(),
        AssetIdField(),
        FeeField(name='min_sponsored_asset_fee'),
        FeeField(),
        TimestampField()
    )


class TransactionSetAssetScript(Transaction):
    tx_type = 15
    tx_name = 'set_asset_script'
    fields = (
        ChainIdField(),
        SenderPublicKeyField(),
        AssetIdField(),
        FeeField(),
        TimestampField(),
        ScriptField()
    )


class TransactionInvokeScript(Transaction):
    # TODO
    tx_type = 16
    tx_name = 'invoke_script'


def _get_all_tx_types():
    members = inspect.getmembers(sys.modules[__name__], inspect.isclass)
    return {m.tx_type: m for k, m in members if issubclass(m, Transaction) and k != 'Transaction'}


_tx_types = _get_all_tx_types()
