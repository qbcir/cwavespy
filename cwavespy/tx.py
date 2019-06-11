import inspect
import sys
import binascii
import base64
import six

from ._cext import ffi, lib


class TransactionField(object):
    def __init__(self, name):
        self.name = name

    def validate(self, val):
        return False

    def to_json(self, val):
        return val

    def serialize(self, val):
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

    def serialize(self, val):
        value_bytes = bytes(self.width)
        lib.base58_decode(value_bytes, val.encode())
        return value_bytes

    def deserialize(self, val):
        buf = ffi.new("char[]", len(val) * 2)
        ret = lib.base58_encode(buf, val, len(val))
        return ffi.string(buf).decode()[0:ret]


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

    def serialize(self, val):
        return {'data': ffi.new("char[]", val.encode()), 'len': len(val)}


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


class ScriptField(StringField):
    def __init__(self, name="script"):
        super(ScriptField, self).__init__(name)

    def validate(self, val):
        try:
            base64.b64decode(val, validate=True)
            return True
        except binascii.Error:
            return False

    def to_json(self, val):
        return val

    def serialize(self, val):
        val_ = base64.b64decode(val)
        return {'data': ffi.new("char[]", val_), 'len': len(val_)}

    def deserialize(self, val):
        return base64.b64encode(val)


class DeserializeError(Exception):
    pass


class Transaction(object):
    tx_type = 0
    fields = []
    name = None

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
        tx_data = ffi.addressof(tx.data, self.name)
        for field in self.fields:
            fval = getattr(self, field.name)
            fval_raw = field.serialize(fval)
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
        tx_data = ffi.addressof(tx_bytes.data, tx_cls.name)
        tx_bytes.type = tx_type
        ret = lib.waves_tx_from_bytes(tx_bytes, buf)
        if ret < 0:
            raise DeserializeError("Can't deserialize '%s' transaction" % tx_cls.name)
        for field in tx_cls.fields:
            fval_raw = getattr(tx_data, field.name)
            fval = field.deserialize(fval_raw)
            setattr(tx, field.name, fval)
        return tx


class TransactionIssue(Transaction):
    # TODO
    tx_type = 3
    name = 'issue'
    fields = (
        ChainIdField(),
        SenderPublicKeyField(),
        StringField('asset_name'),
        StringField('asset_description'),
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
    name = 'transfer'


class TransactionReissue(Transaction):
    # TODO
    tx_type = 5
    name = 'reissue'


class TransactionBurn(Transaction):
    tx_type = 6
    name = 'burn'
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
    name = 'exchange'


class TransactionLease(Transaction):
    # TODO
    tx_type = 8
    name = 'lease'


class TransactionLeaseCancel(Transaction):
    tx_type = 9
    name = 'lease_cancel'
    fields = (
        ChainIdField(),
        SenderPublicKeyField(),
        FeeField(),
        TimestampField(),
        LeaseIdField()
    )


class TransactionAlias(Transaction):
    # TODO
    tx_type = 10
    name = 'alias'


class TransactionMassTransfer(Transaction):
    # TODO
    tx_type = 11
    name = 'mass_transfer'


class TransactionData(Transaction):
    # TODO
    tx_type = 12
    name = 'data'


class TransactionSetScript(Transaction):
    tx_type = 13
    name = 'set_script'
    fields = (
        ChainIdField(),
        SenderPublicKeyField(),
        ScriptField(),
        FeeField(),
        TimestampField()
    )


class TransactionSponsorship(Transaction):
    tx_type = 14
    name = 'sponsorship'
    fields = (
        SenderPublicKeyField(),
        AssetIdField(),
        FeeField(name='sponsored_asset_fee'),
        FeeField(),
        TimestampField()
    )


class TransactionSetAssetScript(Transaction):
    tx_type = 15
    name = 'set_asset_script'
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
    name = 'invoke_script'


def _get_all_tx_types():
    members = inspect.getmembers(sys.modules[__name__], inspect.isclass)
    return {m.tx_type: m for k, m in members if issubclass(m, Transaction) and k != 'Transaction'}


_tx_types = _get_all_tx_types()
