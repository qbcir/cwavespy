import inspect
import sys
import binascii
import base64
import weakref

import six

from ._cext import ffi, lib

_g_weakrefs = weakref.WeakKeyDictionary()


def _tx_add_buf(tx, dtype, val):
    buf = ffi.new(dtype, val)
    if not _g_weakrefs.get(tx, None):
        _g_weakrefs[tx] = []
    _g_weakrefs[tx].append(buf)
    return buf


def _add_strbuf(tx, val):
    return _tx_add_buf(tx, "char[]", val)


class TransactionField(object):
    def __init__(self, name):
        self.name = name

    def validate(self, val):
        return False

    def from_dict(self, val):
        return val

    def serialize(self, tx, val):
        return val

    def deserialize(self, val):
        return val

    def null(self):
        return 0

    def is_null(self, val):
        return True


def _check_uint(val, bits):
    return isinstance(val, int) and 0 <= val < (1 << bits)


class OptionField(TransactionField):
    def __init__(self, field, name=None):
        if not isinstance(field, TransactionField):
            raise TypeError("Expected type TransactionField, got %s" % type(field).__name__)
        super(OptionField, self).__init__(name or field.name)
        self.field = field

    def validate(self, val):
        if val is None:
            return True
        return self.field.validate(val)

    def serialize(self, tx, val):
        if val is None:
            return self.field.null()
        return self.field.serialize(tx, val)

    def deserialize(self, val):
        if self.field.is_null(val):
            return None
        return self.field.deserialize(val)


class StructField(TransactionField):
    fields = []
    ctype = None

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
            'array': _tx_add_buf(tx, "%s[%d]" % (self.dtype.ctype, len(data)), data),
            'len': len(data)
        }

    def deserialize(self, val):
        data = []
        for i in range(val.len):
            fval = self.dtype.deserialize(val.array[i])
            data.append(fval)
        return data


class Base64Field(TransactionField):
    def __init__(self, name):
        super(Base64Field, self).__init__(name)

    def validate(self, val):
        if not isinstance(val, six.string_types):
            return False
        val_ = val.encode()
        value_bytes = bytes(len(val_))
        ret = lib.base64_decode(value_bytes, val_)
        return ret >= 0

    def serialize(self, tx, val):
        encoded_data = val.encode()
        decoded_data = bytes(len(encoded_data))
        ret = lib.base64_decode(decoded_data, encoded_data)
        if ret < 0:
            raise ValueError()
        return {
            'encoded_data': _add_strbuf(tx, encoded_data),
            'decoded_data': _add_strbuf(tx, decoded_data[0:ret]),
            'encoded_len': len(encoded_data),
            'decoded_len': ret
        }

    def deserialize(self, val):
        return ffi.string(val.encoded_data).decode()


class Base58Field(TransactionField):
    def __init__(self, width, name):
        super(Base58Field, self).__init__(name)
        self.width = width

    def validate(self, val):
        if not isinstance(val, six.string_types):
            return False
        if self.width is None:
            val_ = val.encode()
            value_bytes = bytes(len(val_))
            ret = lib.base58_decode(value_bytes, val_)
            return ret >= 0
        else:
            value_bytes = bytes(self.width)
            ret = lib.base58_decode(value_bytes, val.encode())
            return ret == self.width

    def serialize(self, tx, val):
        encoded_data = val.encode()
        if self.width is None:
            decoded_data = bytes(len(encoded_data))
            ret = lib.base58_decode(decoded_data, encoded_data)
            if ret < 0:
                raise ValueError()
            return {
                'encoded_data': _add_strbuf(tx, encoded_data),
                'decoded_data': _add_strbuf(tx, decoded_data[0:ret]),
                'encoded_len': len(encoded_data),
                'decoded_len': ret
            }
        return {
            'encoded_data': _add_strbuf(tx, encoded_data),
            'decoded_data': ffi.NULL,
            'encoded_len': len(encoded_data),
            'decoded_len': self.width
        }

    def deserialize(self, val):
        return ffi.string(val.encoded_data).decode()

    def null(self):
        return {
            'encoded_data': ffi.NULL,
            'decoded_data': ffi.NULL,
            'encoded_len': 0,
            'decoded_len': 0
        }

    def is_null(self, val):
        return val.encoded_data == ffi.NULL


class AssetIdField(Base58Field):
    def __init__(self, name='asset_id'):
        super(AssetIdField, self).__init__(32, name)


class LeaseAssetIdField(OptionField):
    def __init__(self, name='lease_asset_id'):
        super(LeaseAssetIdField, self).__init__(field=Base58Field(32, name), name=name)


class LeaseIdField(Base58Field):
    def __init__(self, name='lease_id'):
        super(LeaseIdField, self).__init__(32, name)


class SenderPublicKeyField(Base58Field):
    def __init__(self, name='sender_public_key'):
        super(SenderPublicKeyField, self).__init__(32, name)


class AttachmentField(Base58Field):
    def __init__(self, name='attachment'):
        super(AttachmentField, self).__init__(width=None, name=name)


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


class RecipientField(TransactionField):
    def __init__(self, name='recipient'):
        super(RecipientField, self).__init__(name)
        self.address_field = Base58Field(width=26, name='address')
        self.alias_field = AliasField()

    def validate(self, val):
        if isinstance(val, dict):
            if val.get('is_alias', False):
                return self.alias_field.validate(val['data']['alias'])
            else:
                return self.address_field.validate(val['data']['address'])
        return False

    def deserialize(self, val):
        if val.is_alias:
            data = {'alias': self.alias_field.deserialize(val.data.alias)}
        else:
            data = {'address': self.address_field.deserialize(val.data.address)}
        return {'is_alias': val.is_alias, 'data':data}

    def serialize(self, tx, val):
        if isinstance(val, six.string_types):
            return {
                'is_alias': False,
                'data': {
                    'address': self.address_field.serialize(tx, val)
                }
            }
        elif isinstance(val, dict):
            is_alias = val.get('is_alias', False)
            if is_alias:
                alias_data = {'alias': self.alias_field.serialize(tx, val['data']['alias'])}
            else:
                alias_data = {'address': self.address_field.serialize(tx, val['data']['address'])}
            return {
                'is_alias': is_alias,
                'data': alias_data
            }
        else:
            return {
                'is_alias': True,
                'data': {
                    'alias': self.alias_field.serialize(tx, val)
                }
            }


class TransferField(StructField):

    ctype = 'tx_transfer_t'
    fields = (
        RecipientField(),
        AmountField()
    )

    def __init__(self, name='transfer'):
        super(TransferField, self).__init__(name)


class DataField(TransactionField):
    py_types = [int, bool, bytes, str]

    def __init__(self, name):
        self.string_field = StringField(name='string')
        self.binary_field = Base64Field(name='binary')
        super(DataField, self).__init__(name)

    def validate(self, val):
        if not any(isinstance(val, t) for t in self.py_types):
            return False
        return True

    def serialize(self, tx, val):
        if isinstance(val, int):
            return {'data_type': 0, 'types': {'integer': val}}
        elif isinstance(val, bool):
            return {'data_type': 1, 'types': {'boolean': val}}
        elif isinstance(val, str):
            val_ = self.string_field.serialize(tx, val)
            return {'data_type': 3, 'types': {'string': val_}}
        elif isinstance(val, bytes):
            value_bytes = bytes(len(val)*2)
            ret = lib.base64_encode(value_bytes, val, len(val))
            val_ = {
                'encoded_data': _add_strbuf(tx, value_bytes[0:ret]),
                'decoded_data': _add_strbuf(tx, val),
                'encoded_len': ret,
                'decoded_len': len(val)
            }
            return {'data_type': 3, 'types': {'binary': val_}}

    def deserialize(self, val):
        if val.data_type == 0:
            return int(val.types.integer)
        elif val.data_type == 1:
            return bool(val.types.boolean)
        elif val.data_type == 2:
            return ffi.string(val.decoded_data)
        elif val.data_type == 3:
            return ffi.string(val.types.string.data).decode()


class DataKeyValueField(StructField):
    ctype = 'tx_data_entry_t'
    fields = (
        StringField(name='key'),
        DataField(name='value')
    )


class DataArrayField(ArrayField):
    def __init__(self, name='data'):
        super(DataArrayField, self).__init__(DataKeyValueField(name='data_entry'), name)


class ScriptField(StringField):
    def __init__(self, name="script"):
        super(ScriptField, self).__init__(name)

    def validate(self, val):
        return val is None or isinstance(val, str) or isinstance(val, bytes)

    def from_dict(self, val):
        if isinstance(val, bytes):
            return val.decode()
        return val

    def serialize(self, tx, val):
        if val is None:
            return {
                'encoded_data': ffi.NULL,
                'decoded_data': ffi.NULL,
                'encoded_len': 0,
                'decoded_len': 0
            }
        encoded_val = val.encode()
        decoded_val = base64.b64decode(val)
        return {
            'encoded_data': _add_strbuf(tx, encoded_val),
            'decoded_data': _add_strbuf(tx, decoded_val),
            'encoded_len': len(encoded_val),
            'decoded_len': len(decoded_val)
        }

    def deserialize(self, val):
        if val.encoded_len == 0:
            return None
        return ffi.string(val.encoded_data).decode()


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
            setattr(tx, field.name, field.from_dict(fval))
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
    tx_type = 4
    tx_name = 'transfer'
    fields = (
        SenderPublicKeyField(),
        OptionField(field=AssetIdField()),
        OptionField(field=AssetIdField(), name='fee_asset_id'),
        TimestampField(),
        AmountField(),
        FeeField(),
        RecipientField(),
        AttachmentField()
    )


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
    tx_type = 8
    tx_name = 'lease'
    fields = (
        LeaseAssetIdField(),
        SenderPublicKeyField(),
        RecipientField(),
        AmountField(),
        FeeField(),
        TimestampField()
    )


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
    tx_type = 11
    tx_name = 'mass_transfer'
    fields = (
        SenderPublicKeyField(),
        OptionField(AssetIdField(), name='asset_id'),
        ArrayField(dtype=TransferField(), name='transfers'),
        TimestampField(),
        FeeField(),
        AttachmentField()
    )


class TransactionData(Transaction):
    tx_type = 12
    tx_name = 'data'
    fields = (
        SenderPublicKeyField(),
        DataArrayField(),
        FeeField(),
        TimestampField()
    )


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
