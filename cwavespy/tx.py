import inspect
import sys
import base64
import weakref

import six

from ._cext import ffi, lib
from .signature import Signature

_g_weakrefs = weakref.WeakKeyDictionary()


class TXError(Exception):
    pass


def _tx_add_buf(tx, dtype, val):
    buf = ffi.new(dtype, val)
    if not _g_weakrefs.get(tx, None):
        _g_weakrefs[tx] = []
    _g_weakrefs[tx].append(buf)
    return buf


def _add_strbuf(tx, val):
    return _tx_add_buf(tx, "char[]", val)


def _to_camel_case(val):
    return ''.join([s if i == 0 else s.title() for i, s in enumerate(val.split('_'))])


def _field_name_from_camel_case(s):
    prev = 0
    ss = []
    for i, c in enumerate(s):
        if c.istitle():
            ss.append(s[prev].lower() + s[prev+1:i])
            prev = i
    if len(s) != 0:
        ss.append(s[prev].lower() + s[prev+1:len(s)])
    return '_'.join(ss)


class TransactionField(object):
    def __init__(self, name, json_key=None):
        self.name = name
        self.json_key = json_key

    def default(self):
        return None

    def validate(self, val):
        return False

    def to_dict(self, val):
        return val

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

    def to_json(self, val):
        return _to_camel_case(self.name), val

    def from_json(self, val):
        return val


def _check_uint(val, bits):
    return isinstance(val, int) and 0 <= val < (1 << bits)


class OptionField(TransactionField):
    def __init__(self, field, name=None):
        if not isinstance(field, TransactionField):
            raise TypeError("Expected type TransactionField, got %s" % type(field).__name__)
        super(OptionField, self).__init__(name or field.name)
        self.field = field

    def default(self):
        return None

    def validate(self, val):
        if val is None:
            return True
        return self.field.validate(val)

    def to_dict(self, val):
        if val is not None:
            return self.field.to_dict(val)

    def from_dict(self, val):
        if val is not None:
            return self.field.from_dict(val)

    def serialize(self, tx, val):
        if val is None:
            return self.field.null()
        return self.field.serialize(tx, val)

    def deserialize(self, val):
        if self.field.is_null(val):
            return None
        return self.field.deserialize(val)

    def to_json(self, val):
        k = _to_camel_case(self.name)
        if val:
            return k, self.field.to_json(val)[1]
        else:
            return k, None

    def from_json(self, val):
        if val:
            return self.field.from_json(val)


class FieldBase(object):
    fields = []
    struct = None
    cstruct = None

    def __init__(self, **kwargs):
        _fields_map = {field.name: field for field in self.fields}
        super(FieldBase, self).__setattr__('_fields_map', _fields_map)
        for field in self.fields:
            if field.name in kwargs:
                fval = kwargs[field.name]
                if not field.validate(fval):
                    raise ValueError("Invalid value for '%s' field" % field.name)
                if isinstance(fval, dict):
                    fval = field.from_dict(fval)
            else:
                fval = field.default()
            super(FieldBase, self).__setattr__(field.name, fval)

    def to_cstruct(self):
        if not self.cstruct:
            raise TXError("Can't serialize %s cstruct isn't defined" % type(self).__name__)
        cs = ffi.new("%s*" % self.cstruct)
        for field in self.fields:
            fval = getattr(self, field.name)
            fval_raw = field.serialize(cs, fval)
            setattr(cs, field.name, fval_raw)
        return cs

    def to_dict(self):
        data = {}
        for field in self.fields:
            fval = getattr(self, field.name, None)
            data[field.name] = field.to_dict(fval)
        return data

    def serialize_value(self, tx):
        raw = {}
        for field in self.fields:
            fval_raw = field.serialize(tx, getattr(self, field.name, None))
            raw[field.name] = fval_raw
        return raw

    def to_json(self):
        data = {}
        for field in self.fields:
            k, jv = field.to_json(getattr(self, field.name, None))
            if field.json_key:
                k = field.json_key
            data[k] = jv
        return data

    @classmethod
    def from_json(cls, val):
        data = {}
        for field in cls.fields:
            if field.json_key:
                k = field.json_key
            else:
                k = _to_camel_case(field.name)
            data[k] = field.from_json(val.get(k, None))
        return cls(**data)

    def __repr__(self):
        f_s = ','.join(["%s=%r" % (field.name, getattr(self, field.name, None))
                        for field in self.fields])
        return "%s(%s)" % (type(self).__name__, f_s)


class StructField(TransactionField):
    fields = []
    ctype = None
    pytype = None

    @property
    def _pytype_valid(self):
        return self.pytype and issubclass(self.pytype, FieldBase)

    def _is_pytype(self, val):
        return self._pytype_valid and isinstance(val, self.pytype)

    @classmethod
    def create_field_class(cls, name):
        pytype = type(name, (FieldBase,), {
            'fields': cls.fields,
            'struct': cls
        })
        if cls.pytype is not None:
            raise Exception("Python class is already defined for %s" % cls.__name__)
        cls.pytype = pytype
        return pytype

    def __init__(self, name, **kwargs):
        super(StructField, self).__init__(name, **kwargs)

    def default(self):
        return {field.name: field.default() for field in self.fields}

    def validate(self, val):
        if self._is_pytype(val):
            return True
        for field in self.fields:
            if not field.validate(val.get(field.name)):
                return False
        return True

    def serialize(self, tx, val):
        if self._is_pytype(val):
            return val.serialize_value(tx)
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
        if self._pytype_valid:
            return self.pytype(**data)
        return data

    def from_dict(self, val):
        if self._pytype_valid:
            return self.pytype(**val)
        else:
            return val

    def to_dict(self, val):
        if self._is_pytype(val):
            return val.to_dict()
        data = {}
        for field in self.fields:
            fval = getattr(self, field.name, None)
            data[field.name] = field.to_dict(fval)
        return data

    def to_json(self, val):
        f_key = _to_camel_case(self.name)
        if self._is_pytype(val):
            return f_key, val.to_json()
        data = {}
        for field in self.fields:
            k, jv = field.to_json(val.get(field.name, None))
            if field.json_key:
                k = field.json_key
            data[k] = jv
        return f_key, data

    def from_json(self, val):
        data = {}
        for field in self.fields:
            if field.json_key:
                k = field.json_key
            else:
                k = _to_camel_case(field.name)
            data[k] = field.from_json(val.get(k, None))
        if self._pytype_valid:
            return self.pytype(**data)
        return data


class ArrayField(TransactionField):
    def __init__(self, dtype, name, **kwargs):
        super(ArrayField, self).__init__(name, **kwargs)
        self.dtype = dtype

    def default(self):
        return list()

    def validate(self, val):
        for v in val:
            if not self.dtype.validate(v):
                return False
        return True

    def from_dict(self, val):
        return [self.dtype.from_dict(v) for v in val]

    def serialize(self, tx, val):
        data = []
        for v in val:
            data.append(self.dtype.serialize(tx, v))
        array = _tx_add_buf(tx, "%s[%d]" % (self.dtype.ctype, len(data)), data)
        elem_sz = ffi.sizeof(self.dtype.ctype)
        return {
            'array': ffi.cast("char*", array),
            'len': len(data),
            'capacity': len(data)*elem_sz,
            'elem_sz': elem_sz,
            'elem_destructor': ffi.NULL
        }

    def deserialize(self, val):
        data = []
        array = ffi.cast("%s[%d]" % (self.dtype.ctype, val.len), val.array)
        for i in range(val.len):
            fval = self.dtype.deserialize(array[i])
            data.append(fval)
        return data

    def to_json(self, val):
        return _to_camel_case(self.name), [self.dtype.to_json(v)[1] for v in val]

    def from_json(self, val):
        return [self.dtype.from_json(v) for v in val]


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

    def from_json(self, val):
        prefix = 'base64:'
        if val.startswith(prefix):
            return val[len(prefix):]
        return val


class Base58Field(TransactionField):
    ctype = 'tx_encoded_string_t'

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


class SignatureField(Base58Field):
    def __init__(self, name='signature'):
        super(SignatureField, self).__init__(64, name)


class ProofField(Base58Field):
    def __init__(self, name='proof'):
        super(ProofField, self).__init__(None, name)


class BoolField(TransactionField):
    def __init__(self, name):
        super(BoolField, self).__init__(name)

    def default(self):
        return False

    def validate(self, val):
        return isinstance(val, bool)

    def serialize(self, tx, val):
        return 1 if val else 0

    def deserialize(self, val):
        return False if val == 0 else True


class IntegerField(TransactionField):
    def __init__(self, name, width, **kwargs):
        super(IntegerField, self).__init__(name, **kwargs)
        self.width = width

    def default(self):
        return 0

    def validate(self, val):
        return _check_uint(val, self.width)

    def from_json(self, val):
        return int(val)


class ByteField(IntegerField):
    def __init__(self, name):
        super(ByteField, self).__init__(name, 8)


class ShortField(IntegerField):
    def __init__(self, name):
        super(ShortField, self).__init__(name, 16)


class IntField(IntegerField):
    def __init__(self, name):
        super(IntField, self).__init__(name, 32)


class LongField(IntegerField):
    def __init__(self, name):
        super(LongField, self).__init__(name, 64)

    def to_json(self, val):
        val_ = str(val) if val >= (1 << 32) else val
        return _to_camel_case(self.name), val_


class StringField(TransactionField):
    def default(self):
        return ''

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

    def from_json(self, val):
        prefix, chain_id, alias = val.split(':')
        return Alias(chain_id=ord(chain_id), alias=alias)


Alias = AliasField.create_field_class('Alias')


class RecipientField(TransactionField):
    def __init__(self, name='recipient'):
        super(RecipientField, self).__init__(name)
        self.address_field = Base58Field(width=26, name='address')
        self.alias_field = AliasField()

    def validate(self, val):
        if isinstance(val, six.string_types):
            return True
        elif isinstance(val, Alias):
            return True
        elif isinstance(val, dict):
            if val.get('is_alias', False):
                return self.alias_field.validate(val['data']['alias'])
            else:
                return self.address_field.validate(val['data']['address'])
        return False

    def from_dict(self, val):
        if val.get('is_alias', False):
            return self.alias_field.from_dict(val['data']['alias'])
        else:
            return self.address_field.from_dict(val['data']['address'])

    def deserialize(self, val):
        if val.is_alias:
            return self.alias_field.deserialize(val.data.alias)
        else:
            return self.address_field.deserialize(val.data.address)

    def serialize(self, tx, val):
        if isinstance(val, six.string_types):
            return {
                'is_alias': False,
                'data': {
                    'address': self.address_field.serialize(tx, val)
                }
            }
        else:
            return {
                'is_alias': True,
                'data': {
                    'alias': self.alias_field.serialize(tx, val)
                }
            }

    def to_json(self, val):
        if isinstance(val, six.string_types):
            jv = val
        else:
            jv = 'alias:%s:%s' % (chr(val.chain_id), val.alias)
        return _to_camel_case(self.name), jv

    def from_json(self, val):
        if val.startswith('alias'):
            return self.alias_field.from_json(val)
        else:
            return self.address_field.from_json(val)


class TransferField(StructField):
    ctype = 'tx_transfer_t'
    fields = (
        RecipientField(),
        AmountField()
    )

    def __init__(self, name='transfer'):
        super(TransferField, self).__init__(name)


Transfer = TransferField.create_field_class('Transfer')


class PaymentField(StructField):
    ctype = 'tx_payment_t'
    fields = (
        AmountField(),
        OptionField(AssetIdField(), name='asset_id')
    )

    def __init__(self, name='payment', **kwargs):
        super(PaymentField, self).__init__(name, **kwargs)


Payment = PaymentField.create_field_class('Payment')


class OrderTypeField(TransactionField):
    def __init__(self, name='order_type'):
        super(OrderTypeField, self).__init__(name=name)

    def validate(self, val):
        return val in ['sell', 'buy']

    def serialize(self, tx, val):
        return 1 if val == 'sell' else 0

    def deserialize(self, val):
        return 'sell' if val == 1 else 'buy'


class AssetPairField(StructField):
    fields = (
        OptionField(AssetIdField(), name='amount_asset'),
        OptionField(AssetIdField(), name='price_asset')
    )


AssetPair = AssetPairField.create_field_class('AssetPair')


class OrderField(StructField):
    fields = (
        SenderPublicKeyField(),
        SenderPublicKeyField(name='matcher_public_key'),
        ByteField(name='version'),
        OrderTypeField(),
        AssetPairField(name='asset_pair'),
        LongField(name='price'),
        LongField(name='amount'),
        TimestampField(),
        LongField(name='expiration'),
        LongField(name='matcher_fee')
    )

    def __init__(self, name, **kwargs):
        super(OrderField, self).__init__(name=name, **kwargs)
        self._proofs_field = ArrayField(ProofField(), 'proofs')
        self._sig_field = SignatureField()

    def _add_proofs_from_dict(self, val, data):
        if val.version == 1:
            sig = data.get('signature', None)
            if sig:
                val.add_proof_str(sig)
        elif val.version == 2:
            proofs = data.get('proofs', list())
            for p in proofs:
                val.add_proof_str(p)

    def from_json(self, val):
        ret = super(OrderField, self).from_json(val)
        self._add_proofs_from_dict(ret, val)
        return ret

    def from_dict(self, val):
        ret = super(OrderField, self).from_dict(val)
        self._add_proofs_from_dict(ret, val)
        return ret

    def deserialize(self, val):
        ret = super(OrderField, self).deserialize(val)
        if val.version == 1:
            ret.signature = self._sig_field.deserialize(val.signature)
        elif val.version == 2:
            ps = self._proofs_field.deserialize(val.proofs)
            for p in ps:
                ret.add_proof_str(p)
        return ret


class Order(FieldBase):
    fields = OrderField.fields
    cstruct = 'tx_order_t'

    def __init__(self, **kwargs):
        super(Order, self).__init__(**kwargs)
        self._proofs_field = ArrayField(ProofField(), 'proofs')
        self._sig_field = SignatureField()
        self._proofs = []

    @property
    def proofs(self):
        return self._proofs

    def add_proof_str(self, s):
        self._proofs.append(Signature(s))

    def add_proof(self, pk, i=None):
        cs = self.to_cstruct()
        cs_bytes_size = lib.waves_order_bytes_size(cs)
        cs_bytes = bytes(cs_bytes_size)
        ret = lib.waves_order_to_bytes(cs_bytes, cs)
        proof = pk.sign(cs_bytes)
        if i is None:
            self._proofs.insert(0, proof)
        else:
            self._proofs.append(proof)

    def _add_proofs_to_dict(self, data):
        if self.version == 1:
            if len(self._proofs) >= 1:
                data['signature'] = self.proofs[0].b58_str
        else:
            data['proofs'] = [p.b58_str for p in self._proofs]

    def to_json(self):
        data = super(Order, self).to_json()
        self._add_proofs_to_dict(data)
        return data

    def to_dict(self):
        data = super(Order, self).to_dict()
        self._add_proofs_to_dict(data)
        return data

    def serialize_value(self, tx):
        raw = super(Order, self).serialize_value(tx)
        if self.version == 1:
            if len(self._proofs) >= 1:
                raw['signature'] = self._sig_field.serialize(tx, self._proofs[0].b58_str)
        elif self.version == 2:
            ps = [p.b58_str for p in self._proofs]
            raw['proofs'] = self._proofs_field.serialize(tx, ps)
        return raw


OrderField.pytype = Order


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

    def to_json(self, val):
        if isinstance(val, bool):
            dt = 'boolean'
        elif isinstance(val, int):
            dt = 'integer'
            val = str(val)
        elif isinstance(val, str):
            dt = 'string'
        elif isinstance(val, bytes):
            dt = 'binary'
            val = 'base64:' + base64.b64encode(val).decode()
        else:
            dt = ''
        return '', {'type': dt, 'value': val}


class DataKeyValueField(StructField):
    ctype = 'tx_data_entry_t'
    fields = (
        StringField(name='key'),
        DataField(name='value')
    )

    def to_json(self, val):
        dk, jv = self.fields[1].to_json(val['value'])
        dk, djv = self.fields[0].to_json(val['key'])
        jv[dk] = djv
        return _to_camel_case(self.name), jv


class FuncArgField(DataField):
    ctype = 'tx_func_arg_t'

    def __init__(self, name='func_arg'):
        super(FuncArgField, self).__init__(name)

    def serialize(self, tx, val):
        if isinstance(val, bool):
            if val:
                return {'arg_type': 6, 'types': {'boolean': val}}
            else:
                return {'arg_type': 7, 'types': {'boolean': val}}
        elif isinstance(val, int):
            return {'arg_type': 0, 'types': {'integer': val}}
        elif isinstance(val, str):
            val_ = self.string_field.serialize(tx, val)
            return {'arg_type': 2, 'types': {'string': val_}}
        elif isinstance(val, bytes):
            value_bytes = bytes(len(val)*2)
            ret = lib.base64_encode(value_bytes, val, len(val))
            val_ = {
                'encoded_data': _add_strbuf(tx, value_bytes[0:ret]),
                'decoded_data': _add_strbuf(tx, val),
                'encoded_len': ret,
                'decoded_len': len(val)
            }
            return {'arg_type': 1, 'types': {'binary': val_}}

    def deserialize(self, val):
        if val.arg_type == 0:
            return int(val.types.integer)
        elif val.arg_type == 1:
            return ffi.string(val.types.binary.decoded_data)
        elif val.arg_type == 2:
            return ffi.string(val.types.string.data).decode()
        elif val.arg_type == 6:
            return True
        elif val.arg_type == 7:
            return False

    def from_json(self, val):
        return val['value']


class FuncCallField(StructField):
    fields = (
        StringField('function'),
        ArrayField(dtype=FuncArgField(), name='args')
    )

    def __init__(self, name='call'):
        super(FuncCallField, self).__init__(name=name)

    def null(self):
        return {'valid': False}

    def is_null(self, val):
        return not val.valid

    def serialize(self, tx, val):
        if self._is_pytype(val):
            data = val.serialize_value(tx)
        else:
            data = super(FuncCallField, self).serialize(tx, val)
        data['valid'] = True
        return data


FuncCall = FuncCallField.create_field_class('FuncCall')


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

    def from_json(self, val):
        prefix = 'base64:'
        if val.startswith(prefix):
            return val[len(prefix):]
        return val


class DeserializeError(Exception):
    pass


class Transaction(FieldBase):
    tx_type = 0
    tx_version = 0
    fields = []
    tx_name = None
    _fields_map = {}

    def __init__(self, **kwargs):
        super(Transaction, self).__init__(**kwargs)
        self._proofs = []

    def __setattr__(self, key, value):
        field = self._fields_map.get(key, None)
        if field and not field.validate(value):
            raise ValueError("Invalid value for field %s" % key)
        super(Transaction, self).__setattr__(key, value)

    @property
    def proofs(self):
        return self._proofs

    def add_proof(self, pk, i=None):
        tx_bytes = self.serialize()
        proof = pk.sign(tx_bytes)
        if i is None:
            self._proofs.insert(0, proof)
        else:
            self._proofs.append(proof)

    def to_dict(self):
        id_attr = getattr(self, 'id', None)
        data = {
            'id': self.get_id() if not id_attr else id_attr,
            'version': self.tx_version
        }
        for field in self.fields:
            fval = getattr(self, field.name)
            data[field.name] = field.to_dict(fval)
        return data

    @staticmethod
    def from_dict(data):
        tx_type = data.get('type')
        if tx_type is None:
            raise ValueError("Transaction type is not defined")
        tx_cls = _tx_types[tx_type]
        tx = tx_cls()
        tx.id = data.get('id', None)
        tx.tx_version = data.get('version', tx_cls.tx_version)
        for field in tx_cls.fields:
            fval = data.get(field.name)
            if not field.validate(fval):
                raise ValueError("Invalid value for field %s" % field.name)
            setattr(tx, field.name, field.from_dict(fval))
        return tx

    def _to_cstruct(self):
        tx = ffi.new("waves_tx_t*")
        tx.type = self.tx_type
        tx.version = self.tx_version
        tx_data = ffi.addressof(tx.data, self.tx_name)
        for field in self.fields:
            fval = getattr(self, field.name)
            fval_raw = field.serialize(tx, fval)
            setattr(tx_data, field.name, fval_raw)
        return tx

    def serialize(self, strip=False):
        tx = self._to_cstruct()
        buf_size = lib.waves_tx_buffer_size(tx)
        tx_buf = bytes(buf_size)
        ret = lib.waves_tx_to_bytes(tx_buf, tx)
        if tx_buf[0] == 0 and strip and self.tx_type != TransactionExchange.tx_type:
            return tx_buf[1:]
        return tx_buf

    def get_id(self):
        tx = self._to_cstruct()
        id_bytes = lib.waves_tx_id(tx)
        id_bytes = ffi.gc(id_bytes, lib.waves_tx_destroy_string)
        return ffi.string(id_bytes.data).decode()

    @staticmethod
    def deserialize(buf):
        tx_type = int(buf[0])
        if tx_type == 0:
            tx_type = int(buf[1])
        tx_cls = _tx_types.get(tx_type)
        if tx_cls is None:
            raise DeserializeError("No such transaction type: %d" % tx_type)
        tx = tx_cls()
        tx_bytes = lib.waves_tx_load(buf)

        if tx_bytes == ffi.NULL:
            raise DeserializeError("Can't deserialize '%s' transaction" % tx_cls.tx_name)
        tx_bytes = ffi.gc(tx_bytes, lib.waves_tx_destroy)
        tx.tx_version = tx_bytes.version
        tx_data = ffi.addressof(tx_bytes.data, tx_cls.tx_name)
        for field in tx_cls.fields:
            fval_raw = getattr(tx_data, field.name)
            fval = field.deserialize(fval_raw)
            setattr(tx, field.name, fval)
        return tx

    def to_json(self):
        data = {
            'type': self.tx_type,
            'id': self.get_id(),
            'version': self.tx_version
        }
        for field in self.fields:
            if not hasattr(self, field.name):
                continue
            fval = getattr(self, field.name)
            k, jv = field.to_json(fval)
            if field.json_key:
                k = field.json_key
            data[k] = jv
        data['proofs'] = [p.b58_str for p in self._proofs]
        return data

    @staticmethod
    def from_json(jdata):
        tx_type = jdata['type']
        tx_cls = _tx_types.get(tx_type)
        if tx_cls is None:
            raise DeserializeError("No such transaction type: %d" % tx_type)
        tx = tx_cls()
        tx.id = jdata.get('id', None)
        tx.tx_version = jdata.get('version', tx_cls.tx_version)
        if isinstance(tx, TransactionAlias):
            chain_id = jdata['chainId']
            if isinstance(chain_id, str):
                try:
                    chain_id = chr(int(chain_id))
                except ValueError:
                    pass
            elif isinstance(chain_id, int):
                chain_id = chr(chain_id)
            jdata['alias'] = 'alias:%s:%s' % (chain_id, jdata['alias'])
        for field in tx.fields:
            fname = field.json_key if field.json_key else field.name
            jk = _to_camel_case(fname)
            if isinstance(field, OptionField) and jk not in jdata:
                setattr(tx, field.name, None)
            else:
                jv = jdata[jk]
                fval = field.from_json(jv)
                if not field.validate(fval):
                    raise DeserializeError("Can't load transaction (type='%d') field '%s' from json"
                                           % (tx_type, field.name))
                setattr(tx, field.name, fval)
        tx._proofs = [Signature(p) for p in jdata['proofs']]
        return tx


class TransactionIssue(Transaction):
    tx_type = 3
    tx_version = 2
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
    tx_version = 2
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
    tx_version = 2
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
    tx_version = 2
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
    tx_type = 7
    tx_name = 'exchange'
    tx_version = 2
    fields = (
        OrderField(name='order1'),
        OrderField(name='order2'),
        LongField(name='price'),
        AmountField(),
        FeeField(name='buy_matcher_fee'),
        FeeField(name='sell_matcher_fee'),
        FeeField(),
        TimestampField()
    )


class TransactionLease(Transaction):
    tx_type = 8
    tx_version = 2
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
    tx_version = 2
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
    tx_version = 2
    tx_name = 'alias'
    fields = [
        SenderPublicKeyField(),
        AliasField(),
        FeeField(),
        TimestampField()
    ]

    def to_json(self):
        data = super(TransactionAlias, self).to_json()
        data['alias'] = self.alias.alias
        data['chainId'] = self.alias.chain_id
        return data


class TransactionMassTransfer(Transaction):
    tx_type = 11
    tx_version = 1
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
    tx_version = 1
    tx_name = 'data'
    fields = (
        SenderPublicKeyField(),
        DataArrayField(),
        FeeField(),
        TimestampField()
    )


class TransactionSetScript(Transaction):
    tx_type = 13
    tx_version = 1
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
    tx_version = 1
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
    tx_version = 1
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
    tx_type = 16
    tx_version = 1
    tx_name = 'invoke_script'
    fields = (
        ChainIdField(),
        SenderPublicKeyField(),
        RecipientField(name='d_app'),
        OptionField(FuncCallField(), name='call'),
        ArrayField(dtype=PaymentField(), name='payments', json_key='payment'),
        FeeField(),
        OptionField(AssetIdField(), name='fee_asset_id'),
        TimestampField()
    )


def _get_all_tx_types():
    members = inspect.getmembers(sys.modules[__name__], inspect.isclass)
    return {m.tx_type: m for k, m in members if issubclass(m, Transaction) and k != 'Transaction'}


_tx_types = _get_all_tx_types()
