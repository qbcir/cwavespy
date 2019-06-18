import base64

import pytest
import requests
import six

from cwavespy import *

from faker import Faker
from faker.providers import BaseProvider

g_faker = Faker()


class _TestRandProvider(BaseProvider):

    def random_byte(self):
        return self.random_int(min=0, max=(1 << 8) - 1)

    def random_short(self):
        return self.random_int(min=0, max=(1 << 16) - 1)

    def random_uint32(self):
        return self.random_int(min=0, max=(1 << 32) - 1)

    def random_uint64(self):
        return self.random_int(min=0, max=(1 << 64)-1)

    def tx_chain_id(self):
        return ord('M')
        #return self.random_byte()

    def tx_decimals(self):
        return self.random_byte()

    def tx_fee(self):
        return self.random_uint64()

    def tx_timestamp(self):
        return self.random_uint64()

    def tx_quantity(self):
        return self.random_uint64()

    def tx_amount(self):
        return self.random_uint64()

    def tx_public_key(self):
        seed = g_faker.sentence()
        priv_key = PrivateKey.from_seed(seed)
        pub_key = PublicKey.from_private_key(priv_key)
        return pub_key.b58_str

    def tx_address(self):
        seed = g_faker.sentence()
        priv_key = PrivateKey.from_seed(seed)
        pub_key = PublicKey.from_private_key(priv_key)
        addr = pub_key.to_address('M')
        return addr.b58_str

    def random_bytes(self, n):
        return bytes([self.random_byte() for i in range(n)])

    def random_b58(self, width):
        bs = bytes(self.random_byte() for i in range(width))
        return base58_encode(bs)

    def tx_asset_id(self):
        return self.random_b58(32)

    def tx_lease_id(self):
        return self.random_b58(32)

    def tx_attachment(self):
        rlen = g_faker.random_int(min=0, max=1024)
        return self.random_b58(rlen)

    def tx_script(self):
        s = base64.b64encode(g_faker.sentence().encode())
        return s.decode()

    def tx_recipient(self):
        is_alias = g_faker.boolean()
        if is_alias:
            return {'is_alias': is_alias, 'data': {'alias': self.tx_alias_s()}}
        else:
            return {'is_alias': is_alias, 'data': {'address': self.tx_address()}}

    def tx_reissuable(self):
        #FIXME
        return False#g_faker.boolean()

    def tx_network_alias(self):
        return g_faker.pystr(min_chars=0, max_chars=30)

    def tx_alias_s(self):
        return {
            'chain_id': self.tx_chain_id(),
            'alias': self.tx_network_alias()
        }

    def tx_payment_s(self):
        return {
            'amount': self.tx_amount(),
            'asset_id': self.tx_asset_id()
        }

    def tx_payments(self, n):
        return [self.tx_payment_s() for i in range(n)]

    def tx_transfer_s(self):
        return {
            'recipient': self.tx_recipient(),
            'amount': self.tx_amount()
        }

    def tx_transfers(self, n):
        return [self.tx_transfer_s() for i in range(n)]

    def tx_func_arg_(self):
        arg_type = g_faker.random_element(elements=(0, 2))
        if arg_type == 0:
            return 'integer', self.random_uint64()
        elif arg_type == 1:
            return 'binary', self.random_bytes(64)
        elif arg_type == 2:
            return 'string', g_faker.sentence()
        elif arg_type == 6:
            return 'boolean', True
        elif arg_type == 7:
            return 'boolean', False
        else:
            return '', None

    def tx_func_arg(self):
        dt, value = self.tx_func_arg_()
        return value

    def tx_func_args(self, n):
        return [self.tx_func_arg() for i in range(n)]

    def tx_func_call(self, nargs):
        return {
            'function': g_faker.word(),
            'args': self.tx_func_args(nargs)
        }

    def tx_data_value(self):
        data_type = g_faker.random_element(elements=(0, 3))
        if data_type == 0:
            return  self.random_uint64()
        elif data_type == 1:
            return g_faker.boolean()
        elif data_type == 2:
            return self.random_bytes(64)
        elif data_type == 3:
            return g_faker.sentence()
        else:
            return None

    def tx_data_entry(self):
        value = self.tx_data_value()
        return {
            'key': g_faker.sentence(),
            'value': value
        }

    def tx_data_array(self, n):
        return [self.tx_data_entry() for i in range(n)]

    def tx_alias(self):
        return {
            'type': TransactionAlias.tx_type,
            'sender_public_key': self.tx_public_key(),
            'alias': self.tx_alias_s(),
            'fee': self.tx_fee(),
            'timestamp': self.tx_timestamp()
        }

    def tx_transfer(self):
        return {
            'type': TransactionTransfer.tx_type,
            'sender_public_key': self.tx_public_key(),
            'asset_id': self.tx_asset_id(),
            'fee_asset_id': self.tx_asset_id(),
            'timestamp': self.tx_timestamp(),
            'amount': self.tx_amount(),
            'fee': self.tx_fee(),
            'recipient': self.tx_recipient(),
            'attachment': self.tx_attachment()
         }

    def tx_data(self):
        return {
            'type': TransactionData.tx_type,
            'sender_public_key': self.tx_public_key(),
            'data': self.tx_data_array(4),
            'timestamp': self.tx_timestamp(),
            'fee': self.tx_fee()
        }

    def tx_mass_transfer(self):
        return {
            'type': TransactionMassTransfer.tx_type,
            'sender_public_key': self.tx_public_key(),
            'asset_id': self.tx_asset_id(),
            'transfers': self.tx_transfers(32),
            'timestamp': self.tx_timestamp(),
            'fee': self.tx_fee(),
            'attachment': self.tx_attachment()
        }

    def tx_issue(self):
        return {
            'type': TransactionIssue.tx_type,
            'chain_id': self.tx_chain_id(),
            'sender_public_key': self.tx_public_key(),
            'name': g_faker.sentence(),
            'description': g_faker.sentence(),
            'quantity': self.tx_quantity(),
            'decimals': self.tx_decimals(),
            'reissuable': self.tx_reissuable(),
            'fee': self.tx_fee(),
            'timestamp': self.tx_timestamp(),
            'script': self.tx_script()
        }

    def tx_reissue(self):
        return {
            'type': TransactionReissue.tx_type,
            'chain_id': self.tx_chain_id(),
            'sender_public_key': self.tx_public_key(),
            'asset_id': self.tx_asset_id(),
            'quantity': self.tx_quantity(),
            'reissuable': self.tx_reissuable(),
            'fee': self.tx_fee(),
            'timestamp': self.tx_timestamp()
        }

    def tx_burn(self):
        return {
            'type': TransactionBurn.tx_type,
            'chain_id': self.tx_chain_id(),
            'sender_public_key': self.tx_public_key(),
            'asset_id': self.tx_asset_id(),
            'quantity': self.tx_quantity(),
            'fee': self.tx_fee(),
            'timestamp': self.tx_timestamp()
        }

    def tx_lease(self):
        return {
            'type': TransactionLease.tx_type,
            'lease_asset_id': None,#self.tx_asset_id(),
            'sender_public_key': self.tx_public_key(),
            'recipient': self.tx_recipient(),
            'amount': self.tx_amount(),
            'fee': self.tx_fee(),
            'timestamp': self.tx_timestamp()
        }

    def tx_sponsorship(self):
        return {
            'type': TransactionSponsorship.tx_type,
            'sender_public_key': self.tx_public_key(),
            'asset_id': self.tx_asset_id(),
            'min_sponsored_asset_fee': self.tx_fee(),
            'fee': self.tx_fee(),
            'timestamp': self.tx_timestamp()
        }

    def tx_lease_cancel(self):
        return {
            'type': TransactionLeaseCancel.tx_type,
            'chain_id': self.tx_chain_id(),
            'sender_public_key': self.tx_public_key(),
            'fee': self.tx_fee(),
            'timestamp': self.tx_timestamp(),
            'lease_id': self.tx_lease_id()
        }

    def tx_set_script(self):
        return {
            'type': TransactionSetScript.tx_type,
            'chain_id': self.tx_chain_id(),
            'sender_public_key': self.tx_public_key(),
            'script': self.tx_script(),
            'fee': self.tx_fee(),
            'timestamp': self.tx_timestamp()
        }

    def tx_set_asset_script(self):
        return {
            'type': TransactionSetAssetScript.tx_type,
            'chain_id': self.tx_chain_id(),
            'asset_id': self.tx_asset_id(),
            'sender_public_key': self.tx_public_key(),
            'script': self.tx_script(),
            'fee': self.tx_fee(),
            'timestamp': self.tx_timestamp()
        }

    def tx_invoke_script(self):
        return {
            'type': TransactionInvokeScript.tx_type,
            'chain_id': self.tx_chain_id(),
            'sender_public_key': self.tx_public_key(),
            'd_app': self.tx_recipient(),
            'payments': self.tx_payments(1),
            'call': self.tx_func_call(4),
            'fee': self.tx_fee(),
            'fee_asset_id': self.tx_asset_id(),
            'timestamp': self.tx_timestamp()
        }


@pytest.fixture(scope="session")
def _faker():
    g_faker.add_provider(_TestRandProvider)
    g_faker.seed_instance(777)
    return g_faker


def _check_tx_fields(tx1, tx2):
    j1 = tx1.to_dict()
    j2 = tx2.to_dict()
    for field in tx1.fields:
        assert j1[field.name] == j2[field.name]


def _bytes_to_hex(bs):
    return ''.join(['%02x' % int(b) for b in bs])


def _to_camel_case(val):
    return ''.join([s if i == 0 else s.title() for i, s in enumerate(val.split('_'))])


def get_serialized_value(tx):
    app_data = tx.to_json()
    print(app_data)
    resp = requests.post('http://127.0.0.1:3000/serialize', json=app_data)
    resp_json = resp.json()
    if 'error' in resp_json:
        print(resp_json['error'])
    assert 'error' not in resp_json
    print("Expected: ", resp_json['tx'])
    tx3 = Transaction.from_json(resp_json['tx'])
    return resp_json['bin'], tx3


def _test_tx(_faker, cls):
    gen_f = getattr(_faker, 'tx_%s' % cls.tx_name)
    data = gen_f()
    print("Generated:", data)
    seed = gen_new_seed()
    pk = PrivateKey.from_seed(seed)
    tx1 = Transaction.from_dict(data)
    tx1.add_proof(pk)
    buf = tx1.serialize()
    expected, expected_tx = get_serialized_value(tx1)
    tx2 = Transaction.deserialize(buf)
    print("Deserialized:", tx2.to_dict())
    assert expected == _bytes_to_hex(buf)
    _check_tx_fields(tx1, tx2)


def test_tx_alias(_faker):
    _test_tx(_faker, TransactionAlias)


def test_tx_transfer(_faker):
    _test_tx(_faker, TransactionTransfer)


def test_tx_mass_transfer(_faker):
    _test_tx(_faker, TransactionMassTransfer)


def test_tx_data(_faker):
    _test_tx(_faker, TransactionData)


def test_tx_burn(_faker):
    _test_tx(_faker, TransactionBurn)


def test_tx_lease(_faker):
    _test_tx(_faker, TransactionLease)


def test_tx_issue(_faker):
    _test_tx(_faker, TransactionIssue)


def test_tx_reissue(_faker):
    _test_tx(_faker, TransactionReissue)


def test_tx_sponsorship(_faker):
    _test_tx(_faker, TransactionSponsorship)


def test_tx_lease_cancel(_faker):
    _test_tx(_faker, TransactionLeaseCancel)


def test_tx_set_script(_faker):
    _test_tx(_faker, TransactionSetScript)


def test_tx_set_asset_script(_faker):
    _test_tx(_faker, TransactionSetAssetScript)


def test_tx_invoke_script(_faker):
    _test_tx(_faker, TransactionInvokeScript)
