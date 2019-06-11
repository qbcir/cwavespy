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

    def random_uin64(self):
        return self.random_int(min=0, max=(1 << 64)-1)

    def tx_chain_id(self):
        return self.random_byte()

    def tx_decimals(self):
        return self.random_byte()

    def tx_fee(self):
        return self.random_uin64()

    def tx_timestamp(self):
        return self.random_uin64()

    def tx_quantity(self):
        return self.random_uin64()

    def tx_amount(self):
        return self.random_uin64()

    def tx_public_key(self):
        seed = g_faker.sentence()
        priv_key = PrivateKey.from_seed(seed)
        pub_key = PublicKey.from_private_key(priv_key)
        return pub_key.b58_str

    def random_b58(self, width):
        bs = bytes(self.random_byte() for i in range(width))
        return base58_encode(bs)

    def tx_asset_id(self):
        return self.random_b58(32)

    def tx_lease_id(self):
        return self.random_b58(32)

    def tx_script(self):
        return base64.b64encode(g_faker.sentence().encode())

    def tx_issue(self):
        return {
            'type': TransactionIssue.tx_type,
            'chain_id': self.tx_chain_id(),
            'sender_public_key': self.tx_public_key(),
            'asset_name': 'xxxx',#g_faker.sentence(),
            'asset_description': 'XXXX',##g_faker.sentence(),
            'quantity': self.tx_quantity(),
            'decimals': self.tx_decimals(),
            'reissuable': g_faker.boolean(),
            'fee': self.tx_fee(),
            'timestamp': self.tx_timestamp(),
            'script': self.tx_script()
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


@pytest.fixture(scope="session")
def _faker():
    g_faker.add_provider(_TestRandProvider)
    g_faker.seed_instance(777)
    return g_faker


def _check_tx_fields(tx, data):
    for field in tx.fields:
        assert getattr(tx, field.name) == data[field.name]


def _bytes_to_hex(bs):
    return ''.join(['%02x' % int(b) for b in bs])


def _to_camel_case(val):
    return ''.join([s if i == 0 else s.title() for i, s in enumerate(val.split('_'))])


def _to_serde_app_json(data):
    return {_to_camel_case(k): str(v) for k,v in six.iteritems(data)}


def get_serialized_value(data):
    resp = requests.post('http://127.0.0.1:3000/serialize', json=_to_serde_app_json(data))
    print(resp.json())
    return resp.json()['tx']


def test_tx_burn(_faker):
    data = _faker.tx_burn()
    tx = Transaction.from_dict(data)
    buf = tx.serialize()
    expected = get_serialized_value(data)
    assert expected == _bytes_to_hex(buf)
    tx2 = Transaction.deserialize(buf)
    _check_tx_fields(tx2, data)


def test_tx_issue(_faker):
    data = _faker.tx_issue()
    print(data)
    tx = Transaction.from_dict(data)
    buf = tx.serialize()
    expected = get_serialized_value(data)
    assert expected == _bytes_to_hex(buf)
    tx2 = Transaction.deserialize(buf)
    _check_tx_fields(tx2, data)
