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
        return ord('M')
        #return self.random_byte()

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

    def tx_address(self):
        seed = g_faker.sentence()
        priv_key = PrivateKey.from_seed(seed)
        pub_key = PublicKey.from_private_key(priv_key)
        addr = pub_key.to_address('M')
        return addr.b58_str

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
            #FIXME
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
    if isinstance(data, dict):
        data_ = {_to_camel_case(k): _to_serde_app_json(v) for k,v in six.iteritems(data)}
        if 'chainId' in data_:
            data_['chainId'] = 'M'
        if 'alias' in data and isinstance(data['alias'], dict):
            data_['chainId'] = 'M'
            data_['alias'] = data['alias']['alias']
        if 'recipient' in data:
            rcpt_data = data['recipient']['data']
            if data['recipient']['is_alias']:
                data_['recipient'] = 'alias:%s:%s' % (chr(rcpt_data['alias']['chain_id']), rcpt_data['alias']['alias'])
            else:
                data_['recipient'] = rcpt_data['address']
        return data_
    elif isinstance(data, bytes):
        return data.decode()
    else:
        return str(data)


def get_serialized_value(data):
    app_data = _to_serde_app_json(data)
    print(app_data)
    resp = requests.post('http://127.0.0.1:3000/serialize', json=app_data)
    resp_json = resp.json()
    if 'error' in resp_json:
        print(resp_json['error'])
    assert 'error' not in resp_json
    print("Expected: ", resp_json['tx'])
    return resp_json['bin']


def _test_tx(_faker, cls):
    gen_f = getattr(_faker, 'tx_%s' % cls.tx_name)
    data = gen_f()
    print("Generated:", data)
    tx = Transaction.from_dict(data)
    buf = tx.serialize()
    expected = get_serialized_value(data)
    tx2 = Transaction.deserialize(buf)
    print("Deserialized:", tx2.to_dict())
    assert expected == _bytes_to_hex(buf)
    _check_tx_fields(tx2, data)


def test_tx_alias(_faker):
    _test_tx(_faker, TransactionAlias)


def test_tx_transfer(_faker):
    _test_tx(_faker, TransactionTransfer)


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
