import pytest

from cwavespy import *


# Values generated using https://silkmind.com/wallet2console/
def test_priv_key_from_seed():
    seed = "wreck bonus pet equip wild tower vacuum creek ancient leaf present hobby brief dynamic captain"
    priv_key = PrivateKey.from_seed(seed)
    assert priv_key.b58_str == "AAnJK1jCZLUNfbEB3WXqfnfDDSLtpprKnxB75gRoN3Tp"


def test_pub_key_from_priv_key():
    priv_key = PrivateKey("AAnJK1jCZLUNfbEB3WXqfnfDDSLtpprKnxB75gRoN3Tp")
    pub_key = priv_key.gen_public_key()
    assert pub_key.b58_str == "AKwewrpZ2QVyNGJvfWZNKvpnaf64PtBAK4jeMKQDWnWX"


def test_pub_key_to_address():
    pub_key = PublicKey("AKwewrpZ2QVyNGJvfWZNKvpnaf64PtBAK4jeMKQDWnWX")
    addr = pub_key.to_address('W')
    assert addr.b58_str == "3PBtvYFvtmHetYw2gyNavVfvLHcXgqdzJBN"


def test_check_signature():
    msg = "hello"
    sig = "K3gDYbiGJ2JFtfdZUWkzbHYzY6QXmjjJSG1grMmD6Fi43sYsDaFLWxLUgDSDXrPfJ2em7ZFewgQHKhfigCcb644"
    pub_key = PublicKey("AKwewrpZ2QVyNGJvfWZNKvpnaf64PtBAK4jeMKQDWnWX")
    assert pub_key.verify_signature(msg, sig)
