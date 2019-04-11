from cffi import FFI


ffi = FFI()

ffi.cdef("""
typedef unsigned char curve25519_signature[64];
typedef unsigned char curve25519_public_key[32];
typedef unsigned char curve25519_secret_key[32];

void waves_secure_hash(const uint8_t *message, size_t message_len, uint8_t hash[32]);
void waves_gen_public_key(curve25519_public_key pubkey, curve25519_secret_key privkey);
void waves_public_key_to_address(const curve25519_public_key public_key, const unsigned char network_byte, unsigned char address[26]);
bool waves_sign_message(const curve25519_secret_key private_key, const unsigned char *message, size_t message_size, curve25519_signature signature);
bool waves_sign_message_custom_random(const curve25519_secret_key private_key, const unsigned char *message, const size_t message_size, curve25519_signature signature, const unsigned char *random64);
bool waves_verify_message(const curve25519_public_key public_key, const unsigned char *message, const size_t message_size, const curve25519_signature signature);
void waves_seed_to_address(const unsigned char *key, unsigned char network_byte, unsigned char output[26]);

ssize_t base58_decode(unsigned char *out, const char *in);
size_t base58_encode(char* out, const unsigned char* in, size_t in_sz);
""")

ffi.set_source("cwavespy._cext",
"""
     #include "waves/crypto.h"
     #include "waves/b58.h"
""",
     libraries=['waves_c', 'crypto'], library_dirs=['/usr/local/lib/waves'])


if __name__ == "__main__":
    ffi.compile(verbose=True)
