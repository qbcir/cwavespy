from cffi import FFI


ffi = FFI()

ffi.cdef("""
typedef unsigned char curve25519_signature[64];
typedef unsigned char curve25519_public_key[32];
typedef unsigned char curve25519_secret_key[32];

void waves_secure_hash(const uint8_t *message, size_t message_len, uint8_t hash[32]);
void waves_gen_private_key(curve25519_secret_key privkey, const unsigned char *seed);
void waves_gen_public_key(curve25519_public_key pubkey, curve25519_secret_key privkey);
void waves_public_key_to_address(const curve25519_public_key public_key, const unsigned char network_byte, unsigned char address[26]);
bool waves_sign_message(const curve25519_secret_key private_key, const unsigned char *message, size_t message_size, curve25519_signature signature);
bool waves_sign_message_custom_random(const curve25519_secret_key private_key, const unsigned char *message, const size_t message_size, curve25519_signature signature, const unsigned char *random64);
bool waves_verify_message(const curve25519_public_key public_key, const unsigned char *message, const size_t message_size, const curve25519_signature signature);

ssize_t base58_decode(unsigned char *out, const char *in);
size_t base58_encode(char* out, const unsigned char* in, size_t in_sz);

ssize_t base64_decode(unsigned char *dst, const char *src);
size_t base64_encode(char* dst, const unsigned char* src, size_t in_sz);

typedef uint8_t tx_version_t;
typedef uint8_t tx_chain_id_t;
typedef uint8_t tx_decimals_t;
typedef uint64_t tx_fee_t;
typedef uint64_t tx_quantity_t;
typedef uint64_t tx_timestamp_t;
typedef uint64_t tx_amount_t;
typedef bool tx_reissuable_t;

typedef struct tx_encoded_string_s {
    char* encoded_data;
    char* decoded_data;
    size_t encoded_len;
    size_t decoded_len;
} tx_encoded_string_t;

typedef struct tx_string_s
{
    char* data;
    uint16_t len;
} tx_string_t;

typedef tx_encoded_string_t tx_public_key_t;
typedef tx_encoded_string_t tx_asset_id_t;
typedef tx_encoded_string_t tx_lease_id_t;
typedef tx_encoded_string_t tx_lease_asset_id_t;
typedef tx_encoded_string_t tx_address_t;
typedef tx_encoded_string_t tx_signature_t;

typedef uint32_t tx_array_size_t;
typedef int64_t tx_array_ssize_t;
typedef void (*tx_array_elem_destroy_func_t)(char*);

typedef struct tx_array_s
{
    char* array;
    tx_array_size_t len;
    size_t elem_sz;
    size_t capacity;
    tx_array_elem_destroy_func_t elem_destructor;
} tx_array_t;

typedef struct tx_alias_s
{
    tx_chain_id_t chain_id;
    tx_string_t alias;
} tx_alias_t;

typedef struct tx_addr_or_alias_s
{
    bool is_alias;
    union
    {
        tx_address_t address;
        tx_alias_t alias;
    } data;
} tx_addr_or_alias_t;

typedef uint16_t tx_size_t;
typedef uint64_t tx_data_integer_t;
typedef uint8_t tx_data_boolean_t;
typedef tx_string_t tx_data_string_t;

typedef tx_encoded_string_t tx_script_t;
typedef tx_encoded_string_t tx_attachment_t;

enum
{
    TX_DATA_TYPE_INTEGER = 0,
    TX_DATA_TYPE_BOOLEAN = 1,
    TX_DATA_TYPE_BINARY = 2,
    TX_DATA_TYPE_STRING = 3,
};

typedef struct tx_data_s
{
    uint8_t data_type;
    union {
        tx_data_integer_t integer;
        tx_data_boolean_t boolean;
        tx_encoded_string_t binary;
        tx_data_string_t string;
    } types;
} tx_data_t;

typedef struct tx_data_entry_s
{
    tx_string_t key;
    tx_data_t value;
} tx_data_entry_t;

typedef struct tx_payment_s
{
    tx_amount_t amount;
    tx_asset_id_t asset_id;
} tx_payment_t;

typedef struct tx_transfer_s
{
    tx_addr_or_alias_t recipient;
    tx_amount_t amount;
} tx_transfer_t;

enum
{
    TX_FUNC_ARG_INT = 0,
    TX_FUNC_ARG_BIN = 1,
    TX_FUNC_ARG_STR = 2,
    TX_FUNC_ARG_TRUE = 6,
    TX_FUNC_ARG_FALSE = 7
};

typedef uint64_t tx_func_arg_integer_t;
typedef bool tx_func_arg_boolean_t;

typedef struct tx_func_arg_string_s
{
    char* data;
    uint32_t len;
} tx_func_arg_string_t;

typedef struct tx_func_arg_binary_s
{
    char* encoded_data;
    char* decoded_data;
    uint64_t encoded_len;
    uint32_t decoded_len;
} tx_func_arg_binary_t;

typedef struct tx_func_arg_s
{
    uint8_t arg_type;
    union {
        tx_func_arg_integer_t integer;
        tx_func_arg_boolean_t boolean;
        tx_func_arg_binary_t binary;
        tx_func_arg_string_t string;
    } types;
} tx_func_arg_t;

typedef struct tx_func_call_s
{
    bool valid;
    tx_func_arg_string_t function;
    tx_array_t args;
} tx_func_call_t;

typedef struct tx_asset_pair_s
{
    tx_asset_id_t amount_asset;
    tx_asset_id_t price_asset;
} tx_asset_pair_t;

typedef struct tx_order_s
{
    uint8_t version;
    tx_public_key_t sender_public_key;
    tx_public_key_t matcher_public_key;
    tx_asset_pair_t asset_pair;
    uint8_t order_type;
    uint64_t price;
    tx_amount_t amount;
    tx_timestamp_t timestamp;
    uint64_t expiration;
    tx_fee_t matcher_fee;
    tx_array_t proofs;
    tx_signature_t signature;
} tx_order_t;

typedef struct alias_tx_bytes_s
{
    tx_public_key_t sender_public_key;
    tx_alias_t alias;
    tx_fee_t fee;
    tx_timestamp_t timestamp;
} alias_tx_bytes_t;

typedef struct burn_tx_bytes_s
{
    tx_chain_id_t chain_id;
    tx_public_key_t sender_public_key;
    tx_asset_id_t asset_id;
    tx_quantity_t quantity;
    tx_fee_t fee;
    tx_timestamp_t timestamp;
} burn_tx_bytes_t;

typedef struct data_tx_bytes_s
{
    tx_public_key_t sender_public_key;
    tx_array_t data;
    tx_fee_t fee;
    tx_timestamp_t timestamp;
} data_tx_bytes_t;

typedef struct exchange_tx_bytes_s
{
    tx_order_t order1;
    tx_order_t order2;
    tx_amount_t price;
    tx_amount_t amount;
    tx_fee_t buy_matcher_fee;
    tx_fee_t sell_matcher_fee;
    tx_fee_t fee;
    tx_timestamp_t timestamp;
} exchange_tx_bytes_t;

typedef struct lease_cancel_tx_bytes_s
{
    tx_chain_id_t chain_id;
    tx_public_key_t sender_public_key;
    tx_fee_t fee;
    tx_timestamp_t timestamp;
    tx_lease_id_t lease_id;
} lease_cancel_tx_bytes_t;

typedef struct lease_tx_bytes_s
{
    tx_lease_asset_id_t lease_asset_id;
    tx_public_key_t sender_public_key;
    tx_addr_or_alias_t recipient;
    uint64_t amount;
    uint64_t fee;
    uint64_t timestamp;
} lease_tx_bytes_t;

typedef struct mass_transfer_tx_bytes_s
{
    tx_public_key_t sender_public_key;
    tx_asset_id_t asset_id;
    tx_array_t transfers;
    tx_timestamp_t timestamp;
    tx_fee_t fee;
    tx_encoded_string_t attachment;
} mass_transfer_tx_bytes_t;

typedef struct issue_tx_bytes_s
{
    tx_chain_id_t chain_id;
    tx_public_key_t sender_public_key;
    tx_string_t name;
    tx_string_t description;
    tx_quantity_t quantity;
    tx_decimals_t decimals;
    tx_reissuable_t reissuable;
    tx_fee_t fee;
    tx_timestamp_t timestamp;
    tx_script_t script;
} issue_tx_bytes_t;

typedef struct reissue_tx_bytes_s
{
    tx_chain_id_t chain_id;
    tx_public_key_t sender_public_key;
    tx_asset_id_t asset_id;
    tx_quantity_t quantity;
    tx_reissuable_t reissuable;
    tx_fee_t fee;
    tx_timestamp_t timestamp;
} reissue_tx_bytes_t;

typedef struct set_asset_script_tx_bytes_s
{
    tx_chain_id_t chain_id;
    tx_public_key_t sender_public_key;
    tx_asset_id_t asset_id;
    tx_fee_t fee;
    tx_timestamp_t timestamp;
    tx_script_t script;
} set_asset_script_tx_bytes_t;

typedef struct set_script_tx_bytes_s
{
    tx_chain_id_t chain_id;
    tx_public_key_t sender_public_key;
    tx_script_t script;
    tx_fee_t fee;
    tx_timestamp_t timestamp;
} set_script_tx_bytes_t;

typedef struct sponsorship_tx_bytes_s
{
    tx_public_key_t sender_public_key;
    tx_asset_id_t asset_id;
    tx_fee_t min_sponsored_asset_fee;
    tx_fee_t fee;
    tx_timestamp_t timestamp;
} sponsorship_tx_bytes_t;

typedef struct invoke_script_tx_bytes_s
{
    tx_chain_id_t chain_id;
    tx_public_key_t sender_public_key;
    tx_addr_or_alias_t d_app;
    tx_func_call_t call;
    tx_array_t payments;
    tx_fee_t fee;
    tx_asset_id_t fee_asset_id;
    tx_timestamp_t timestamp;
} invoke_script_tx_bytes_t;

typedef struct transfer_tx_bytes_s
{
    tx_public_key_t sender_public_key;
    tx_asset_id_t asset_id;
    tx_asset_id_t fee_asset_id;
    tx_timestamp_t timestamp;
    tx_amount_t amount;
    tx_fee_t fee;
    tx_addr_or_alias_t recipient;
    tx_encoded_string_t attachment;
} transfer_tx_bytes_t;

typedef struct tx_bytes_s
{
    uint8_t type;
    tx_version_t version;
    union {
        alias_tx_bytes_t alias;
        burn_tx_bytes_t burn;
        data_tx_bytes_t data;
        exchange_tx_bytes_t exchange;
        lease_cancel_tx_bytes_t lease_cancel;
        lease_tx_bytes_t lease;
        issue_tx_bytes_t issue;
        reissue_tx_bytes_t reissue;
        sponsorship_tx_bytes_t sponsorship;
        transfer_tx_bytes_t transfer;
        mass_transfer_tx_bytes_t mass_transfer;
        set_script_tx_bytes_t set_script;
        set_asset_script_tx_bytes_t set_asset_script;
        invoke_script_tx_bytes_t invoke_script;
    } data;
} waves_tx_t;

int waves_tx_init(waves_tx_t* tx, uint8_t tx_type);
waves_tx_t* waves_tx_load(const unsigned char *src);
ssize_t waves_tx_from_bytes(waves_tx_t* tx, const unsigned char *src);
size_t waves_tx_to_bytes(unsigned char *dst, const waves_tx_t* tx);
size_t waves_tx_buffer_size(const waves_tx_t* tx);
void waves_tx_destroy(waves_tx_t *tx);

size_t waves_order_to_bytes(unsigned char* dst, const tx_order_t *src);
size_t waves_order_bytes_size(const tx_order_t *v);

tx_string_t* waves_tx_id(waves_tx_t* tx);
void waves_tx_destroy_string(tx_string_t* id);

""")

ffi.set_source("cwavespy._cext",
"""
     #include "waves/crypto.h"
     #include "waves/b58.h"
     #include "waves/b64.h"
     #include "waves/tx.h"
""",
     libraries=['waves_c', 'crypto'], library_dirs=['/usr/local/lib/waves'])


if __name__ == "__main__":
    ffi.compile(verbose=True)
