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

enum
{
    TX_VERSION_0 = 0,
    TX_VERSION_1 = 1,
    TX_VERSION_2 = 2
};

enum
{
    TRANSACTION_TYPE_GENESIS = 1,
    TRANSACTION_TYPE_PAYMENT = 2,
    TRANSACTION_TYPE_ISSUE = 3,
    TRANSACTION_TYPE_TRANSFER = 4,
    TRANSACTION_TYPE_REISSUE = 5,
    TRANSACTION_TYPE_BURN = 6,
    TRANSACTION_TYPE_EXCHANGE = 7,
    TRANSACTION_TYPE_LEASE = 8,
    TRANSACTION_TYPE_CANCEL_LEASE = 9,
    TRANSACTION_TYPE_ALIAS = 10,
    TRANSACTION_TYPE_MASS_TRANSFER = 11,
    TRANSACTION_TYPE_DATA = 12,
    TRANSACTION_TYPE_SET_SCRIPT = 13,
    TRANSACTION_TYPE_SPONSORSHIP = 14,
    TRANSACTION_TYPE_SET_ASSET_SCRIPT = 15,
    TRANSACTION_TYPE_INVOKE_SCRIPT = 16
};

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
        tx_data_string_t binary;
        tx_data_string_t string;
    } types;
} tx_data_t;

typedef struct tx_data_entry_s
{
    tx_string_t key;
    tx_data_t value;
} tx_data_entry_t;

typedef struct tx_data_entry_array_s
{
    tx_data_entry_t* array;
    uint16_t len;
} tx_data_entry_array_t;

typedef struct tx_payment_s
{
    tx_size_t length;
    tx_amount_t amount;
    tx_asset_id_t asset_id;
} tx_payment_t;

typedef struct tx_payment_array_s
{
    tx_payment_t* array;
    uint16_t len;
} tx_payment_array_t;

typedef struct tx_transfer_s
{
    tx_addr_or_alias_t recepient;
    tx_amount_t amount;
} tx_transfer_t;

typedef struct tx_transfer_array_s
{
    tx_transfer_t* array;
    uint16_t len;
} tx_transfer_array_t;

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

typedef struct tx_func_arg_s
{
    uint8_t arg_type;
    union {
        tx_func_arg_integer_t integer;
        tx_func_arg_boolean_t boolean;
        tx_func_arg_string_t binary;
        tx_func_arg_string_t string;
    } types;
} tx_func_arg_t;

typedef struct tx_func_arg_array_s
{
    uint32_t len;
    tx_func_arg_t* array;
} tx_func_arg_array_t;

typedef struct tx_func_call_s
{
    tx_func_arg_string_t function_name;
    tx_func_arg_array_t args;
} tx_func_call_t;

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
    tx_data_entry_array_t data;
    tx_fee_t fee;
    tx_timestamp_t timestamp;
} data_tx_bytes_t;

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
    tx_transfer_array_t transfers;
    tx_timestamp_t timestamp;
    tx_fee_t fee;
    tx_string_t attachment;
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
    tx_addr_or_alias_t dapp;
    tx_func_call_t function_call;
    tx_payment_array_t payments;
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
    tx_string_t attachment;
} transfer_tx_bytes_t;

typedef struct tx_bytes_s
{
    uint8_t type;
    union {
        alias_tx_bytes_t alias;
        burn_tx_bytes_t burn;
        data_tx_bytes_t data;
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
} tx_bytes_t;


ssize_t waves_tx_from_bytes(tx_bytes_t* tx, const unsigned char *src);
size_t waves_tx_to_bytes(unsigned char *dst, const tx_bytes_t* tx);
size_t waves_tx_buffer_size(const tx_bytes_t* tx);

""")

ffi.set_source("cwavespy._cext",
"""
     #include "waves/crypto.h"
     #include "waves/b58.h"
     #include "waves/tx.h"
""",
     libraries=['waves_c', 'crypto'], library_dirs=['/usr/local/lib/waves'])


if __name__ == "__main__":
    ffi.compile(verbose=True)
