global-incdirs-y += include
global-incdirs-y += crypto

# source file
srcs-y += bip39.c
srcs-y += bip32.c
srcs-y += bitcoin_wallet_ta.c

# adding bip39 required crypto functions
srcs-y += crypto/hmac.c
srcs-y += crypto/memzero.c
srcs-y += crypto/pbkdf2.c
srcs-y += crypto/sha2.c
srcs-y += crypto/bignum.c
srcs-y += crypto/ecdsa.c
srcs-y += crypto/secp256k1.c
srcs-y += crypto/ta_ripemd160.c