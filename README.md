# Bitcoin CLI

Dependencies:
* openssl
* secp256k1
* bech32

Compile run:
```
  clang main.c -I/path/to/openssl/include -L/path/to/openssl/lib -I/path/to/secp256k1/include -L/path/to/secp256k1/lib  -lcrypto -lsecp256k1
```
