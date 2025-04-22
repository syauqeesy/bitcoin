#include <stdio.h>
#include <string.h>
#include <openssl/rand.h>
#include <openssl/sha.h>
#include <openssl/ripemd.h>
#include <secp256k1.h>
#include "segwit_addr.h"

int main() {
  unsigned char private_key[32];
  unsigned char pubkey_serialized[33];
  unsigned char sha256_result[32];
  unsigned char ripemd160_result[20];
  unsigned char address[100];

  secp256k1_pubkey pubkey;
  secp256k1_context *ctx;

  size_t pubkey_len = 33;

  unsigned char witprog[21] = {0x00};

  if (RAND_bytes(private_key, sizeof(private_key)) != 1) {
    fprintf(stderr, "error generating random bytes\n");
    return 1;
  }

  ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN);

  if (secp256k1_ec_pubkey_create(ctx, &pubkey, private_key) != 1) {
    fprintf(stderr, "error creating public key\n");
    secp256k1_context_destroy(ctx);
    return 1;
  }

  if (secp256k1_ec_pubkey_serialize(ctx, pubkey_serialized, &pubkey_len, &pubkey, SECP256K1_EC_COMPRESSED) != 1) {
    fprintf(stderr, "error serializing public key\n");
    secp256k1_context_destroy(ctx);
    return 1;
  }

  SHA256(pubkey_serialized, 33, sha256_result);
  RIPEMD160(sha256_result, 32, ripemd160_result);

  memcpy(witprog + 1, ripemd160_result, 20);

  if (segwit_addr_encode(address, "tb" /* "bc" */, 3, witprog, sizeof(witprog)) != 1) {
    fprintf(stderr, "error encoding to bech32 wallet\n");
    secp256k1_context_destroy(ctx);
    return 1;
  }

  printf("private key (hex): ");
  for (int i = 0; i < 32; i++) {
    printf("%02x", private_key[i]);
  }

  printf("\n");

  printf("public key (compressed, hex): ");
  for (int i = 0; i < 33; i++) {
    printf("%02x", pubkey_serialized[i]);
  }

  printf("\n");

  printf("bitcoin SegWit Address (Bech32): ");
  for (int i = 0; address[i] != '\0'; i++) {
    printf("%c", address[i]);
  }

  printf("\n");

  secp256k1_context_destroy(ctx);

  return 0;
}
