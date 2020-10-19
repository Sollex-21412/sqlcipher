/*
** SQLCipher
** http://sqlcipher.net
**
** Copyright (c) 2008 - 2013, ZETETIC LLC
** All rights reserved.
**
** Redistribution and use in source and binary forms, with or without
** modification, are permitted provided that the following conditions are met:
**     * Redistributions of source code must retain the above copyright
**       notice, this list of conditions and the following disclaimer.
**     * Redistributions in binary form must reproduce the above copyright
**       notice, this list of conditions and the following disclaimer in the
**       documentation and/or other materials provided with the distribution.
**     * Neither the name of the ZETETIC LLC nor the
**       names of its contributors may be used to endorse or promote products
**       derived from this software without specific prior written permission.
**
** THIS SOFTWARE IS PROVIDED BY ZETETIC LLC ''AS IS'' AND ANY
** EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
** WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
** DISCLAIMED. IN NO EVENT SHALL ZETETIC LLC BE LIABLE FOR ANY
** DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
** (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
** LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
** ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
** (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
** SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
**
*/
/* BEGIN SQLCIPHER */

#define SQLITE_HAS_CODEC 1
#define SQLCIPHER_CRYPTO_BOTAN 1

#ifdef SQLITE_HAS_CODEC
#ifdef SQLCIPHER_CRYPTO_BOTAN
#include "crypto.h"
#include "sqlcipher.h"

typedef struct botan_rng_struct* botan_rng_t;
typedef struct botan_mac_struct* botan_mac_t;
typedef struct botan_cipher_struct* botan_cipher_t;

const char* botan_version_string(void);

int botan_pwdhash(
   const char* algo,
   size_t param1,
   size_t param2,
   size_t param3,
   uint8_t out[],
   size_t out_len,
   const char* passphrase,
   size_t passphrase_len,
   const uint8_t salt[],
   size_t salt_len);

int botan_cipher_init(botan_cipher_t* cipher, const char* name, uint32_t flags);
int botan_cipher_set_key(botan_cipher_t cipher, const uint8_t* key, size_t key_len);
int botan_cipher_start(botan_cipher_t cipher, const uint8_t* nonce, size_t nonce_len);
int botan_cipher_update(botan_cipher_t cipher,
                                  uint32_t flags,
                                  uint8_t output[],
                                  size_t output_size,
                                  size_t* output_written,
                                  const uint8_t input_bytes[],
                                  size_t input_size,
                                  size_t* input_consumed);
int botan_cipher_destroy(botan_cipher_t cipher);

int botan_mac_init(botan_mac_t* mac, const char* mac_name, uint32_t flags);
int botan_mac_set_key(botan_mac_t mac, const uint8_t* key, size_t key_len);
int botan_mac_update(botan_mac_t mac, const uint8_t* buf, size_t len);
int botan_mac_final(botan_mac_t mac, uint8_t out[]);
int botan_mac_output_length(botan_mac_t mac, size_t* output_length);
int botan_mac_destroy(botan_mac_t mac);

#define BOTAN_CIPHER_INIT_FLAG_ENCRYPT 0
#define BOTAN_CIPHER_INIT_FLAG_DECRYPT 1

#define BOTAN_CIPHER_UPDATE_FLAG_FINAL (1U << 0)

#define BOTAN_FFI_SUCCESS 0

static unsigned int botan_init_count = 0;

static int sqlcipher_botan_activate(void *ctx) {
  CODEC_TRACE_MUTEX("sqlcipher_botan_activate: entering SQLCIPHER_MUTEX_PROVIDER_ACTIVATE\n");
  sqlite3_mutex_enter(sqlcipher_mutex(SQLCIPHER_MUTEX_PROVIDER_ACTIVATE));
  CODEC_TRACE_MUTEX("sqlcipher_botan_activate: entered SQLCIPHER_MUTEX_PROVIDER_ACTIVATE\n");

  botan_init_count++;

  CODEC_TRACE_MUTEX("sqlcipher_botan_activate: leaving SQLCIPHER_MUTEX_PROVIDER_ACTIVATE\n");
  sqlite3_mutex_leave(sqlcipher_mutex(SQLCIPHER_MUTEX_PROVIDER_ACTIVATE));
  CODEC_TRACE_MUTEX("sqlcipher_botan_activate: left SQLCIPHER_MUTEX_PROVIDER_ACTIVATE\n");
  return SQLITE_OK;
}

static int sqlcipher_botan_deactivate(void *ctx) {
  CODEC_TRACE_MUTEX("sqlcipher_botan_deactivate: entering SQLCIPHER_MUTEX_PROVIDER_ACTIVATE\n");
  sqlite3_mutex_enter(sqlcipher_mutex(SQLCIPHER_MUTEX_PROVIDER_ACTIVATE));
  CODEC_TRACE_MUTEX("sqlcipher_botan_deactivate: entered SQLCIPHER_MUTEX_PROVIDER_ACTIVATE\n");

  botan_init_count--;

  CODEC_TRACE_MUTEX("sqlcipher_botan_deactivate: leaving SQLCIPHER_MUTEX_PROVIDER_ACTIVATE\n");
  sqlite3_mutex_leave(sqlcipher_mutex(SQLCIPHER_MUTEX_PROVIDER_ACTIVATE));
  CODEC_TRACE_MUTEX("sqlcipher_botan_deactivate: left SQLCIPHER_MUTEX_PROVIDER_ACTIVATE\n");
  return SQLITE_OK;
}

static int sqlcipher_botan_add_random(void *ctx, void *buffer, int length) {
  return SQLITE_OK;
}

/* generate a defined number of random bytes */
static int sqlcipher_botan_random (void *ctx, void *buffer, int length) {
  int rc = SQLITE_OK;
  botan_rng_t rng = NULL;
  if (botan_rng_init(&rng, "system") != BOTAN_FFI_SUCCESS) {
    goto error;
  }

  if (botan_rng_get(rng, buffer, length) != BOTAN_FFI_SUCCESS) {
    goto error;
  }

  goto cleanup;
  error:
    rc = SQLITE_ERROR;
  cleanup:
    if (rng) botan_rng_destroy(rng);
    return rc;
}

static const char* sqlcipher_botan_get_provider_name(void *ctx) {
  return "botan";
}

static const char* sqlcipher_botan_get_provider_version(void *ctx) {
  return botan_version_string();
}

static const char* sqlcipher_botan_get_cipher(void *ctx) {
  return "AES-256/CBC/NoPadding";
}

static int sqlcipher_botan_get_key_sz(void *ctx) {
  botan_cipher_t cipher = NULL;

  if (botan_cipher_init(&cipher, sqlcipher_botan_get_cipher(ctx), BOTAN_CIPHER_INIT_FLAG_ENCRYPT) != BOTAN_FFI_SUCCESS) {
    goto error;
  }

  size_t min_keylen = 0;
  if (botan_cipher_get_keyspec(cipher, &min_keylen, NULL, NULL) != BOTAN_FFI_SUCCESS) {
    goto error;
  }

  goto cleanup;
  error:
    min_keylen = SQLITE_ERROR;
  cleanup:
    if (cipher) botan_cipher_destroy(cipher);
    return min_keylen;
}

static int sqlcipher_botan_get_iv_sz(void *ctx) {
  botan_cipher_t cipher = NULL;

  if (botan_cipher_init(&cipher, sqlcipher_botan_get_cipher(ctx), BOTAN_CIPHER_INIT_FLAG_ENCRYPT) != BOTAN_FFI_SUCCESS) {
    goto error;
  }

  size_t nl = 0;
  if (botan_cipher_get_default_nonce_length(cipher, &nl) != BOTAN_FFI_SUCCESS) {
    goto error;
  }

  goto cleanup;
  error:
    nl = SQLITE_ERROR;
  cleanup:
    if (cipher) botan_cipher_destroy(cipher);
    return nl;
}

static int sqlcipher_botan_get_block_sz(void *ctx) {
  botan_cipher_t cipher = NULL;

  if (botan_cipher_init(&cipher, sqlcipher_botan_get_cipher(ctx), BOTAN_CIPHER_INIT_FLAG_ENCRYPT) != BOTAN_FFI_SUCCESS) {
    goto error;
  }

  size_t ug = 0;
  if (botan_cipher_get_update_granularity(cipher, &ug) != BOTAN_FFI_SUCCESS) {
    goto error;
  }

  goto cleanup;
  error:
    ug = SQLITE_ERROR;
  cleanup:
    if (cipher) botan_cipher_destroy(cipher);
    return ug;
}

static int sqlcipher_botan_get_hmac_sz(void *ctx, int algorithm) {
  botan_mac_t mac = NULL;
  char *mac_name = NULL; 
  switch(algorithm) {
    case SQLCIPHER_HMAC_SHA1:
      mac_name = "HMAC(SHA1)";
      break;
    case SQLCIPHER_HMAC_SHA256:
      mac_name = "HMAC(SHA-256)";
      break;
    case SQLCIPHER_HMAC_SHA512:
      mac_name = "HMAC(SHA-256)";
      break;
    default:
      return SQLITE_ERROR;
  }

  if (botan_mac_init(&mac, mac_name, 0) != BOTAN_FFI_SUCCESS) {
    goto error;
  }

  size_t output_length = 0;
  if (botan_mac_output_length(mac, &output_length) != BOTAN_FFI_SUCCESS) {
    goto error;
  }

  goto cleanup;
  error:
    output_length = SQLITE_ERROR;
  cleanup:
    if (mac) botan_mac_destroy(mac);
    return output_length;
}

static int sqlcipher_botan_hmac(void *ctx, int algorithm, unsigned char *hmac_key, int key_sz, unsigned char *in, int in_sz, unsigned char *in2, int in2_sz, unsigned char *out) {
  int rc = SQLITE_OK;
  botan_mac_t mac = NULL;
  char *mac_name = NULL; 
  if (in == NULL) {
    return SQLITE_ERROR;
  }

  switch(algorithm) {
    case SQLCIPHER_HMAC_SHA1:
      mac_name = "HMAC(SHA1)";
      break;
    case SQLCIPHER_HMAC_SHA256:
      mac_name = "HMAC(SHA-256)";
      break;
    case SQLCIPHER_HMAC_SHA512:
      mac_name = "HMAC(SHA-256)";
      break;
    default:
      return SQLITE_ERROR;
  }

  if (botan_mac_init(&mac, mac_name, 0) != BOTAN_FFI_SUCCESS) {
    goto error;
  }

  if (botan_mac_set_key(mac, hmac_key, key_sz) != BOTAN_FFI_SUCCESS) {
    goto error;
  }

  if (botan_mac_update(mac, in, in_sz) != BOTAN_FFI_SUCCESS) {
    goto error;
  }

  if (in2 != NULL) {
    if (botan_mac_update(mac, in2, in2_sz) != BOTAN_FFI_SUCCESS) {
      goto error;
    }
  }

  if (botan_mac_final(mac, out) != BOTAN_FFI_SUCCESS) {
    goto error;
  }

  goto cleanup;
  error:
    rc = SQLITE_ERROR;
  cleanup:
    if (mac) botan_mac_destroy(mac);
    return rc;
}

static int sqlcipher_botan_kdf(void *ctx, int algorithm, const unsigned char *pass, int pass_sz, unsigned char* salt, int salt_sz, int workfactor, int key_sz, unsigned char *key) {
  int rc = SQLITE_OK;
  char *algo = NULL;
  switch(algorithm) {
    case SQLCIPHER_HMAC_SHA1:
      algo = "PBKDF2(SHA1)";
      break;
    case SQLCIPHER_HMAC_SHA256:
      algo = "PBKDF2(SHA-256)";
      break;
    case SQLCIPHER_HMAC_SHA512:
      algo = "PBKDF2(SHA-512)";
      break;
    default:
      goto error;
  }

  if (botan_pwdhash(algo, workfactor, 0, 0, key, key_sz, pass, pass_sz, salt, salt_sz) != BOTAN_FFI_SUCCESS) {
    goto error;
  }

  goto cleanup;
  error:
    rc = SQLITE_ERROR;
  cleanup:
    return rc;
}

static int sqlcipher_botan_cipher(void *ctx, int mode, unsigned char *key, int key_sz, unsigned char *iv, unsigned char *in, int in_sz, unsigned char *out) {
  int rc = SQLITE_OK;
  botan_cipher_t cipher = NULL;

  if (botan_cipher_init(&cipher, sqlcipher_botan_get_cipher(ctx), mode == CIPHER_ENCRYPT ? BOTAN_CIPHER_INIT_FLAG_ENCRYPT : BOTAN_CIPHER_INIT_FLAG_DECRYPT) != BOTAN_FFI_SUCCESS) {
    goto error;
  }

  if (botan_cipher_set_key(cipher, key, key_sz) != BOTAN_FFI_SUCCESS) {
    goto error;
  }

  if (botan_cipher_start(cipher, iv, sqlcipher_botan_get_iv_sz(ctx)) != BOTAN_FFI_SUCCESS) {
    goto error;
  }

  size_t output_written = 0;
  size_t input_consumed = 0;

  if (botan_cipher_update(cipher, BOTAN_CIPHER_UPDATE_FLAG_FINAL, out, in_sz + 16, &output_written, in, in_sz, &input_consumed) != BOTAN_FFI_SUCCESS) {
    goto error;
  }

  goto cleanup;
  error:
    rc = SQLITE_ERROR;
  cleanup:
    if (cipher) botan_cipher_destroy(cipher);
    return rc;
}

static int sqlcipher_botan_ctx_init(void **ctx) {
  sqlcipher_botan_activate(NULL);
  return SQLITE_OK;
}

static int sqlcipher_botan_ctx_free(void **ctx) {
  sqlcipher_botan_deactivate(NULL);
  return SQLITE_OK;
}

static int sqlcipher_botan_fips_status(void *ctx) {
  return 0;
}

int sqlcipher_botan_setup(sqlcipher_provider *p) {
  p->activate = sqlcipher_botan_activate;
  p->deactivate = sqlcipher_botan_deactivate;
  p->random = sqlcipher_botan_random;
  p->get_provider_name = sqlcipher_botan_get_provider_name;
  p->hmac = sqlcipher_botan_hmac;
  p->kdf = sqlcipher_botan_kdf;
  p->cipher = sqlcipher_botan_cipher;
  p->get_cipher = sqlcipher_botan_get_cipher;
  p->get_key_sz = sqlcipher_botan_get_key_sz;
  p->get_iv_sz = sqlcipher_botan_get_iv_sz;
  p->get_block_sz = sqlcipher_botan_get_block_sz;
  p->get_hmac_sz = sqlcipher_botan_get_hmac_sz;
  p->ctx_init = sqlcipher_botan_ctx_init;
  p->ctx_free = sqlcipher_botan_ctx_free;
  p->add_random = sqlcipher_botan_add_random;
  p->fips_status = sqlcipher_botan_fips_status;
  p->get_provider_version = sqlcipher_botan_get_provider_version;
  return SQLITE_OK;
}

#endif
#endif
/* END SQLCIPHER */
