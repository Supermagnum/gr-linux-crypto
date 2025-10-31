#include <cstdint>
#include <cstring>
#include <unistd.h>
#include <openssl/evp.h>
#include <openssl/aes.h>
#include <openssl/rand.h>
#include <openssl/err.h>
#include <openssl/hmac.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <iostream>
#include <cstdlib>

#define MAX_SIZE 8192

// OpenSSL library fuzzing harness (tests OpenSSL directly)
static bool test_openssl_aes(const uint8_t* data, size_t size) {
    if (size < 32 + 16) return false; // Need at least key + IV

    // Extract key (32 bytes for AES-256)
    const uint8_t* key = data;

    // Extract IV (16 bytes)
    const uint8_t* iv = data + 32;

    // Remaining data is plaintext
    const uint8_t* plaintext = data + 48;
    size_t plaintext_len = size - 48;

    if (plaintext_len == 0) return false;

    // Test different AES modes
    const EVP_CIPHER* ciphers[] = {
        EVP_aes_256_cbc(),
        EVP_aes_256_ecb(),
        EVP_aes_256_cfb(),
        EVP_aes_256_ofb(),
        EVP_aes_256_gcm()
    };

    for (int i = 0; i < 5; i++) {
        EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
        if (!ctx) continue;

        // Initialize encryption
        if (EVP_EncryptInit_ex(ctx, ciphers[i], NULL, key, iv) != 1) {
            EVP_CIPHER_CTX_free(ctx);
            continue;
        }

        // Encrypt data
        uint8_t* encrypted = new uint8_t[plaintext_len + 16];
        int len = 0;
        int final_len = 0;

        if (EVP_EncryptUpdate(ctx, encrypted, &len, plaintext, plaintext_len) == 1) {
            if (EVP_EncryptFinal_ex(ctx, encrypted + len, &final_len) == 1) {
                // Test decryption
                EVP_CIPHER_CTX* dctx = EVP_CIPHER_CTX_new();
                if (dctx) {
                    if (EVP_DecryptInit_ex(dctx, ciphers[i], NULL, key, iv) == 1) {
                        uint8_t* decrypted = new uint8_t[len + final_len + 16];
                        int dlen = 0;
                        int dfinal_len = 0;

                        EVP_DecryptUpdate(dctx, decrypted, &dlen, encrypted, len + final_len);
                        EVP_DecryptFinal_ex(dctx, decrypted + dlen, &dfinal_len);

                        delete[] decrypted;
                    }
                    EVP_CIPHER_CTX_free(dctx);
                }
            }
        }

        delete[] encrypted;
        EVP_CIPHER_CTX_free(ctx);
    }

    return true;
}

static bool test_openssl_hash(const uint8_t* data, size_t size) {
    if (size < 1) return false;

    // Test different hash algorithms
    const EVP_MD* md_algs[] = {
        EVP_sha1(),
        EVP_sha256(),
        EVP_sha512(),
        EVP_md5(),
        EVP_sha3_256()
    };

    for (int i = 0; i < 5; i++) {
        EVP_MD_CTX* ctx = EVP_MD_CTX_new();
        if (!ctx) continue;

        if (EVP_DigestInit_ex(ctx, md_algs[i], NULL) == 1) {
            if (EVP_DigestUpdate(ctx, data, size) == 1) {
                uint8_t hash[EVP_MD_size(md_algs[i])];
                unsigned int hash_len;
                EVP_DigestFinal_ex(ctx, hash, &hash_len);
            }
        }

        EVP_MD_CTX_free(ctx);
    }

    return true;
}

static bool test_openssl_hmac(const uint8_t* data, size_t size) {
    if (size < 32) return false; // Need at least key

    // Extract key (first 32 bytes)
    const uint8_t* key = data;

    // Remaining data is message
    const uint8_t* message = data + 32;
    size_t message_len = size - 32;

    if (message_len == 0) return false;

    // Test different HMAC algorithms
    const EVP_MD* md_algs[] = {
        EVP_sha1(),
        EVP_sha256(),
        EVP_sha512()
    };

    for (int i = 0; i < 3; i++) {
        uint8_t hmac[EVP_MD_size(md_algs[i])];
        unsigned int hmac_len;

        HMAC(md_algs[i], key, 32, message, message_len, hmac, &hmac_len);
    }

    return true;
}

static bool test_openssl_rsa(const uint8_t* data, size_t size) {
    if (size < 1) return false;

    // Generate RSA key pair
    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL);
    if (!ctx) return false;

    if (EVP_PKEY_keygen_init(ctx) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        return false;
    }

    if (EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, 2048) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        return false;
    }

    EVP_PKEY* pkey = NULL;
    if (EVP_PKEY_keygen(ctx, &pkey) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        return false;
    }

    // Test encryption/decryption
    if (pkey) {
        // Encrypt
        EVP_PKEY_CTX* enc_ctx = EVP_PKEY_CTX_new(pkey, NULL);
        if (enc_ctx) {
            if (EVP_PKEY_encrypt_init(enc_ctx) > 0) {
                size_t outlen = 0;
                if (EVP_PKEY_encrypt(enc_ctx, NULL, &outlen, data, size) > 0) {
                    uint8_t* encrypted = new uint8_t[outlen];
                    if (EVP_PKEY_encrypt(enc_ctx, encrypted, &outlen, data, size) > 0) {
                        // Decrypt
                        EVP_PKEY_CTX* dec_ctx = EVP_PKEY_CTX_new(pkey, NULL);
                        if (dec_ctx) {
                            if (EVP_PKEY_decrypt_init(dec_ctx) > 0) {
                                size_t doutlen = 0;
                                if (EVP_PKEY_decrypt(dec_ctx, NULL, &doutlen, encrypted, outlen) > 0) {
                                    uint8_t* decrypted = new uint8_t[doutlen];
                                    EVP_PKEY_decrypt(dec_ctx, decrypted, &doutlen, encrypted, outlen);
                                    delete[] decrypted;
                                }
                            }
                            EVP_PKEY_CTX_free(dec_ctx);
                        }
                    }
                    delete[] encrypted;
                }
            }
            EVP_PKEY_CTX_free(enc_ctx);
        }

        EVP_PKEY_free(pkey);
    }

    EVP_PKEY_CTX_free(ctx);
    return true;
}

static void test_openssl_edge_cases(const uint8_t* data, size_t size) {
    if (size < 1) return;

    // Test with different data sizes
    if (size > 16) {
        test_openssl_aes(data, 16);
    }
    if (size > 32) {
        test_openssl_aes(data, 32);
    }
    if (size > 64) {
        test_openssl_aes(data, 64);
    }

    // Test with modified data
    if (size > 1) {
        uint8_t* modified_data = new uint8_t[size];
        memcpy(modified_data, data, size);

        // Flip bits
        for (size_t i = 0; i < size && i < 10; i++) {
            modified_data[i] ^= 0xFF;
        }
        test_openssl_aes(modified_data, size);

        // Zero out some bytes
        for (size_t i = 0; i < size && i < 5; i++) {
            modified_data[i] = 0x00;
        }
        test_openssl_aes(modified_data, size);

        delete[] modified_data;
    }
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size < 1 || size > MAX_SIZE) return 0;

    // Test actual OpenSSL operations - no artificial branching
    (void)test_openssl_aes(data, size);
    (void)test_openssl_hash(data, size);
    (void)test_openssl_hmac(data, size);
    (void)test_openssl_rsa(data, size);
    
    // Test edge cases
    test_openssl_edge_cases(data, size);

    return 0;
}

int main() {
    uint8_t buf[MAX_SIZE];
    ssize_t len = read(STDIN_FILENO, buf, MAX_SIZE);
    if (len <= 0) return 0;

    int result = LLVMFuzzerTestOneInput(buf, (size_t)len);
    return result;
}
