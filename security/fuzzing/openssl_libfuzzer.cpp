#include <cstdint>
#include <cstddef>
#include <cstring>
#include <openssl/evp.h>
#include <openssl/aes.h>
#include <openssl/err.h>
#include <openssl/hmac.h>

// LibFuzzer entry point
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size < 1 || size > 4096) {
        return 0; // Reject invalid sizes
    }

    // Test hash operations - ALWAYS runs, maximizes coverage
    EVP_MD_CTX* hash_ctx = EVP_MD_CTX_new();
    if (hash_ctx) {
        // Test multiple hash algorithms with same input
        const EVP_MD* hash_algs[] = {
            EVP_sha1(),
            EVP_sha256(),
            EVP_sha512(),
            EVP_md5()
        };
        
        for (int i = 0; i < 4; i++) {
            if (EVP_DigestInit_ex(hash_ctx, hash_algs[i], NULL) == 1) {
                if (EVP_DigestUpdate(hash_ctx, data, size) == 1) {
                    uint8_t hash[64]; // Max size for SHA512
                    unsigned int hash_len;
                    EVP_DigestFinal_ex(hash_ctx, hash, &hash_len);
                }
            }
        }
        EVP_MD_CTX_free(hash_ctx);
    }

    // Test AES operations - handle all input sizes gracefully
    uint8_t key[32] = {0}; // Default zero key
    uint8_t iv[16] = {0};  // Default zero IV
    size_t key_len = (size >= 32) ? 32 : size;  // Use available data for key
    size_t iv_len = (size >= 16) ? 16 : ((size > key_len) ? (size - key_len) : 0);
    
    // Extract key and IV from input data, pad with zeros if needed
    memcpy(key, data, (key_len < size) ? key_len : size);
    if (size > key_len) {
        memcpy(iv, data + key_len, (iv_len < (size - key_len)) ? iv_len : (size - key_len));
    }
    
    const uint8_t* plaintext = (size > key_len + iv_len) ? (data + key_len + iv_len) : data;
    size_t plaintext_len = (size > key_len + iv_len) ? (size - key_len - iv_len) : 0;
    
    // Test multiple AES modes - this exercises more code paths
    const EVP_CIPHER* aes_ciphers[] = {
        EVP_aes_256_cbc(),
        EVP_aes_256_ecb(),
        EVP_aes_128_cbc(),
        EVP_aes_128_ecb()
    };
    
    for (int i = 0; i < 4; i++) {
        EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
        if (ctx) {
            // Determine actual key size needed for this cipher
            int req_key_len = EVP_CIPHER_key_length(aes_ciphers[i]);
            if (req_key_len == 16) {
                // Use first 16 bytes of key for AES-128
                if (EVP_EncryptInit_ex(ctx, aes_ciphers[i], NULL, key, iv) == 1) {
                    if (plaintext_len > 0) {
                        uint8_t* encrypted = new uint8_t[plaintext_len + 16];
                        int len = 0;
                        int final_len = 0;
                        
                        if (EVP_EncryptUpdate(ctx, encrypted, &len, plaintext, plaintext_len) == 1) {
                            EVP_EncryptFinal_ex(ctx, encrypted + len, &final_len);
                        }
                        delete[] encrypted;
                    } else {
                        // Even with no plaintext, test init/update/final
                        uint8_t encrypted[16];
                        int len = 0;
                        int final_len = 0;
                        EVP_EncryptUpdate(ctx, encrypted, &len, data, (size < 16) ? size : 16);
                        EVP_EncryptFinal_ex(ctx, encrypted + len, &final_len);
                    }
                }
            } else if (req_key_len == 32) {
                // Use full 32 bytes for AES-256
                if (EVP_EncryptInit_ex(ctx, aes_ciphers[i], NULL, key, iv) == 1) {
                    if (plaintext_len > 0) {
                        uint8_t* encrypted = new uint8_t[plaintext_len + 16];
                        int len = 0;
                        int final_len = 0;
                        
                        if (EVP_EncryptUpdate(ctx, encrypted, &len, plaintext, plaintext_len) == 1) {
                            EVP_EncryptFinal_ex(ctx, encrypted + len, &final_len);
                        }
                        delete[] encrypted;
                    } else {
                        // Even with no plaintext, test init/update/final
                        uint8_t encrypted[16];
                        int len = 0;
                        int final_len = 0;
                        EVP_EncryptUpdate(ctx, encrypted, &len, data, (size < 16) ? size : 16);
                        EVP_EncryptFinal_ex(ctx, encrypted + len, &final_len);
                    }
                }
            }
            EVP_CIPHER_CTX_free(ctx);
        }
    }

    // Test HMAC operations - handle all input sizes gracefully
    size_t hmac_key_len = (size >= 32) ? 32 : size;  // Use available data
    const uint8_t* hmac_key = data;
    const uint8_t* hmac_message = (size > hmac_key_len) ? (data + hmac_key_len) : data;
    size_t hmac_message_len = (size > hmac_key_len) ? (size - hmac_key_len) : 0;
    
    // Test multiple HMAC algorithms
    const EVP_MD* hmac_algs[] = {
        EVP_sha1(),
        EVP_sha256(),
        EVP_sha512()
    };
    
    for (int i = 0; i < 3; i++) {
        uint8_t hmac[64]; // Max size for SHA512 HMAC
        unsigned int hmac_len;
        
        // Always call HMAC, even with minimal data - exercises error handling paths
        if (hmac_message_len > 0) {
            HMAC(hmac_algs[i], hmac_key, hmac_key_len, hmac_message, hmac_message_len, hmac, &hmac_len);
        } else {
            // Test with just key, no message (should still exercise some code)
            HMAC(hmac_algs[i], hmac_key, hmac_key_len, data, size, hmac, &hmac_len);
        }
    }

    return 0;
}
