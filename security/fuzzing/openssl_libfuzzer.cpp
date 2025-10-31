#include <cstdint>
#include <cstddef>
#include <cstring>
#include <openssl/evp.h>
#include <openssl/aes.h>
#include <openssl/err.h>
#include <openssl/hmac.h>

// LibFuzzer entry point
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size < 1 || size > 1024) {
        return 0; // Reject invalid sizes
    }

    // Test AES operations
    if (size >= 48) {  // Need at least key (32) + IV (16)
        const uint8_t* key = data;
        const uint8_t* iv = data + 32;
        const uint8_t* plaintext = data + 48;
        size_t plaintext_len = size - 48;
        
        if (plaintext_len > 0) {
            const EVP_CIPHER* cipher = EVP_aes_256_cbc();
            EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
            
            if (ctx) {
                if (EVP_EncryptInit_ex(ctx, cipher, NULL, key, iv) == 1) {
                    uint8_t* encrypted = new uint8_t[plaintext_len + 16];
                    int len = 0;
                    int final_len = 0;
                    
                    if (EVP_EncryptUpdate(ctx, encrypted, &len, plaintext, plaintext_len) == 1) {
                        EVP_EncryptFinal_ex(ctx, encrypted + len, &final_len);
                    }
                    
                    delete[] encrypted;
                }
                EVP_CIPHER_CTX_free(ctx);
            }
        }
    }

    // Test hash operations
    if (size > 0) {
        EVP_MD_CTX* ctx = EVP_MD_CTX_new();
        if (ctx) {
            if (EVP_DigestInit_ex(ctx, EVP_sha256(), NULL) == 1) {
                if (EVP_DigestUpdate(ctx, data, size) == 1) {
                    uint8_t hash[32];
                    unsigned int hash_len;
                    EVP_DigestFinal_ex(ctx, hash, &hash_len);
                }
            }
            EVP_MD_CTX_free(ctx);
        }
    }

    // Test HMAC operations
    if (size >= 32) {  // Need at least key
        const uint8_t* key = data;
        const uint8_t* message = data + 32;
        size_t message_len = size - 32;
        
        if (message_len > 0) {
            uint8_t hmac[32];
            unsigned int hmac_len;
            HMAC(EVP_sha256(), key, 32, message, message_len, hmac, &hmac_len);
        }
    }

    return 0;
}
