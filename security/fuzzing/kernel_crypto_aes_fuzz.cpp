#include <cstdint>
#include <cstring>
#include <vector>
#include <string>
#include <unistd.h>
#include <algorithm>
#include <gnuradio/linux_crypto/kernel_crypto_aes.h>
#include <gnuradio/io_signature.h>

#define MAX_SIZE 8192

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    // Need at least key (16, 24, or 32 bytes) + optional mode byte
    if (size < 16 || size > MAX_SIZE) {
        return 0;
    }

    // Determine key size: use first 16, 24, or 32 bytes
    size_t key_size = 16;
    if (size >= 24) {
        key_size = (data[0] % 3 == 0) ? 24 : 16;
    }
    if (size >= 32 && data[0] % 3 == 1) {
        key_size = 32;
    }
    key_size = std::min(key_size, size);

    // Extract key
    std::vector<unsigned char> key(data, data + key_size);
    
    // Extract IV (16 bytes) if available
    std::vector<unsigned char> iv;
    if (size >= key_size + 16) {
        iv.assign(data + key_size, data + key_size + 16);
    } else if (size > key_size) {
        // Partial IV, pad with zeros
        iv.assign(data + key_size, data + size);
        iv.resize(16, 0);
    } else {
        iv.resize(16, 0);
    }

    // Determine mode from input
    std::string mode = "cbc(aes)";
    if (size > key_size + 16) {
        uint8_t mode_selector = data[key_size + 16] % 4;
        switch (mode_selector) {
            case 0: mode = "cbc(aes)"; break;
            case 1: mode = "ecb(aes)"; break;
            case 2: mode = "ctr(aes)"; break;
            case 3: mode = "gcm(aes)"; break;
        }
    }

    // Determine encrypt/decrypt flag
    bool encrypt = true;
    if (size > key_size + 16) {
        encrypt = (data[key_size + 16] & 0x01) == 0;
    }

    // Create actual GNU Radio block instance
    try {
        auto block = gr::linux_crypto::kernel_crypto_aes::make(key, iv, mode, encrypt);
        
        if (!block) {
            return 0;
        }

        // Test public API methods
        (void)block->is_kernel_crypto_available();
        (void)block->get_key();
        (void)block->get_iv();
        (void)block->get_mode();
        (void)block->is_encrypt();
        (void)block->get_supported_modes();
        (void)block->get_supported_key_sizes();

        // Prepare input data for work() method
        size_t input_size = 1024;
        if (size > key_size + 16 + 1) {
            input_size = std::min(size - key_size - 16 - 1, static_cast<size_t>(4096));
            // Pad to block size for AES
            input_size = ((input_size + 15) / 16) * 16;
        }

        unsigned char* input = new unsigned char[input_size];
        unsigned char* output = new unsigned char[input_size];
        
        // Fill input with remaining fuzzer data or zeros
        if (size > key_size + 16 + 1) {
            size_t copy_len = std::min(input_size, size - key_size - 16 - 1);
            memcpy(input, data + key_size + 16 + 1, copy_len);
            if (input_size > copy_len) {
                memset(input + copy_len, 0, input_size - copy_len);
            }
        } else {
            memset(input, 0, input_size);
        }

        gr_vector_const_void_star inputs;
        inputs.push_back(input);
        gr_vector_void_star outputs;
        outputs.push_back(output);

        // Call actual work() method
        int result = block->work(static_cast<int>(input_size), inputs, outputs);

        // Test setter methods
        if (key_size == 32) {
            std::vector<unsigned char> new_key(key.begin(), key.begin() + 16);
            block->set_key(new_key);
        }
        
        if (!iv.empty()) {
            std::vector<unsigned char> new_iv(iv.begin(), iv.begin() + std::min(iv.size(), size_t(16)));
            block->set_iv(new_iv);
        }

        block->set_mode("ecb(aes)");
        block->set_encrypt(!encrypt);

        // Call work() again with modified parameters
        result = block->work(static_cast<int>(input_size), inputs, outputs);

        delete[] input;
        delete[] output;

        return 0;
    } catch (...) {
        // Handle exceptions gracefully
        return 0;
    }
}

int main() {
    uint8_t buf[MAX_SIZE];
    ssize_t len = read(STDIN_FILENO, buf, MAX_SIZE);
    if (len <= 0) return 0;

    return LLVMFuzzerTestOneInput(buf, static_cast<size_t>(len));
}
