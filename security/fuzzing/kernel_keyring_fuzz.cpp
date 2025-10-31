#include <cstdint>
#include <cstring>
#include <vector>
#include <unistd.h>
#include <algorithm>
#include <keyutils.h>
#include <gnuradio/linux_crypto/kernel_keyring_source.h>
#include <gnuradio/io_signature.h>

#define MAX_SIZE 8192

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size < sizeof(key_serial_t) || size > MAX_SIZE) {
        return 0;
    }

    // Extract key_id from input
    key_serial_t key_id;
    memcpy(&key_id, data, sizeof(key_serial_t));
    
    // Extract auto_repeat flag from next byte if available
    bool auto_repeat = false;
    if (size > sizeof(key_serial_t)) {
        auto_repeat = (data[sizeof(key_serial_t)] & 0x01) != 0;
    }

    // Create actual GNU Radio block instance
    try {
        auto block = gr::linux_crypto::kernel_keyring_source::make(key_id, auto_repeat);
        
        if (!block) {
            return 0;
        }

        // Test public API methods
        block->is_key_loaded();
        block->get_key_size();
        block->get_key_id();
        block->get_auto_repeat();
        
        // Test the actual work() method with real input/output buffers
        int noutput_items = 1024;
        if (size > sizeof(key_serial_t) + 1) {
            // Use remaining input size as output size (within reason)
            noutput_items = std::min(static_cast<int>(size - sizeof(key_serial_t) - 1), 4096);
        }
        
        unsigned char* output = new unsigned char[noutput_items];
        gr_vector_const_void_star inputs;  // Source block has no inputs
        gr_vector_void_star outputs;
        outputs.push_back(output);
        
        // First: Test with initial auto_repeat value (multiple calls to test state progression)
        int result = block->work(noutput_items, inputs, outputs);
        result = block->work(noutput_items, inputs, outputs);  // Continue state machine
        result = block->work(noutput_items, inputs, outputs);  // Continue state machine
        
        // Second: Test with flipped auto_repeat value (test the other boolean path)
        block->set_auto_repeat(!auto_repeat);
        block->get_auto_repeat();
        
        // Multiple calls with flipped value to ensure both paths are fully exercised
        result = block->work(noutput_items, inputs, outputs);
        result = block->work(noutput_items, inputs, outputs);  // Continue state machine if false
        result = block->work(noutput_items, inputs, outputs);  // Continue state machine if false
        
        // Test reload_key separately (after testing state machine)
        block->reload_key();
        result = block->work(noutput_items, inputs, outputs);
        
        delete[] output;
        
        return 0;
    } catch (...) {
        // Handle any exceptions gracefully
        return 0;
    }
}

int main() {
    uint8_t buf[MAX_SIZE];
    ssize_t len = read(STDIN_FILENO, buf, MAX_SIZE);
    if (len <= 0) return 0;

    return LLVMFuzzerTestOneInput(buf, static_cast<size_t>(len));
}
