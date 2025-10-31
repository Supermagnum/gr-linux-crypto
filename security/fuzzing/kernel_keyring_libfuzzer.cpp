#include <cstdint>
#include <cstddef>
#include <cstring>
#include <vector>
#include <algorithm>
#include <keyutils.h>
#include <gnuradio/linux_crypto/kernel_keyring_source.h>
#include <gnuradio/io_signature.h>

// LibFuzzer entry point
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size < sizeof(key_serial_t) || size > 1024) {
        return 0; // Reject invalid sizes
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
        (void)block->is_key_loaded();
        (void)block->get_key_size();
        (void)block->get_key_id();
        (void)block->get_auto_repeat();
        
        // Test the actual work() method with multiple calls to exercise state machine
        int noutput_items = 512;
        if (size > sizeof(key_serial_t) + 1) {
            noutput_items = std::min(static_cast<int>(size - sizeof(key_serial_t) - 1), 2048);
        }
        
        unsigned char* output = new unsigned char[noutput_items];
        gr_vector_const_void_star inputs;
        gr_vector_void_star outputs;
        outputs.push_back(output);
        
        // First: Test with initial auto_repeat value (multiple calls to test state progression)
        (void)block->work(noutput_items, inputs, outputs);
        (void)block->work(noutput_items, inputs, outputs);  // Continue state machine
        (void)block->work(noutput_items, inputs, outputs);  // Continue state machine
        
        // Second: Test with flipped auto_repeat value (test the other boolean path)
        block->set_auto_repeat(!auto_repeat);
        
        // Multiple calls with flipped value to ensure both paths are fully exercised
        (void)block->work(noutput_items, inputs, outputs);
        (void)block->work(noutput_items, inputs, outputs);  // Continue state machine if false
        (void)block->work(noutput_items, inputs, outputs);  // Continue state machine if false
        
        // Test reload_key separately (after testing state machine)
        block->reload_key();
        (void)block->work(noutput_items, inputs, outputs);
        
        delete[] output;
        
        return 0;
    } catch (...) {
        // Handle exceptions gracefully
        return 0;
    }
}
