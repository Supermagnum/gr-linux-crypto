#include <cstdint>
#include <cstring>
#include <vector>
#include <unistd.h>
#include <algorithm>
#include <gnuradio/linux_crypto/nitrokey_interface.h>
#include <gnuradio/io_signature.h>

#define MAX_SIZE 8192

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size < 1 || size > MAX_SIZE) {
        return 0;
    }

    // Extract slot number from first byte
    int slot = data[0] % 16;  // Nitrokey has 16 slots (0-15)
    
    // Extract auto_repeat flag from second byte if available
    bool auto_repeat = false;
    if (size > 1) {
        auto_repeat = (data[1] & 0x01) != 0;
    }

    // Create actual GNU Radio block instance
    try {
        auto block = gr::linux_crypto::nitrokey_interface::make(slot, auto_repeat);
        
        if (!block) {
            return 0;
        }

        // Test public API methods
        (void)block->is_nitrokey_available();
        (void)block->is_key_loaded();
        (void)block->get_key_size();
        (void)block->get_slot();
        (void)block->get_auto_repeat();
        (void)block->get_device_info();
        (void)block->get_available_slots();

        // Test the actual work() method
        int noutput_items = 1024;
        if (size > 2) {
            noutput_items = std::min(static_cast<int>(size - 2), 4096);
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
        (void)block->get_auto_repeat();

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
