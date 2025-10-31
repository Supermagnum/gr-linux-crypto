/* -*- c++ -*- */
/*
 * Copyright 2024
 *
 * This file is part of gr-linux-crypto.
 *
 * gr-linux-crypto is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3, or (at your option)
 * any later version.
 *
 * gr-linux-crypto is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with gr-linux-crypto; see the file COPYING.  If not, write to
 * the Free Software Foundation, Inc., 51 Franklin Street,
 * Boston, MA 02110-1301, USA.
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <gnuradio/io_signature.h>
#include "nitrokey_interface_impl.h"
#include <cstring>
#include <stdexcept>

// Note: Framework implementation - libnitrokey integration pending
// Real implementation would use libnitrokey headers
// #include <libnitrokey/NitrokeyManager.h>

namespace gr {
namespace linux_crypto {

nitrokey_interface::sptr
nitrokey_interface::make(int slot, bool auto_repeat)
{
    return gnuradio::get_initial_sptr(
        new nitrokey_interface_impl(slot, auto_repeat));
}

nitrokey_interface_impl::nitrokey_interface_impl(int slot, bool auto_repeat)
    : gr::sync_block("nitrokey_interface",
                     gr::io_signature::make(0, 0, 0),
                     gr::io_signature::make(1, 1, sizeof(unsigned char))),
      d_slot(slot),
      d_auto_repeat(auto_repeat),
      d_key_size(0),
      d_key_loaded(false),
      d_key_offset(0),
      d_nitrokey_available(false),
      d_device(nullptr)
{
    connect_to_nitrokey();
    if (d_nitrokey_available) {
        load_key_from_nitrokey();
    }
}

nitrokey_interface_impl::~nitrokey_interface_impl()
{
    // Clear key data from memory
    if (!d_key_data.empty()) {
        memset(d_key_data.data(), 0, d_key_data.size());
    }

    // Disconnect from Nitrokey
    if (d_device) {
        // Real implementation would call libnitrokey disconnect
        d_device = nullptr;
    }
}

void
nitrokey_interface_impl::connect_to_nitrokey()
{
    std::lock_guard<std::mutex> lock(d_mutex);

    // Framework implementation - requires libnitrokey for full functionality
    // This provides the interface structure; actual Nitrokey integration requires:
    // 1. libnitrokey library integration
    // 2. Device connection handling
    // 3. Slot management
    // 4. Key storage/retrieval operations
    
    // Current status: Framework ready, awaiting libnitrokey integration
    // When libnitrokey is available, implement as follows:
    //   1. Initialize libnitrokey: NK_initialize();
    //   2. Connect: NK_device* device = NK_connect();
    //   3. Check connection: if (device) { ... }
    //   4. Get device info: d_device_info = NK_get_device_info(device);
    //   5. Set d_nitrokey_available = true if connection succeeds
    
    d_nitrokey_available = false;
    d_device_info = "Nitrokey (framework - libnitrokey integration pending)";
}

void
nitrokey_interface_impl::load_key_from_nitrokey()
{
    std::lock_guard<std::mutex> lock(d_mutex);

    if (!d_nitrokey_available || !d_device) {
        d_key_loaded = false;
        d_key_size = 0;
        return;
    }

    // Framework implementation - requires libnitrokey for full functionality
    // This provides the interface structure; actual key loading requires:
    // 1. libnitrokey NK_read_slot_data() calls
    // 2. Slot validation and error handling
    // 3. Key integrity verification
    
    // Current status: Framework ready, awaiting libnitrokey integration
    // When libnitrokey is available, implement as follows:
    //   1. Get slot size: size_t key_size = NK_get_slot_data_size(d_device, d_slot);
    //   2. Validate: if (key_size > 0 && key_size <= MAX_KEY_SIZE) { ... }
    //   3. Allocate: d_key_data.resize(key_size);
    //   4. Read data: if (NK_read_slot_data(d_device, d_slot, d_key_data.data(), key_size)) {
    //   5. Set state: d_key_size = key_size; d_key_loaded = true;
    
    // Framework implementation: No key loaded until libnitrokey is integrated
    d_key_size = 0;
    d_key_data.clear();
    d_key_loaded = false;
    d_key_offset = 0;
}

bool
nitrokey_interface_impl::is_nitrokey_available() const
{
    std::lock_guard<std::mutex> lock(d_mutex);
    return d_nitrokey_available;
}

bool
nitrokey_interface_impl::is_key_loaded() const
{
    std::lock_guard<std::mutex> lock(d_mutex);
    return d_key_loaded;
}

size_t
nitrokey_interface_impl::get_key_size() const
{
    std::lock_guard<std::mutex> lock(d_mutex);
    return d_key_size;
}

int
nitrokey_interface_impl::get_slot() const
{
    return d_slot;
}

void
nitrokey_interface_impl::set_auto_repeat(bool repeat)
{
    d_auto_repeat = repeat;
}

bool
nitrokey_interface_impl::get_auto_repeat() const
{
    return d_auto_repeat;
}

void
nitrokey_interface_impl::reload_key()
{
    {
        std::lock_guard<std::mutex> lock(d_mutex);
        d_key_offset = 0;  // Reset offset before reloading
    }
    // Lock is automatically released here, then load_key_from_nitrokey() will lock again
    load_key_from_nitrokey();
}

std::string
nitrokey_interface_impl::get_device_info() const
{
    std::lock_guard<std::mutex> lock(d_mutex);
    return d_device_info;
}

std::vector<int>
nitrokey_interface_impl::get_available_slots() const
{
    std::lock_guard<std::mutex> lock(d_mutex);

    // Framework implementation - requires libnitrokey for full functionality
    std::vector<int> slots;

    if (d_nitrokey_available) {
        // When libnitrokey is integrated, replace with:
        // return NK_get_available_slots(d_device);
        // Standard Nitrokey devices support 16 slots (0-15)
        // This is framework placeholder until libnitrokey integration
        for (int i = 0; i < 16; i++) {
            slots.push_back(i);
        }
    }

    return slots;
}

int
nitrokey_interface_impl::work(int noutput_items,
                              gr_vector_const_void_star& input_items,
                              gr_vector_void_star& output_items)
{
    unsigned char* out = (unsigned char*)output_items[0];

    if (!d_nitrokey_available || !d_key_loaded || d_key_data.empty()) {
        // No Nitrokey or key loaded, output zeros
        memset(out, 0, noutput_items);
        return noutput_items;
    }

    std::lock_guard<std::mutex> lock(d_mutex);

    if (d_auto_repeat) {
        // Repeat key data to fill output
        for (int i = 0; i < noutput_items; i++) {
            out[i] = d_key_data[i % d_key_data.size()];
        }
    } else {
        // Output key data exactly once across all work() calls, then zeros
        size_t remaining_key = (d_key_offset < d_key_data.size()) 
                                ? (d_key_data.size() - d_key_offset) 
                                : 0;
        
        if (remaining_key > 0) {
            // Still have key data to output
            size_t key_bytes_to_output = std::min(static_cast<size_t>(noutput_items), remaining_key);
            memcpy(out, d_key_data.data() + d_key_offset, key_bytes_to_output);
            d_key_offset += key_bytes_to_output;
            
            // Fill remaining with zeros if needed
            if (noutput_items > static_cast<int>(key_bytes_to_output)) {
                memset(out + key_bytes_to_output, 0, noutput_items - key_bytes_to_output);
            }
        } else {
            // Entire key has been output, output zeros
            memset(out, 0, noutput_items);
        }
    }

    return noutput_items;
}

} // namespace linux_crypto
} // namespace gr
