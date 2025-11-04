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
#include "kernel_keyring_source_impl.h"
#include <cstring>
#include <stdexcept>

namespace gr {
namespace linux_crypto {

/**
 * @brief Create a kernel keyring source block
 * @param key_id The key ID to read from the kernel keyring
 * @param auto_repeat Whether to repeat the key data to fill output
 * @return Shared pointer to the kernel keyring source block
 */
kernel_keyring_source::sptr
kernel_keyring_source::make(key_serial_t key_id, bool auto_repeat)
{
    return gnuradio::get_initial_sptr(
        new kernel_keyring_source_impl(key_id, auto_repeat));
}

/**
 * @brief Constructor for kernel keyring source implementation
 * @param key_id The key ID to read from the kernel keyring
 * @param auto_repeat Whether to repeat the key data to fill output
 */
kernel_keyring_source_impl::kernel_keyring_source_impl(key_serial_t key_id, bool auto_repeat)
    : gr::sync_block("kernel_keyring_source",
                     gr::io_signature::make(0, 0, 0),
                     gr::io_signature::make(1, 1, sizeof(unsigned char))),
      d_key_id(key_id),
      d_auto_repeat(auto_repeat),
      d_key_size(0),
      d_key_loaded(false),
      d_key_offset(0),
      d_key_check_counter(0)
{
    load_key_from_keyring();
}

kernel_keyring_source_impl::~kernel_keyring_source_impl()
{
    // Clear key data from memory
    if (!d_key_data.empty()) {
        memset(d_key_data.data(), 0, d_key_data.size());
    }
}

/**
 * Load key data from the kernel keyring using keyctl system call.
 */
void
kernel_keyring_source_impl::load_key_from_keyring()
{
    std::lock_guard<std::mutex> lock(d_mutex);
    
    // Get key size first
    long key_size = keyctl(KEYCTL_READ, d_key_id, nullptr, 0);
    if (key_size < 0) {
        d_key_loaded = false;
        d_key_size = 0;
        d_key_data.clear();
        d_key_offset = 0;
        return;
    }
    
    d_key_size = static_cast<size_t>(key_size);
    d_key_data.resize(d_key_size);
    
    // Read the actual key data
    long bytes_read = keyctl(KEYCTL_READ, d_key_id, d_key_data.data(), d_key_size);
    if (bytes_read < 0 || static_cast<size_t>(bytes_read) != d_key_size) {
        d_key_loaded = false;
        d_key_size = 0;
        d_key_data.clear();
        d_key_offset = 0;
        return;
    }
    
    d_key_loaded = true;
    d_key_offset = 0;  // Reset offset when key is reloaded
}

bool
kernel_keyring_source_impl::is_key_loaded() const
{
    std::lock_guard<std::mutex> lock(d_mutex);
    return d_key_loaded;
}

size_t
kernel_keyring_source_impl::get_key_size() const
{
    std::lock_guard<std::mutex> lock(d_mutex);
    return d_key_size;
}

key_serial_t
kernel_keyring_source_impl::get_key_id() const
{
    return d_key_id;
}

void
kernel_keyring_source_impl::set_auto_repeat(bool repeat)
{
    d_auto_repeat = repeat;
}

bool
kernel_keyring_source_impl::get_auto_repeat() const
{
    return d_auto_repeat;
}

void
kernel_keyring_source_impl::reload_key()
{
    {
        std::lock_guard<std::mutex> lock(d_mutex);
        d_key_offset = 0;  // Reset offset before reloading
    }
    // Lock is automatically released here, then load_key_from_keyring() will lock again
    load_key_from_keyring();
}

void
kernel_keyring_source_impl::clear_key_data_unlocked()
{
    // Note: This function assumes d_mutex is already locked by caller
    // Securely clear key data from memory
    if (!d_key_data.empty()) {
        memset(d_key_data.data(), 0, d_key_data.size());
    }
    d_key_data.clear();
    d_key_size = 0;
    d_key_loaded = false;
    d_key_offset = 0;
}

bool
kernel_keyring_source_impl::check_key_exists()
{
    // Check if key still exists in kernel keyring
    // Returns true if key exists, false if removed
    long key_size = keyctl(KEYCTL_READ, d_key_id, nullptr, 0);
    if (key_size < 0) {
        // Key doesn't exist or was removed
        return false;
    }
    return true;
}

/**
 * Output key data from kernel keyring.
 * If auto_repeat enabled, repeats key to fill output.
 * If auto_repeat disabled, outputs key exactly once, then zeros.
 */
int
kernel_keyring_source_impl::work(int noutput_items,
                                 gr_vector_const_void_star& input_items,
                                 gr_vector_void_star& output_items)
{
    unsigned char* out = (unsigned char*)output_items[0];
    
    // Periodically check if key still exists in keyring (every 1000 work() calls)
    // This balances security with performance
    d_key_check_counter++;
    bool should_check_key = (d_key_check_counter % 1000 == 0);

    if (should_check_key && d_key_loaded) {
        std::lock_guard<std::mutex> lock(d_mutex);
        if (!check_key_exists()) {
            // Key removed from keyring - clear cached key data immediately
            clear_key_data_unlocked();
        }
    }
    
    if (!d_key_loaded || d_key_data.empty()) {
        // No key loaded, output zeros
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
