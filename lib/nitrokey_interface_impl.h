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

#ifndef INCLUDED_GR_LINUX_CRYPTO_NITROKEY_INTERFACE_IMPL_H
#define INCLUDED_GR_LINUX_CRYPTO_NITROKEY_INTERFACE_IMPL_H

#include <gnuradio/linux_crypto/nitrokey_interface.h>
#include <gnuradio/io_signature.h>
#include <vector>
#include <mutex>
#include <string>

#ifdef HAVE_NITROKEY
// Forward declaration for libnitrokey
namespace nitrokey {
    class NitrokeyManager;
}
#else
// Forward declaration when libnitrokey not available
struct NK_device;
#endif

namespace gr {
namespace linux_crypto {

class nitrokey_interface_impl : public nitrokey_interface
{
private:
    int d_slot;
    bool d_auto_repeat;
    std::vector<unsigned char> d_key_data;
    size_t d_key_size;
    bool d_key_loaded;
    size_t d_key_offset;  // Track position when auto_repeat == false
    bool d_nitrokey_available;
    mutable std::mutex d_mutex;
    int d_connection_check_counter;  // Counter for periodic connection checks

#ifdef HAVE_NITROKEY
    nitrokey::NitrokeyManager* d_nitrokey_manager;
#else
    void* d_device;  // Placeholder when libnitrokey not available
#endif
    std::string d_device_info;

    void connect_to_nitrokey();
    void load_key_from_nitrokey();  // Public: acquires lock
    void load_key_from_nitrokey_unlocked();  // Private: assumes lock is held
    void clear_key_data_unlocked();  // Private: securely clears key data (assumes lock is held)
    void output_key_data(int noutput_items, gr_vector_void_star& output_items);
    bool check_device_connected();  // Private: checks if device is still connected

public:
    nitrokey_interface_impl(int slot, bool auto_repeat);
    ~nitrokey_interface_impl();

    bool is_nitrokey_available() const override;
    bool is_key_loaded() const override;
    size_t get_key_size() const override;
    int get_slot() const override;
    void set_auto_repeat(bool repeat) override;
    bool get_auto_repeat() const override;
    void reload_key() override;
    std::string get_device_info() const override;
    std::vector<int> get_available_slots() const override;

    int work(int noutput_items,
             gr_vector_const_void_star& input_items,
             gr_vector_void_star& output_items) override;
};

} // namespace linux_crypto
} // namespace gr

#endif /* INCLUDED_GR_LINUX_CRYPTO_NITROKEY_INTERFACE_IMPL_H */
