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

#ifdef HAVE_NITROKEY
#include <libnitrokey/NitrokeyManager.h>
#include <libnitrokey/DeviceCommunicationExceptions.h>
#include <libnitrokey/CommandFailedException.h>
#include <libnitrokey/Command.h>
#endif

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
      d_connection_check_counter(0)
#ifdef HAVE_NITROKEY
      , d_nitrokey_manager(nullptr)
#else
      , d_device(nullptr)
#endif
{
    connect_to_nitrokey();
    if (d_nitrokey_available) {
        // Use unlocked version since constructor runs before other threads can access
        std::lock_guard<std::mutex> lock(d_mutex);
        load_key_from_nitrokey_unlocked();
    }
}

nitrokey_interface_impl::~nitrokey_interface_impl()
{
    // Clear key data from memory
    if (!d_key_data.empty()) {
        memset(d_key_data.data(), 0, d_key_data.size());
    }

#ifdef HAVE_NITROKEY
    // NitrokeyManager is a singleton, don't delete it
    // Just release our reference
    d_nitrokey_manager = nullptr;
#else
    // Disconnect from Nitrokey placeholder
    d_device = nullptr;
#endif
}

void
nitrokey_interface_impl::connect_to_nitrokey()
{
    std::lock_guard<std::mutex> lock(d_mutex);

#ifdef HAVE_NITROKEY
    try {
        // Get NitrokeyManager singleton instance (returns shared_ptr)
        d_nitrokey_manager = nitrokey::NitrokeyManager::instance().get();
        
        if (d_nitrokey_manager) {
            // Try to connect to a Nitrokey device
            auto devices = d_nitrokey_manager->list_devices();
            
            if (!devices.empty()) {
                // Found at least one device, try to connect
                // Connect to first available device
                bool connected = d_nitrokey_manager->connect();
                
                if (connected && d_nitrokey_manager->is_connected()) {
                    d_nitrokey_available = true;
                    
                    // Get device info
                    try {
                        auto model = d_nitrokey_manager->get_connected_device_model();
                        if (model == nitrokey::device::DeviceModel::PRO) {
                            d_device_info = "Nitrokey Pro";
                        } else if (model == nitrokey::device::DeviceModel::STORAGE) {
                            d_device_info = "Nitrokey Storage";
                        } else {
                            d_device_info = "Nitrokey (connected)";
                        }
                    } catch (...) {
                        d_device_info = "Nitrokey (connected)";
                    }
                } else {
                    // Devices found but connection failed
                    d_nitrokey_available = false;
                    d_device_info = "Nitrokey (connection failed)";
                }
            } else {
                // No devices found
                d_nitrokey_available = false;
                d_device_info = "Nitrokey (no device found)";
            }
        } else {
            d_nitrokey_available = false;
            d_device_info = "Nitrokey (manager unavailable)";
        }
    } catch (const nitrokey::DeviceNotConnectedException&) {
        d_nitrokey_available = false;
        d_device_info = "Nitrokey (not connected)";
    } catch (const std::exception& e) {
        d_nitrokey_available = false;
        d_device_info = std::string("Nitrokey (error: ") + e.what() + ")";
    } catch (...) {
        d_nitrokey_available = false;
        d_device_info = "Nitrokey (unknown error)";
    }
#else
    // libnitrokey not available at compile time
    d_nitrokey_available = false;
    d_device_info = "Nitrokey (libnitrokey not available - rebuild with libnitrokey)";
#endif
}

void
nitrokey_interface_impl::load_key_from_nitrokey()
{
    std::lock_guard<std::mutex> lock(d_mutex);
    load_key_from_nitrokey_unlocked();
}

void
nitrokey_interface_impl::load_key_from_nitrokey_unlocked()
{
    // Note: This function assumes d_mutex is already locked by caller
    if (!d_nitrokey_available) {
        d_key_loaded = false;
        d_key_size = 0;
        d_key_data.clear();
        d_key_offset = 0;
        return;
    }

#ifdef HAVE_NITROKEY
    if (!d_nitrokey_manager) {
        d_key_loaded = false;
        d_key_size = 0;
        d_key_data.clear();
        d_key_offset = 0;
        return;
    }

    try {
        // Validate slot number (Nitrokey devices typically have 16 slots: 0-15)
        if (d_slot < 0 || d_slot > 15) {
            d_key_loaded = false;
            d_key_size = 0;
            d_key_data.clear();
            d_key_offset = 0;
            return;
        }

        // Read password safe slot (Nitrokey stores passwords in slots)
        // libnitrokey API: get_password_safe_slot_password() returns char*
        // The returned pointer is owned by libnitrokey and may be freed on next call
        // We need to copy the data immediately
        
        char* password_ptr = d_nitrokey_manager->get_password_safe_slot_password(static_cast<uint8_t>(d_slot));
        
        if (password_ptr && password_ptr[0] != '\0') {
            // Copy password data to string (libnitrokey owns the pointer)
            std::string password = password_ptr;
            
            if (!password.empty()) {
                // Copy password data to key buffer
                d_key_data.resize(password.size());
                memcpy(d_key_data.data(), password.c_str(), password.size());
                d_key_size = password.size();
                d_key_loaded = true;
                d_key_offset = 0;
            } else {
                // Empty password
                d_key_loaded = false;
                d_key_size = 0;
                d_key_data.clear();
                d_key_offset = 0;
            }
        } else {
            // Slot doesn't exist or is empty
            d_key_loaded = false;
            d_key_size = 0;
            d_key_data.clear();
            d_key_offset = 0;
        }
    } catch (const nitrokey::DeviceNotConnectedException&) {
        d_nitrokey_available = false;
        d_key_loaded = false;
        d_key_size = 0;
        d_key_data.clear();
        d_key_offset = 0;
    } catch (const std::exception&) {
        d_key_loaded = false;
        d_key_size = 0;
        d_key_data.clear();
        d_key_offset = 0;
    } catch (...) {
        d_key_loaded = false;
        d_key_size = 0;
        d_key_data.clear();
        d_key_offset = 0;
    }
#else
    // libnitrokey not available at compile time
    d_key_loaded = false;
    d_key_size = 0;
    d_key_data.clear();
    d_key_offset = 0;
#endif
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
    std::lock_guard<std::mutex> lock(d_mutex);
    d_key_offset = 0;  // Reset offset before reloading
    // Call unlocked version since we already hold the lock
    load_key_from_nitrokey_unlocked();
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

    std::vector<int> slots;

    if (!d_nitrokey_available) {
        return slots;  // Return empty vector
    }

#ifdef HAVE_NITROKEY
    if (!d_nitrokey_manager) {
        return slots;  // Return empty vector
    }

    try {
        // Nitrokey devices have 16 password safe slots (0-15)
        // Use get_password_safe_slot_status() to check which slots are populated
        // Note: This may throw if password safe is not enabled or requires authentication
        auto slot_status = d_nitrokey_manager->get_password_safe_slot_status();
        
        // slot_status is a vector<uint8_t> where each byte indicates slot status
        // Check slots 0-15 (up to size of status vector)
        for (size_t i = 0; i < slot_status.size() && i < 16; i++) {
            if (slot_status[i] != 0) {
                // Slot is populated, verify it has a password
                try {
                    char* password_ptr = d_nitrokey_manager->get_password_safe_slot_password(static_cast<uint8_t>(i));
                    if (password_ptr && password_ptr[0] != '\0') {
                        slots.push_back(static_cast<int>(i));
                    }
                } catch (...) {
                    // Skip this slot if password retrieval fails (may require authentication)
                    continue;
                }
            }
        }
    } catch (const nitrokey::DeviceNotConnectedException&) {
        // Device disconnected, return empty
    } catch (const nitrokey::CommandFailedException&) {
        // Password safe may be disabled or requires authentication
        // Return empty vector - device is connected but password safe unavailable
    } catch (const std::exception&) {
        // Other exceptions (e.g., password safe not enabled)
        // Return empty vector - device detected but slots not accessible
    } catch (...) {
        // Unknown error accessing slots, return empty
    }
#else
    // libnitrokey not available - return empty vector
#endif

    return slots;
}

void
nitrokey_interface_impl::clear_key_data_unlocked()
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
    d_nitrokey_available = false;
}

bool
nitrokey_interface_impl::check_device_connected()
{
    // Check if Nitrokey device is still connected
    // Returns true if connected, false if disconnected
#ifdef HAVE_NITROKEY
    if (!d_nitrokey_manager) {
        return false;
    }
    
    try {
        // Check if device is still connected
        if (d_nitrokey_manager->is_connected()) {
            return true;
        }
        return false;
    } catch (const nitrokey::DeviceNotConnectedException&) {
        return false;
    } catch (...) {
        // Unknown error, assume disconnected
        return false;
    }
#else
    return false;
#endif
}

int
nitrokey_interface_impl::work(int noutput_items,
                              gr_vector_const_void_star& input_items,
                              gr_vector_void_star& output_items)
{
    unsigned char* out = (unsigned char*)output_items[0];

    // Periodically check if device is still connected (every 1000 work() calls)
    // This balances security with performance
    d_connection_check_counter++;
    bool should_check_connection = (d_connection_check_counter % 1000 == 0);

    if (should_check_connection && d_key_loaded) {
        std::lock_guard<std::mutex> lock(d_mutex);
        if (!check_device_connected()) {
            // Device disconnected - clear cached key data immediately
            clear_key_data_unlocked();
            d_device_info = "Nitrokey (disconnected)";
        }
    }

    if (!d_nitrokey_available || !d_key_loaded || d_key_data.empty()) {
        // No Nitrokey or key loaded, output zeros
        memset(out, 0, noutput_items);
        return noutput_items;
    }

#ifdef HAVE_NITROKEY
    // Verify device manager pointer is valid
    if (!d_nitrokey_manager) {
        memset(out, 0, noutput_items);
        return noutput_items;
    }
#endif

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
