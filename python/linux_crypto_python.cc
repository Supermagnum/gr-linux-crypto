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

#include <pybind11/pybind11.h>
#include <pybind11/stl.h>
#include <pybind11/functional.h>

#include <gnuradio/linux_crypto/kernel_keyring_source.h>
#include <gnuradio/linux_crypto/nitrokey_interface.h>
#include <gnuradio/linux_crypto/kernel_crypto_aes.h>
#ifdef HAVE_OPENSSL
#include <gnuradio/linux_crypto/brainpool_ecies_encrypt.h>
#include <gnuradio/linux_crypto/brainpool_ecies_decrypt.h>
#include <gnuradio/linux_crypto/brainpool_ecies_multi_encrypt.h>
#include <gnuradio/linux_crypto/brainpool_ecies_multi_decrypt.h>
#endif

namespace py = pybind11;

void bind_kernel_keyring_source(py::module& m)
{
    using kernel_keyring_source = gr::linux_crypto::kernel_keyring_source;

    py::class_<kernel_keyring_source, gr::block, std::shared_ptr<kernel_keyring_source>>(
        m, "kernel_keyring_source")
        .def(py::init(&kernel_keyring_source::make),
             py::arg("key_id"),
             py::arg("auto_repeat") = false)
        .def("is_key_loaded", &kernel_keyring_source::is_key_loaded)
        .def("get_key_size", &kernel_keyring_source::get_key_size)
        .def("get_key_id", &kernel_keyring_source::get_key_id)
        .def("set_auto_repeat", &kernel_keyring_source::set_auto_repeat)
        .def("get_auto_repeat", &kernel_keyring_source::get_auto_repeat)
        .def("reload_key", &kernel_keyring_source::reload_key);
}

void bind_nitrokey_interface(py::module& m)
{
    using nitrokey_interface = gr::linux_crypto::nitrokey_interface;

    py::class_<nitrokey_interface, gr::block, std::shared_ptr<nitrokey_interface>>(
        m, "nitrokey_interface")
        .def(py::init(&nitrokey_interface::make),
             py::arg("slot") = 0,
             py::arg("auto_repeat") = false)
        .def("is_nitrokey_available", &nitrokey_interface::is_nitrokey_available)
        .def("is_key_loaded", &nitrokey_interface::is_key_loaded)
        .def("get_key_size", &nitrokey_interface::get_key_size)
        .def("get_slot", &nitrokey_interface::get_slot)
        .def("set_auto_repeat", &nitrokey_interface::set_auto_repeat)
        .def("get_auto_repeat", &nitrokey_interface::get_auto_repeat)
        .def("reload_key", &nitrokey_interface::reload_key)
        .def("get_device_info", &nitrokey_interface::get_device_info)
        .def("get_available_slots", &nitrokey_interface::get_available_slots);
}

void bind_kernel_crypto_aes(py::module& m)
{
    using kernel_crypto_aes = gr::linux_crypto::kernel_crypto_aes;

    py::class_<kernel_crypto_aes, gr::sync_block, std::shared_ptr<kernel_crypto_aes>>(
        m, "kernel_crypto_aes")
        .def(py::init(&kernel_crypto_aes::make),
             py::arg("key"),
             py::arg("iv"),
             py::arg("mode") = "cbc",
             py::arg("encrypt") = true)
        .def("is_kernel_crypto_available", &kernel_crypto_aes::is_kernel_crypto_available)
        .def("get_key", &kernel_crypto_aes::get_key)
        .def("get_iv", &kernel_crypto_aes::get_iv)
        .def("get_mode", &kernel_crypto_aes::get_mode)
        .def("is_encrypt", &kernel_crypto_aes::is_encrypt)
        .def("set_key", &kernel_crypto_aes::set_key)
        .def("set_iv", &kernel_crypto_aes::set_iv)
        .def("set_mode", &kernel_crypto_aes::set_mode)
        .def("set_encrypt", &kernel_crypto_aes::set_encrypt)
        .def("get_supported_modes", &kernel_crypto_aes::get_supported_modes)
        .def("get_supported_key_sizes", &kernel_crypto_aes::get_supported_key_sizes);
}

#ifdef HAVE_OPENSSL
void bind_brainpool_ecies_encrypt(py::module& m)
{
    using brainpool_ecies_encrypt = gr::linux_crypto::brainpool_ecies_encrypt;

    py::class_<brainpool_ecies_encrypt, gr::sync_block, std::shared_ptr<brainpool_ecies_encrypt>>(
        m, "brainpool_ecies_encrypt")
        .def(py::init(&brainpool_ecies_encrypt::make),
             py::arg("curve") = "brainpoolP256r1",
             py::arg("recipient_public_key_pem") = "",
             py::arg("kdf_info") = "gr-linux-crypto-ecies-v1")
        .def("set_recipient_public_key", &brainpool_ecies_encrypt::set_recipient_public_key)
        .def("get_recipient_public_key", &brainpool_ecies_encrypt::get_recipient_public_key)
        .def("set_kdf_info", &brainpool_ecies_encrypt::set_kdf_info)
        .def("get_kdf_info", &brainpool_ecies_encrypt::get_kdf_info)
        .def("get_curve", &brainpool_ecies_encrypt::get_curve);
}

void bind_brainpool_ecies_decrypt(py::module& m)
{
    using brainpool_ecies_decrypt = gr::linux_crypto::brainpool_ecies_decrypt;

    py::class_<brainpool_ecies_decrypt, gr::sync_block, std::shared_ptr<brainpool_ecies_decrypt>>(
        m, "brainpool_ecies_decrypt")
        .def(py::init(&brainpool_ecies_decrypt::make),
             py::arg("curve") = "brainpoolP256r1",
             py::arg("recipient_private_key_pem") = "",
             py::arg("private_key_password") = "",
             py::arg("kdf_info") = "gr-linux-crypto-ecies-v1")
        .def("set_recipient_private_key", &brainpool_ecies_decrypt::set_recipient_private_key,
             py::arg("private_key_pem"), py::arg("password") = "")
        .def("is_private_key_loaded", &brainpool_ecies_decrypt::is_private_key_loaded)
        .def("set_kdf_info", &brainpool_ecies_decrypt::set_kdf_info)
        .def("get_kdf_info", &brainpool_ecies_decrypt::get_kdf_info)
        .def("get_curve", &brainpool_ecies_decrypt::get_curve);
}

void bind_brainpool_ecies_multi_encrypt(py::module& m)
{
    using brainpool_ecies_multi_encrypt = gr::linux_crypto::brainpool_ecies_multi_encrypt;

    py::class_<brainpool_ecies_multi_encrypt, gr::sync_block, std::shared_ptr<brainpool_ecies_multi_encrypt>>(
        m, "brainpool_ecies_multi_encrypt")
        .def(py::init(&brainpool_ecies_multi_encrypt::make),
             py::arg("curve") = "brainpoolP256r1",
             py::arg("callsigns") = std::vector<std::string>(),
             py::arg("key_store_path") = "",
             py::arg("kdf_info") = "gr-linux-crypto-ecies-v1",
             py::arg("symmetric_cipher") = "aes-gcm")
        .def("set_callsigns", &brainpool_ecies_multi_encrypt::set_callsigns)
        .def("get_callsigns", &brainpool_ecies_multi_encrypt::get_callsigns)
        .def("add_callsign", &brainpool_ecies_multi_encrypt::add_callsign)
        .def("remove_callsign", &brainpool_ecies_multi_encrypt::remove_callsign)
        .def("set_kdf_info", &brainpool_ecies_multi_encrypt::set_kdf_info)
        .def("get_kdf_info", &brainpool_ecies_multi_encrypt::get_kdf_info)
        .def("get_curve", &brainpool_ecies_multi_encrypt::get_curve)
        .def_readonly_static("MAX_RECIPIENTS", &brainpool_ecies_multi_encrypt::MAX_RECIPIENTS);
}

void bind_brainpool_ecies_multi_decrypt(py::module& m)
{
    using brainpool_ecies_multi_decrypt = gr::linux_crypto::brainpool_ecies_multi_decrypt;

    py::class_<brainpool_ecies_multi_decrypt, gr::sync_block, std::shared_ptr<brainpool_ecies_multi_decrypt>>(
        m, "brainpool_ecies_multi_decrypt")
        .def(py::init(&brainpool_ecies_multi_decrypt::make),
             py::arg("curve") = "brainpoolP256r1",
             py::arg("recipient_callsign") = "",
             py::arg("recipient_private_key_pem") = "",
             py::arg("private_key_password") = "",
             py::arg("kdf_info") = "gr-linux-crypto-ecies-v1")
        .def("set_recipient_callsign", &brainpool_ecies_multi_decrypt::set_recipient_callsign)
        .def("get_recipient_callsign", &brainpool_ecies_multi_decrypt::get_recipient_callsign)
        .def("set_recipient_private_key", &brainpool_ecies_multi_decrypt::set_recipient_private_key,
             py::arg("private_key_pem"), py::arg("password") = "")
        .def("is_private_key_loaded", &brainpool_ecies_multi_decrypt::is_private_key_loaded)
        .def("set_kdf_info", &brainpool_ecies_multi_decrypt::set_kdf_info)
        .def("get_kdf_info", &brainpool_ecies_multi_decrypt::get_kdf_info)
        .def("get_curve", &brainpool_ecies_multi_decrypt::get_curve);
}
#endif

PYBIND11_MODULE(linux_crypto_python, m)
{
    m.doc() = "GNU Radio Linux Crypto Python bindings";

    // Bind the classes
    bind_kernel_keyring_source(m);
    bind_nitrokey_interface(m);
    bind_kernel_crypto_aes(m);
#ifdef HAVE_OPENSSL
    bind_brainpool_ecies_encrypt(m);
    bind_brainpool_ecies_decrypt(m);
    bind_brainpool_ecies_multi_encrypt(m);
    bind_brainpool_ecies_multi_decrypt(m);
#endif

    // Add module-level functions
    m.def("get_integration_status", []() {
        py::dict status;
        status["kernel_keyring_available"] = true;
        status["nitrokey_available"] = true;
        status["kernel_crypto_available"] = true;
        return status;
    });
}