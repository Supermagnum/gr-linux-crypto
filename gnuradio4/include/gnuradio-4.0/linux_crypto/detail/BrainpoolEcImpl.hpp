// SPDX-License-Identifier: GPL-3.0-or-later
#ifndef GNURADIO4_LINUX_CRYPTO_DETAIL_BRAINPOOLECIMPL_HPP
#define GNURADIO4_LINUX_CRYPTO_DETAIL_BRAINPOOLECIMPL_HPP

#include <openssl/evp.h>
#include <openssl/obj_mac.h>

#include <openssl/ec.h>

#include <memory>
#include <string>
#include <vector>

namespace gnuradio4::linux_crypto {

/** OpenSSL-backed Brainpool EC primitives (adapted from gr-linux-crypto). */
class BrainpoolEcImpl {
public:
    enum class Curve { BRAINPOOLP256R1, BRAINPOOLP384R1, BRAINPOOLP512R1 };

    struct KeyPair {
        EVP_PKEY* private_key;
        EVP_PKEY* public_key;
    };

    explicit BrainpoolEcImpl(Curve curve = Curve::BRAINPOOLP256R1);
    ~BrainpoolEcImpl();

    BrainpoolEcImpl(const BrainpoolEcImpl&)            = delete;
    BrainpoolEcImpl& operator=(const BrainpoolEcImpl&) = delete;

    [[nodiscard]] KeyPair              generate_keypair();
    [[nodiscard]] static KeyPair       generate_keypair(Curve curve);
    [[nodiscard]] std::vector<uint8_t> ecdh_exchange(EVP_PKEY* private_key, EVP_PKEY* peer_public_key);

    [[nodiscard]] std::vector<uint8_t> sign(const std::vector<uint8_t>& data, EVP_PKEY* private_key);
    [[nodiscard]] std::vector<uint8_t> sign(const uint8_t* data, size_t data_len, EVP_PKEY* private_key);
    [[nodiscard]] std::vector<uint8_t> sign(const uint8_t* data, size_t data_len, EVP_PKEY* private_key, const EVP_MD* md);

    [[nodiscard]] bool verify(const std::vector<uint8_t>& data, const std::vector<uint8_t>& signature, EVP_PKEY* public_key);
    [[nodiscard]] bool verify(const uint8_t* data, size_t data_len, const uint8_t* signature, size_t sig_len, EVP_PKEY* public_key);
    [[nodiscard]] bool verify(const uint8_t* data, size_t data_len, const uint8_t* signature, size_t sig_len, EVP_PKEY* public_key,
        const EVP_MD* md);

    [[nodiscard]] static std::vector<uint8_t> serialize_public_key(EVP_PKEY* public_key);
    [[nodiscard]] std::vector<uint8_t>        serialize_private_key(EVP_PKEY* private_key, const std::string& password = "");

    [[nodiscard]] static EVP_PKEY* load_public_key(const std::vector<uint8_t>& pem_data);
    [[nodiscard]] static EVP_PKEY* load_private_key(const std::vector<uint8_t>& pem_data, const std::string& password = "");

    void                               set_curve(Curve curve);
    [[nodiscard]] Curve get_curve() const { return d_curve; }
    [[nodiscard]] static std::string   curve_to_string(Curve curve);
    [[nodiscard]] static Curve        string_to_curve(const std::string& curve_name);
    [[nodiscard]] static std::vector<std::string> get_supported_curves();

private:
    Curve     d_curve{};
    EC_GROUP* d_group{nullptr};

    [[nodiscard]] static EC_GROUP* create_curve_group(Curve curve);
    static void                    print_openssl_error();
};

} // namespace gnuradio4::linux_crypto

#endif
