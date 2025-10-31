#ifndef INCLUDED_BRAINPOOL_EC_IMPL_H
#define INCLUDED_BRAINPOOL_EC_IMPL_H

#include <gnuradio/linux_crypto/api.h>
#include <openssl/obj_mac.h>
#include <string>
#include <vector>
#include <memory>
#include <openssl/ec.h>
#include <openssl/evp.h>
#include <openssl/err.h>

namespace gr {
namespace linux_crypto {

class LINUX_CRYPTO_API brainpool_ec_impl
{
public:
    enum class Curve {
        BRAINPOOLP256R1,
        BRAINPOOLP384R1,
        BRAINPOOLP512R1
    };

    struct KeyPair {
        EVP_PKEY* private_key;
        EVP_PKEY* public_key;
    };

    brainpool_ec_impl(Curve curve = Curve::BRAINPOOLP256R1);
    ~brainpool_ec_impl();

    // Disable copy and assignment
    brainpool_ec_impl(const brainpool_ec_impl&) = delete;
    brainpool_ec_impl& operator=(const brainpool_ec_impl&) = delete;

    // Key generation
    KeyPair generate_keypair();
    static KeyPair generate_keypair(Curve curve);

    // ECDH key exchange
    std::vector<uint8_t> ecdh_exchange(EVP_PKEY* private_key, EVP_PKEY* peer_public_key);

    // ECDSA signing
    std::vector<uint8_t> sign(const std::vector<uint8_t>& data, EVP_PKEY* private_key);
    std::vector<uint8_t> sign(const uint8_t* data, size_t data_len, EVP_PKEY* private_key);

    // ECDSA verification
    bool verify(const std::vector<uint8_t>& data,
                const std::vector<uint8_t>& signature,
                EVP_PKEY* public_key);
    bool verify(const uint8_t* data, size_t data_len,
                const uint8_t* signature, size_t sig_len,
                EVP_PKEY* public_key);

    // Key serialization
    std::vector<uint8_t> serialize_public_key(EVP_PKEY* public_key);
    std::vector<uint8_t> serialize_private_key(EVP_PKEY* private_key, 
                                              const std::string& password = "");

    // Key deserialization
    EVP_PKEY* load_public_key(const std::vector<uint8_t>& pem_data);
    EVP_PKEY* load_private_key(const std::vector<uint8_t>& pem_data,
                              const std::string& password = "");

    // Curve management
    void set_curve(Curve curve);
    Curve get_curve() const { return d_curve; }
    static std::string curve_to_string(Curve curve);
    static Curve string_to_curve(const std::string& curve_name);

    // Get supported curves
    static std::vector<std::string> get_supported_curves();

private:
    Curve d_curve;
    EC_GROUP* d_group;

    static EC_GROUP* create_curve_group(Curve curve);
    static void print_openssl_error();
};

} // namespace linux_crypto
} // namespace gr

#endif /* INCLUDED_BRAINPOOL_EC_IMPL_H */

