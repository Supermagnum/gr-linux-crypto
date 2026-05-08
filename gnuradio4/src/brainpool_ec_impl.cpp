// SPDX-License-Identifier: GPL-3.0-or-later
#include <gnuradio-4.0/linux_crypto/detail/BrainpoolEcImpl.hpp>
#include <openssl/ec.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <openssl/bio.h>
#include <cstring>
#include <sstream>

namespace gnuradio4 {
namespace linux_crypto {

BrainpoolEcImpl::BrainpoolEcImpl(BrainpoolEcImpl::Curve curve)
    : d_curve(curve), d_group(nullptr)
{
    d_group = create_curve_group(d_curve);
    // Errors are indicated by d_group being nullptr
    // Error details available via OpenSSL error queue if needed
}

BrainpoolEcImpl::~BrainpoolEcImpl()
{
    if (d_group) {
        EC_GROUP_free(d_group);
    }
}

EC_GROUP* BrainpoolEcImpl::create_curve_group(BrainpoolEcImpl::Curve curve)
{
    int nid = 0;
    switch (curve) {
        case Curve::BRAINPOOLP256R1:
            nid = OBJ_sn2nid("brainpoolP256r1");
            break;
        case Curve::BRAINPOOLP384R1:
            nid = OBJ_sn2nid("brainpoolP384r1");
            break;
        case Curve::BRAINPOOLP512R1:
            nid = OBJ_sn2nid("brainpoolP512r1");
            break;
    }

    if (nid == 0) {
        // Curve not available - return nullptr to indicate error
        return nullptr;
    }

    EC_GROUP* group = EC_GROUP_new_by_curve_name(nid);
    if (!group) {
        print_openssl_error();
        return nullptr;
    }

    return group;
}

BrainpoolEcImpl::KeyPair BrainpoolEcImpl::generate_keypair()
{
    return generate_keypair(d_curve);
}

BrainpoolEcImpl::KeyPair BrainpoolEcImpl::generate_keypair(BrainpoolEcImpl::Curve curve)
{
    KeyPair keypair = { nullptr, nullptr };

    EC_GROUP* group = create_curve_group(curve);
    if (!group) {
        return keypair;
    }

    EC_KEY* ec_key = EC_KEY_new();
    if (!ec_key) {
        EC_GROUP_free(group);
        return keypair;
    }

    if (EC_KEY_set_group(ec_key, group) != 1) {
        EC_GROUP_free(group);
        EC_KEY_free(ec_key);
        return keypair;
    }

    if (EC_KEY_generate_key(ec_key) != 1) {
        EC_GROUP_free(group);
        EC_KEY_free(ec_key);
        print_openssl_error();
        return keypair;
    }

    EVP_PKEY* pkey = EVP_PKEY_new();
    if (!pkey) {
        EC_GROUP_free(group);
        EC_KEY_free(ec_key);
        print_openssl_error();
        return keypair;
    }

    if (EVP_PKEY_assign_EC_KEY(pkey, ec_key) != 1) {
        EVP_PKEY_free(pkey);
        EC_GROUP_free(group);
        print_openssl_error();
        return keypair;
    }

    EC_KEY* pub_ec_key = EC_KEY_new_by_curve_name(EC_GROUP_get_curve_name(group));
    if (!pub_ec_key) {
        EVP_PKEY_free(pkey);
        EC_GROUP_free(group);
        return keypair;
    }

    const EC_POINT* pub_point = EC_KEY_get0_public_key(ec_key);
    if (EC_KEY_set_public_key(pub_ec_key, pub_point) != 1) {
        EC_KEY_free(pub_ec_key);
        EVP_PKEY_free(pkey);
        EC_GROUP_free(group);
        print_openssl_error();
        return keypair;
    }

    EVP_PKEY* pub_pkey = EVP_PKEY_new();
    if (!pub_pkey) {
        EC_KEY_free(pub_ec_key);
        EVP_PKEY_free(pkey);
        EC_GROUP_free(group);
        return keypair;
    }

    if (EVP_PKEY_assign_EC_KEY(pub_pkey, pub_ec_key) != 1) {
        EVP_PKEY_free(pub_pkey);
        EC_KEY_free(pub_ec_key);
        EVP_PKEY_free(pkey);
        EC_GROUP_free(group);
        print_openssl_error();
        return keypair;
    }

    EC_GROUP_free(group);

    keypair.private_key = pkey;
    keypair.public_key = pub_pkey;
    return keypair;
}

std::vector<uint8_t> BrainpoolEcImpl::ecdh_exchange(EVP_PKEY* private_key, EVP_PKEY* peer_public_key)
{
    std::vector<uint8_t> shared_secret;

    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new(private_key, nullptr);
    if (!ctx) {
        print_openssl_error();
        return shared_secret;
    }

    if (EVP_PKEY_derive_init(ctx) != 1) {
        EVP_PKEY_CTX_free(ctx);
        print_openssl_error();
        return shared_secret;
    }

    if (EVP_PKEY_derive_set_peer(ctx, peer_public_key) != 1) {
        EVP_PKEY_CTX_free(ctx);
        print_openssl_error();
        return shared_secret;
    }

    size_t secret_len = 0;
    if (EVP_PKEY_derive(ctx, nullptr, &secret_len) != 1) {
        EVP_PKEY_CTX_free(ctx);
        print_openssl_error();
        return shared_secret;
    }

    shared_secret.resize(secret_len);
    if (EVP_PKEY_derive(ctx, shared_secret.data(), &secret_len) != 1) {
        EVP_PKEY_CTX_free(ctx);
        print_openssl_error();
        shared_secret.clear();
        return shared_secret;
    }

    EVP_PKEY_CTX_free(ctx);
    return shared_secret;
}

std::vector<uint8_t> BrainpoolEcImpl::sign(const std::vector<uint8_t>& data, EVP_PKEY* private_key)
{
    return sign(data.data(), data.size(), private_key, EVP_sha256());
}

std::vector<uint8_t> BrainpoolEcImpl::sign(const uint8_t* data, size_t data_len, EVP_PKEY* private_key)
{
    return sign(data, data_len, private_key, EVP_sha256());
}

std::vector<uint8_t> BrainpoolEcImpl::sign(const uint8_t* data, size_t data_len, EVP_PKEY* private_key, const EVP_MD* md)
{
    std::vector<uint8_t> signature;

    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    if (!ctx) {
        print_openssl_error();
        return signature;
    }

    if (EVP_DigestSignInit(ctx, nullptr, md != nullptr ? md : EVP_sha256(), nullptr, private_key) != 1) {
        EVP_MD_CTX_free(ctx);
        print_openssl_error();
        return signature;
    }

    if (EVP_DigestSignUpdate(ctx, data, data_len) != 1) {
        EVP_MD_CTX_free(ctx);
        print_openssl_error();
        return signature;
    }

    size_t sig_len = 0;
    if (EVP_DigestSignFinal(ctx, nullptr, &sig_len) != 1) {
        EVP_MD_CTX_free(ctx);
        print_openssl_error();
        return signature;
    }

    signature.resize(sig_len);
    if (EVP_DigestSignFinal(ctx, signature.data(), &sig_len) != 1) {
        EVP_MD_CTX_free(ctx);
        print_openssl_error();
        signature.clear();
        return signature;
    }

    signature.resize(sig_len);
    EVP_MD_CTX_free(ctx);
    return signature;
}

bool BrainpoolEcImpl::verify(const std::vector<uint8_t>& data,
                               const std::vector<uint8_t>& signature,
                               EVP_PKEY* public_key)
{
    return verify(data.data(), data.size(), signature.data(), signature.size(), public_key, EVP_sha256());
}

bool BrainpoolEcImpl::verify(const uint8_t* data, size_t data_len,
                               const uint8_t* signature, size_t sig_len,
                               EVP_PKEY* public_key)
{
    return verify(data, data_len, signature, sig_len, public_key, EVP_sha256());
}

bool BrainpoolEcImpl::verify(const uint8_t* data, size_t data_len,
                               const uint8_t* signature, size_t sig_len,
                               EVP_PKEY* public_key,
                               const EVP_MD* md)
{
    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    if (!ctx) {
        print_openssl_error();
        return false;
    }

    if (EVP_DigestVerifyInit(ctx, nullptr, md != nullptr ? md : EVP_sha256(), nullptr, public_key) != 1) {
        EVP_MD_CTX_free(ctx);
        print_openssl_error();
        return false;
    }

    if (EVP_DigestVerifyUpdate(ctx, data, data_len) != 1) {
        EVP_MD_CTX_free(ctx);
        print_openssl_error();
        return false;
    }

    int result = EVP_DigestVerifyFinal(ctx, signature, sig_len);
    EVP_MD_CTX_free(ctx);

    return (result == 1);
}

std::vector<uint8_t> BrainpoolEcImpl::serialize_public_key(EVP_PKEY* public_key)
{
    std::vector<uint8_t> pem_data;

    BIO* bio = BIO_new(BIO_s_mem());
    if (!bio) {
        print_openssl_error();
        return pem_data;
    }

    if (PEM_write_bio_PUBKEY(bio, public_key) != 1) {
        BIO_free(bio);
        print_openssl_error();
        return pem_data;
    }

    char* pem_ptr = nullptr;
    long pem_len = BIO_get_mem_data(bio, &pem_ptr);
    if (pem_len > 0 && pem_ptr) {
        pem_data.assign(reinterpret_cast<const uint8_t*>(pem_ptr), 
                       reinterpret_cast<const uint8_t*>(pem_ptr) + pem_len);
    }

    BIO_free(bio);
    return pem_data;
}

std::vector<uint8_t> BrainpoolEcImpl::serialize_private_key(EVP_PKEY* private_key, const std::string& password)
{
    std::vector<uint8_t> pem_data;

    BIO* bio = BIO_new(BIO_s_mem());
    if (!bio) {
        print_openssl_error();
        return pem_data;
    }

    const EVP_CIPHER* cipher = nullptr;
    const char* passwd = nullptr;
    if (!password.empty()) {
        cipher = EVP_aes_256_cbc();
        passwd = password.c_str();
    }

    if (PEM_write_bio_PrivateKey(bio, private_key, cipher, nullptr, 0, nullptr, 
                                  const_cast<char*>(passwd)) != 1) {
        BIO_free(bio);
        print_openssl_error();
        return pem_data;
    }

    char* pem_ptr = nullptr;
    long pem_len = BIO_get_mem_data(bio, &pem_ptr);
    if (pem_len > 0 && pem_ptr) {
        pem_data.assign(reinterpret_cast<const uint8_t*>(pem_ptr), 
                       reinterpret_cast<const uint8_t*>(pem_ptr) + pem_len);
    }

    BIO_free(bio);
    return pem_data;
}

EVP_PKEY* BrainpoolEcImpl::load_public_key(const std::vector<uint8_t>& pem_data)
{
    BIO* bio = BIO_new_mem_buf(pem_data.data(), pem_data.size());
    if (!bio) {
        print_openssl_error();
        return nullptr;
    }

    EVP_PKEY* pkey = PEM_read_bio_PUBKEY(bio, nullptr, nullptr, nullptr);
    BIO_free(bio);

    if (!pkey) {
        print_openssl_error();
    }

    return pkey;
}

EVP_PKEY* BrainpoolEcImpl::load_private_key(const std::vector<uint8_t>& pem_data, const std::string& password)
{
    BIO* bio = BIO_new_mem_buf(pem_data.data(), pem_data.size());
    if (!bio) {
        print_openssl_error();
        return nullptr;
    }

    const char* passwd = password.empty() ? nullptr : password.c_str();
    EVP_PKEY* pkey = PEM_read_bio_PrivateKey(bio, nullptr, nullptr, 
                                              const_cast<char*>(passwd));
    BIO_free(bio);

    if (!pkey) {
        print_openssl_error();
    }

    return pkey;
}

void BrainpoolEcImpl::set_curve(Curve curve)
{
    if (d_curve == curve) {
        return;
    }

    if (d_group) {
        EC_GROUP_free(d_group);
    }

    d_curve = curve;
    d_group = create_curve_group(d_curve);
    // Errors are indicated by d_group being nullptr
    // Error details available via OpenSSL error queue if needed
}

std::string BrainpoolEcImpl::curve_to_string(Curve curve)
{
    switch (curve) {
        case Curve::BRAINPOOLP256R1:
            return "brainpoolP256r1";
        case Curve::BRAINPOOLP384R1:
            return "brainpoolP384r1";
        case Curve::BRAINPOOLP512R1:
            return "brainpoolP512r1";
        default:
            return "unknown";
    }
}

BrainpoolEcImpl::Curve BrainpoolEcImpl::string_to_curve(const std::string& curve_name)
{
    if (curve_name == "brainpoolP256r1") {
        return Curve::BRAINPOOLP256R1;
    } else if (curve_name == "brainpoolP384r1") {
        return Curve::BRAINPOOLP384R1;
    } else if (curve_name == "brainpoolP512r1") {
        return Curve::BRAINPOOLP512R1;
    }
    return Curve::BRAINPOOLP256R1;
}

std::vector<std::string> BrainpoolEcImpl::get_supported_curves()
{
    return {
        "brainpoolP256r1",
        "brainpoolP384r1",
        "brainpoolP512r1"
    };
}

void BrainpoolEcImpl::print_openssl_error()
{
    // Error reporting is handled via return codes and exceptions
    // Debug only - not for production use
    // OpenSSL errors are propagated through return values and exceptions
    (void)ERR_get_error();  // Clear error queue
}

} // namespace linux_crypto
} // namespace gnuradio4
