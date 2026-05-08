// SPDX-License-Identifier: GPL-3.0-or-later

#include <gnuradio-4.0/linux_crypto/detail/EciesCodec.hpp>

#include <openssl/bio.h>
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/kdf.h>
#include <openssl/pem.h>

#include <algorithm>
#include <cstring>

namespace gnuradio4::linux_crypto::detail {

namespace {

void append_be16(std::vector<std::uint8_t>& dst, std::uint16_t v) {
    dst.push_back(static_cast<std::uint8_t>((v >> 8) & 0xFF));
    dst.push_back(static_cast<std::uint8_t>(v & 0xFF));
}

[[nodiscard]] bool read_be16(std::span<const std::uint8_t> span, std::size_t& pos, std::uint16_t& out) {
    if (pos + 2UZ > span.size()) {
        return false;
    }
    out = static_cast<std::uint16_t>((static_cast<unsigned>(span[pos]) << 8u) | static_cast<unsigned>(span[pos + 1U]));
    pos += 2U;
    return true;
}

[[nodiscard]] bool hkdf_derive_sha256(std::span<const std::uint8_t> secret, std::string_view info, std::vector<std::uint8_t>& aesKey,
    std::vector<std::uint8_t>& ivOut) {
    aesKey.resize(kEciesAesKey);
    ivOut.resize(kEciesIv);

    EVP_PKEY_CTX* pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_HKDF, nullptr);
    if (!pctx) {
        return false;
    }
    if (EVP_PKEY_derive_init(pctx) <= 0 || EVP_PKEY_CTX_set_hkdf_md(pctx, EVP_sha256()) <= 0 || EVP_PKEY_CTX_set1_hkdf_salt(pctx, nullptr, 0) <= 0 ||
        EVP_PKEY_CTX_set1_hkdf_key(pctx, secret.data(), static_cast<int>(secret.size())) <= 0) {
        EVP_PKEY_CTX_free(pctx);
        return false;
    }
    if (!info.empty()) {
        if (EVP_PKEY_CTX_add1_hkdf_info(pctx, reinterpret_cast<const unsigned char*>(info.data()), info.size()) <= 0) {
            EVP_PKEY_CTX_free(pctx);
            return false;
        }
    }
    std::size_t derived_len = kEciesAesKey + kEciesIv;
    std::vector<std::uint8_t> derived(derived_len);
    if (EVP_PKEY_derive(pctx, derived.data(), &derived_len) <= 0) {
        EVP_PKEY_CTX_free(pctx);
        return false;
    }
    EVP_PKEY_CTX_free(pctx);
    if (derived_len < kEciesAesKey + kEciesIv) {
        return false;
    }
    std::memcpy(aesKey.data(), derived.data(), kEciesAesKey);
    std::memcpy(ivOut.data(), derived.data() + kEciesAesKey, kEciesIv);
    return true;
}

[[nodiscard]] bool aes256_gcm_encrypt_bytes(const std::uint8_t* plain, std::size_t ptLen, const std::vector<std::uint8_t>& aesKey,
    const std::vector<std::uint8_t>& iv, std::vector<std::uint8_t>& ciphertext, std::vector<std::uint8_t>& tag) {
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        return false;
    }
    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, nullptr, nullptr) != 1 ||
        EVP_EncryptInit_ex(ctx, nullptr, nullptr, aesKey.data(), iv.data()) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return false;
    }
    ciphertext.resize(ptLen);
    int ol = 0;
    if (EVP_EncryptUpdate(ctx, ciphertext.data(), &ol, plain, static_cast<int>(ptLen)) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return false;
    }
    int fl = 0;
    if (EVP_EncryptFinal_ex(ctx, ciphertext.data() + ol, &fl) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return false;
    }
    tag.resize(kEciesTag);
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, static_cast<int>(kEciesTag), tag.data()) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return false;
    }
    EVP_CIPHER_CTX_free(ctx);
    return true;
}

[[nodiscard]] bool aes256_gcm_decrypt_bytes(const std::uint8_t* ct, std::size_t ctLen, const std::vector<std::uint8_t>& aesKey,
    const std::vector<std::uint8_t>& iv, const std::uint8_t* tag, std::vector<std::uint8_t>& plain) {
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        return false;
    }
    if (EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, nullptr, nullptr) != 1 ||
        EVP_DecryptInit_ex(ctx, nullptr, nullptr, aesKey.data(), iv.data()) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return false;
    }
    plain.resize(ctLen);
    int ol = 0;
    if (EVP_DecryptUpdate(ctx, plain.data(), &ol, ct, static_cast<int>(ctLen)) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return false;
    }
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, static_cast<int>(kEciesTag), const_cast<unsigned char*>(tag)) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return false;
    }
    int fl = 0;
    const int vr = EVP_DecryptFinal_ex(ctx, plain.data() + ol, &fl);
    EVP_CIPHER_CTX_free(ctx);
    if (vr != 1) {
        return false;
    }
    plain.resize(static_cast<std::size_t>(ol + fl));
    return true;
}

} // namespace

EVP_PKEY* loadPublicKeyFromPemString(std::string_view pem) {
    std::vector<std::uint8_t> blob(pem.begin(), pem.end());
    return BrainpoolEcImpl::load_public_key(blob);
}

EVP_PKEY* loadPrivateKeyFromPemString(std::string_view pem) {
    std::vector<std::uint8_t> blob(pem.begin(), pem.end());
    return BrainpoolEcImpl::load_private_key(blob, "");
}

void freeKeys(const std::vector<EVP_PKEY*>& keys) {
    for (EVP_PKEY* p : keys) {
        EVP_PKEY_free(p);
    }
}

bool eciesEncryptPem(BrainpoolEcImpl& ec, EVP_PKEY* recipientPubkey, std::string_view kdfInfo, std::span<const std::uint8_t> plaintext,
    std::vector<std::uint8_t>& wire) {
    wire.clear();
    if (recipientPubkey == nullptr || plaintext.empty()) {
        return false;
    }
    BrainpoolEcImpl::KeyPair ek = ec.generate_keypair();
    if (ek.private_key == nullptr || ek.public_key == nullptr) {
        return false;
    }
    auto shared = ec.ecdh_exchange(ek.private_key, recipientPubkey);
    if (shared.empty()) {
        EVP_PKEY_free(ek.private_key);
        EVP_PKEY_free(ek.public_key);
        return false;
    }

    std::vector<std::uint8_t> ephem_pem = BrainpoolEcImpl::serialize_public_key(ek.public_key);
    EVP_PKEY_free(ek.private_key);
    EVP_PKEY_free(ek.public_key);
    if (ephem_pem.empty()) {
        OPENSSL_cleanse(shared.data(), shared.size());
        return false;
    }

    std::vector<std::uint8_t> dk;
    std::vector<std::uint8_t> ivWire;
    if (!hkdf_derive_sha256(shared, kdfInfo, dk, ivWire)) {
        OPENSSL_cleanse(shared.data(), shared.size());
        OPENSSL_cleanse(dk.data(), dk.size());
        return false;
    }
    OPENSSL_cleanse(shared.data(), shared.size());

    std::vector<std::uint8_t> ct;
    std::vector<std::uint8_t> tag;
    if (!aes256_gcm_encrypt_bytes(plaintext.data(), plaintext.size(), dk, ivWire, ct, tag)) {
        OPENSSL_cleanse(dk.data(), dk.size());
        return false;
    }
    OPENSSL_cleanse(dk.data(), dk.size());

    append_be16(wire, static_cast<std::uint16_t>(ephem_pem.size()));
    wire.insert(wire.end(), ephem_pem.begin(), ephem_pem.end());
    wire.insert(wire.end(), ivWire.begin(), ivWire.end());
    append_be16(wire, static_cast<std::uint16_t>(ct.size()));
    wire.insert(wire.end(), ct.begin(), ct.end());
    wire.insert(wire.end(), tag.begin(), tag.end());
    return true;
}

bool eciesDecryptPem(EVP_PKEY* recipientPriv, std::string_view kdfInfo, std::span<const std::uint8_t> wire, std::vector<std::uint8_t>& plaintext) {
    plaintext.clear();
    if (recipientPriv == nullptr || wire.size() < 2U + 1U + kEciesIv + 2U + 1U + kEciesTag) {
        return false;
    }
    std::size_t pos           = 0U;
    std::uint16_t pubkey_len_u = 0U;
    if (!read_be16(wire, pos, pubkey_len_u)) {
        return false;
    }
    const auto pubkey_len = static_cast<std::size_t>(pubkey_len_u);
    if (pubkey_len == 0UZ || pubkey_len > 8192UZ || pos + pubkey_len > wire.size()) {
        return false;
    }

    BIO* bio = BIO_new_mem_buf(reinterpret_cast<const char*>(wire.data()) + pos, static_cast<int>(pubkey_len));
    if (!bio) {
        return false;
    }
    EVP_PKEY* ephem = PEM_read_bio_PUBKEY(bio, nullptr, nullptr, nullptr);
    BIO_free(bio);
    pos += pubkey_len;
    if (ephem == nullptr || pos + kEciesIv + 2UZ > wire.size()) {
        EVP_PKEY_free(ephem);
        return false;
    }
    std::vector<std::uint8_t> iv(wire.begin() + static_cast<std::ptrdiff_t>(pos), wire.begin() + static_cast<std::ptrdiff_t>(pos + kEciesIv));
    pos += kEciesIv;
    std::uint16_t ct_len_u = 0U;
    if (!read_be16(wire, pos, ct_len_u)) {
        EVP_PKEY_free(ephem);
        return false;
    }
    const auto ct_len = static_cast<std::size_t>(ct_len_u);
    if (ct_len == 0UZ || pos + ct_len + kEciesTag > wire.size()) {
        EVP_PKEY_free(ephem);
        return false;
    }

    EVP_PKEY_CTX* dctx = EVP_PKEY_CTX_new(recipientPriv, nullptr);
    std::vector<std::uint8_t> secret;
    if (!dctx) {
        EVP_PKEY_free(ephem);
        return false;
    }
    if (EVP_PKEY_derive_init(dctx) != 1 || EVP_PKEY_derive_set_peer(dctx, ephem) != 1) {
        EVP_PKEY_CTX_free(dctx);
        EVP_PKEY_free(ephem);
        return false;
    }
    EVP_PKEY_free(ephem);
    std::size_t slen = 0U;
    if (EVP_PKEY_derive(dctx, nullptr, &slen) != 1) {
        EVP_PKEY_CTX_free(dctx);
        return false;
    }
    secret.resize(slen);
    if (EVP_PKEY_derive(dctx, secret.data(), &slen) != 1) {
        OPENSSL_cleanse(secret.data(), secret.size());
        EVP_PKEY_CTX_free(dctx);
        return false;
    }
    EVP_PKEY_CTX_free(dctx);

    std::vector<std::uint8_t> dk;
    std::vector<std::uint8_t> iv_chk;
    if (!hkdf_derive_sha256(secret, kdfInfo, dk, iv_chk)) {
        OPENSSL_cleanse(secret.data(), secret.size());
        return false;
    }
    OPENSSL_cleanse(secret.data(), secret.size());

    if (iv_chk.size() != iv.size() || !std::equal(iv.begin(), iv.end(), iv_chk.begin())) {
        OPENSSL_cleanse(dk.data(), dk.size());
        return false;
    }

    const std::uint8_t* ct_start = wire.data() + pos;
    const std::uint8_t* tag_start             = ct_start + static_cast<std::ptrdiff_t>(ct_len);

    plaintext.clear();
    const bool ok = aes256_gcm_decrypt_bytes(ct_start, ct_len, dk, iv, tag_start, plaintext);
    OPENSSL_cleanse(dk.data(), dk.size());
    OPENSSL_cleanse(iv_chk.data(), iv_chk.size());
    return ok;
}

bool multiEncryptPem(const std::vector<EVP_PKEY*>& recipients, BrainpoolEcImpl& ec256, std::string_view kdfInfo,
    std::span<const std::uint8_t> plaintext, std::vector<std::uint8_t>& wire) {
    wire.clear();
    if (recipients.empty() || recipients.size() > 25UZ) {
        return false;
    }
    append_be16(wire, static_cast<std::uint16_t>(recipients.size()));
    for (EVP_PKEY* r : recipients) {
        if (r == nullptr) {
            return false;
        }
        std::vector<std::uint8_t> frag;
        if (!eciesEncryptPem(ec256, r, kdfInfo, plaintext, frag)) {
            return false;
        }
        append_be16(wire, static_cast<std::uint16_t>(frag.size()));
        wire.insert(wire.end(), frag.begin(), frag.end());
    }
    return true;
}

bool multiDecryptTryKeys(const std::vector<EVP_PKEY*>& privateKeysCandidate, std::string_view kdfInfo, std::span<const std::uint8_t> wire,
    std::vector<std::uint8_t>& plaintext) {
    plaintext.clear();
    std::size_t pos = 0U;
    std::uint16_t nPacked = 0U;
    if (!read_be16(wire, pos, nPacked) || nPacked == 0U || nPacked > 25U) {
        return false;
    }
    std::vector<std::vector<std::uint8_t>> frags;
    frags.reserve(nPacked);
    for (std::uint16_t i = 0; i < nPacked; ++i) {
        std::uint16_t lenU = 0U;
        if (!read_be16(wire, pos, lenU)) {
            return false;
        }
        const auto len = static_cast<std::size_t>(lenU);
        if (pos + len > wire.size()) {
            return false;
        }
        frags.emplace_back(wire.begin() + static_cast<std::ptrdiff_t>(pos), wire.begin() + static_cast<std::ptrdiff_t>(pos + len));
        pos += len;
    }
    for (EVP_PKEY* k : privateKeysCandidate) {
        if (k == nullptr) {
            continue;
        }
        for (const std::vector<std::uint8_t>& frag : frags) {
            if (eciesDecryptPem(k, kdfInfo, frag, plaintext)) {
                return true;
            }
        }
    }
    return false;
}

} // namespace gnuradio4::linux_crypto::detail
