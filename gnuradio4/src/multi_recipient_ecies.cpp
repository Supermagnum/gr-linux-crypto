// SPDX-License-Identifier: GPL-3.0-or-later

#include <gnuradio-4.0/linux_crypto/detail/EciesCodec.hpp>
#include <gnuradio-4.0/linux_crypto/detail/MultiRecipientEcies.hpp>

#include <cctype>

#include <openssl/evp.h>
#include <openssl/rand.h>

#include <algorithm>
#include <cstring>

namespace gnuradio4::linux_crypto::detail {

namespace {

bool aes256_gcm_encrypt(const std::uint8_t* plain, std::size_t ptLen, const std::vector<std::uint8_t>& aesKey, const std::vector<std::uint8_t>& iv,
    std::vector<std::uint8_t>& ciphertext, std::vector<std::uint8_t>& tag) {
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
    tag.resize(kMultiPayloadTag);
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, static_cast<int>(kMultiPayloadTag), tag.data()) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return false;
    }
    EVP_CIPHER_CTX_free(ctx);
    return true;
}

bool aes256_gcm_decrypt(const std::uint8_t* ct, std::size_t ctLen, const std::vector<std::uint8_t>& aesKey, const std::vector<std::uint8_t>& iv,
    const std::uint8_t* tag, std::vector<std::uint8_t>& plain) {
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
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, static_cast<int>(kMultiPayloadTag), const_cast<unsigned char*>(tag)) != 1) {
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

std::uint8_t curveToId(BrainpoolEcImpl::Curve c) {
    switch (c) {
    case BrainpoolEcImpl::Curve::BRAINPOOLP256R1:
        return 0x01;
    case BrainpoolEcImpl::Curve::BRAINPOOLP384R1:
        return 0x02;
    case BrainpoolEcImpl::Curve::BRAINPOOLP512R1:
        return 0x03;
    }
    return 0x01;
}

bool multiRecipientEncrypt(BrainpoolEcImpl::Curve curve, const CallsignKeyStore& store, std::span<const std::string> recipients,
    std::string_view kdfInfo, std::span<const std::uint8_t> plaintext, std::vector<std::uint8_t>& wire) {
    wire.clear();
    if (recipients.empty() || recipients.size() > 25UZ) {
        return false;
    }
    BrainpoolEcImpl ec(curve);
    std::vector<std::uint8_t> symKey(kMultiSymKeyLen);
    std::vector<std::uint8_t> ivPay(kMultiPayloadIv);
    if (RAND_bytes(symKey.data(), static_cast<int>(symKey.size())) != 1 || RAND_bytes(ivPay.data(), static_cast<int>(ivPay.size())) != 1) {
        OPENSSL_cleanse(symKey.data(), symKey.size());
        return false;
    }

    std::vector<std::uint8_t> ctPay;
    std::vector<std::uint8_t> tagPay;
    if (!aes256_gcm_encrypt(plaintext.data(), plaintext.size(), symKey, ivPay, ctPay, tagPay)) {
        OPENSSL_cleanse(symKey.data(), symKey.size());
        return false;
    }

    const std::uint32_t dataLength = static_cast<std::uint32_t>(ctPay.size() + kMultiPayloadIv);
    const std::uint8_t  cid        = curveToId(curve);
    const std::uint8_t  nRec       = static_cast<std::uint8_t>(recipients.size());

    wire.push_back(0x01); // FORMAT_VERSION
    wire.push_back(cid);
    wire.push_back(nRec);
    wire.push_back(0x01);                             // aes-gcm
    wire.push_back(static_cast<std::uint8_t>(dataLength >> 24));
    wire.push_back(static_cast<std::uint8_t>(dataLength >> 16));
    wire.push_back(static_cast<std::uint8_t>(dataLength >> 8));
    wire.push_back(static_cast<std::uint8_t>(dataLength));

    for (const std::string& csRaw : recipients) {
        auto pemOpt = store.publicPemForCallsign(csRaw);
        if (!pemOpt) {
            OPENSSL_cleanse(symKey.data(), symKey.size());
            return false;
        }
        EVP_PKEY* pub = loadPublicKeyFromPemString(std::string_view(pemOpt->data(), pemOpt->size()));
        if (pub == nullptr) {
            OPENSSL_cleanse(symKey.data(), symKey.size());
            return false;
        }
        std::vector<std::uint8_t> rkFrag;
        const bool ek =
            eciesEncryptPem(ec, pub, kdfInfo, std::span<const std::uint8_t>(symKey.data(), symKey.size()), rkFrag);
        EVP_PKEY_free(pub);
        if (!ek) {
            OPENSSL_cleanse(symKey.data(), symKey.size());
            return false;
        }
        std::string csAscii;
        csAscii.reserve(csRaw.size());
        for (unsigned char cu : csRaw) {
            if (static_cast<unsigned char>(cu) > 127U) {
                OPENSSL_cleanse(symKey.data(), symKey.size());
                return false;
            }
            csAscii.push_back(static_cast<char>(std::toupper(cu)));
        }
        if (csAscii.empty() || csAscii.size() > 14UZ) {
            OPENSSL_cleanse(symKey.data(), symKey.size());
            return false;
        }
        const auto csWireLen = static_cast<std::uint8_t>(csAscii.size());
        wire.push_back(csWireLen);
        wire.insert(wire.end(), csAscii.begin(), csAscii.end());
        wire.push_back(0); // terminator
        wire.push_back(static_cast<std::uint8_t>((rkFrag.size() >> 8) & 0xFF));
        wire.push_back(static_cast<std::uint8_t>(rkFrag.size() & 0xFF));
        wire.insert(wire.end(), rkFrag.begin(), rkFrag.end());
    }

    wire.insert(wire.end(), ivPay.begin(), ivPay.end());
    wire.insert(wire.end(), ctPay.begin(), ctPay.end());
    wire.insert(wire.end(), tagPay.begin(), tagPay.end());
    OPENSSL_cleanse(symKey.data(), symKey.size());
    return true;
}

bool multiRecipientDecrypt(BrainpoolEcImpl::Curve curve, std::string_view recipientCallsignUpper, std::string_view privateKeyPem,
    std::string_view kdfInfo, std::span<const std::uint8_t> wire, std::vector<std::uint8_t>& plaintext) {
    plaintext.clear();
    constexpr std::size_t kHdr = 8U;
    if (wire.size() < kHdr) {
        return false;
    }
    std::size_t        pos           = 0;
    const std::uint8_t ver           = wire[pos++];
    const std::uint8_t curveIdWire   = wire[pos++];
    const std::uint8_t nRec          = wire[pos++];
    const std::uint8_t cipherId      = wire[pos++];
    const std::uint32_t dataLenPacked =
        (static_cast<std::uint32_t>(wire[pos]) << 24) | (static_cast<std::uint32_t>(wire[pos + 1]) << 16) |
        (static_cast<std::uint32_t>(wire[pos + 2]) << 8) | static_cast<std::uint32_t>(wire[pos + 3]);
    pos += 4;
    const auto dataLen = static_cast<std::size_t>(dataLenPacked);

    if (ver != 0x01U || cipherId != 0x01U || nRec == 0U || nRec > 25U) {
        return false;
    }
    if (curveToId(curve) != curveIdWire) {
        return false;
    }

    while (!recipientCallsignUpper.empty() && recipientCallsignUpper.back() == ' ') {
        recipientCallsignUpper.remove_suffix(1);
    }

    std::optional<std::vector<std::uint8_t>> encSymMine;
    for (std::uint8_t ri = 0; ri < nRec; ++ri) {
        if (pos >= wire.size()) {
            return false;
        }
        const std::uint8_t csLen = wire[pos++];
        if (csLen == 0U || csLen > 14U || pos + static_cast<std::size_t>(csLen) + 3U > wire.size()) {
            return false;
        }

        std::string csWireUpper;
        for (std::size_t j = 0; j < static_cast<std::size_t>(csLen); ++j) {
            const unsigned char c = wire[pos++];
            if (static_cast<unsigned char>(c) > 127U) {
                return false;
            }
            csWireUpper.push_back(static_cast<char>(std::toupper(static_cast<unsigned char>(c))));
        }

        if (wire[pos++] != 0U) {
            return false;
        }

        const std::uint16_t fragLenBE =
            static_cast<std::uint16_t>((static_cast<unsigned>(wire[pos]) << 8) | static_cast<unsigned>(wire[pos + 1]));
        pos += 2;
        const auto fragLen = static_cast<std::size_t>(fragLenBE);

        if (pos + fragLen > wire.size()) {
            return false;
        }

        if (fragLen != 0U && csWireUpper.size() == recipientCallsignUpper.size() &&
            std::equal(csWireUpper.begin(), csWireUpper.end(), recipientCallsignUpper.begin())) {

            encSymMine.emplace(wire.begin() + static_cast<std::ptrdiff_t>(pos),
                wire.begin() + static_cast<std::ptrdiff_t>(pos + fragLen));
        }
        pos += fragLen;
    }

    if (!encSymMine.has_value()) {
        return false;
    }

    const std::size_t expectedTail = dataLen + kMultiPayloadTag;
    if (wire.size() < pos || wire.size() - pos != expectedTail) {
        OPENSSL_cleanse(encSymMine->data(), encSymMine->size());
        return false;
    }

    EVP_PKEY* priv = loadPrivateKeyFromPemString(privateKeyPem);
    if (priv == nullptr) {
        OPENSSL_cleanse(encSymMine->data(), encSymMine->size());
        return false;
    }

    std::vector<std::uint8_t> symKey;
    const bool dk = eciesDecryptPem(priv, kdfInfo, *encSymMine, symKey);
    EVP_PKEY_free(priv);
    OPENSSL_cleanse(encSymMine->data(), encSymMine->size());

    if (!dk || symKey.size() != kMultiSymKeyLen) {
        OPENSSL_cleanse(symKey.data(), symKey.size());
        return false;
    }

    if (dataLen < kMultiPayloadIv) {
        OPENSSL_cleanse(symKey.data(), symKey.size());
        return false;
    }

    std::vector<std::uint8_t> ivPay(wire.begin() + static_cast<std::ptrdiff_t>(pos),
        wire.begin() + static_cast<std::ptrdiff_t>(pos + kMultiPayloadIv));
    pos += kMultiPayloadIv;
    const std::size_t ctSz = dataLen - kMultiPayloadIv;
    const std::uint8_t* ct   = wire.data() + pos;
    const std::uint8_t* tagp = ct + ctSz;

    const bool ok = aes256_gcm_decrypt(ct, ctSz, symKey, ivPay, tagp, plaintext);
    OPENSSL_cleanse(symKey.data(), symKey.size());
    return ok;
}

} // namespace gnuradio4::linux_crypto::detail
