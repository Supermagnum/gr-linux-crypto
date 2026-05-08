// SPDX-License-Identifier: GPL-3.0-or-later
#ifndef GNURADIO4_LINUX_CRYPTO_DETAIL_CALLSIGNKEYSTORE_HPP
#define GNURADIO4_LINUX_CRYPTO_DETAIL_CALLSIGNKEYSTORE_HPP

#include <optional>
#include <string>
#include <unordered_map>
#include <vector>

namespace gnuradio4::linux_crypto::detail {

/**
 * Minimal callsign -> PEM map loader (flat keys and string values only).
 * JSON groups (list values) are expanded when explicitly requested by name.
 */
class CallsignKeyStore {
public:
    bool loadFile(const std::string& path);

    [[nodiscard]] std::optional<std::string> publicPemForCallsign(const std::string& callsignUpper) const;

    /** Resolve a token: either a callsign or a group name. */
    [[nodiscard]] std::vector<std::string> expandRecipients(const std::vector<std::string>& tokens) const;

private:
    std::unordered_map<std::string, std::string>                    _keys;
    std::unordered_map<std::string, std::vector<std::string>> _groups;
};

} // namespace gnuradio4::linux_crypto::detail

#endif
