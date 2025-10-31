#ifndef INCLUDED_LINUX_CRYPTO_BRAINPOOL_EC_H
#define INCLUDED_LINUX_CRYPTO_BRAINPOOL_EC_H

#include <gnuradio/linux_crypto/api.h>
#include <gnuradio/linux_crypto/brainpool_ec_impl.h>
#include <memory>

namespace gr {
namespace linux_crypto {

/*!
 * \brief Brainpool Elliptic Curve Cryptography wrapper
 * \ingroup linux_crypto
 *
 * Provides Brainpool curve support for key generation, ECDH key exchange,
 * and ECDSA signing/verification using OpenSSL.
 */
class LINUX_CRYPTO_API brainpool_ec : public brainpool_ec_impl
{
public:
    typedef std::shared_ptr<brainpool_ec> sptr;

    static sptr make(brainpool_ec_impl::Curve curve = brainpool_ec_impl::Curve::BRAINPOOLP256R1);

    brainpool_ec(brainpool_ec_impl::Curve curve = brainpool_ec_impl::Curve::BRAINPOOLP256R1);
    ~brainpool_ec();
};

} // namespace linux_crypto
} // namespace gr

#endif /* INCLUDED_LINUX_CRYPTO_BRAINPOOL_EC_H */

