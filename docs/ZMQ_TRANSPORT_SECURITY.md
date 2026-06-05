# ZeroMQ transport security

This document describes transport-layer security options for ZeroMQ deployments. It is written for developers who build on or integrate with gr-linux-crypto and need to understand what plain ZeroMQ provides, what alternatives exist for network-facing use, and what this repository does and does not implement. None of the mechanisms below are implemented, supported, or tested as part of the gr-linux-crypto ZMQ key store.

## What ZeroMQ provides by itself

A plain ZeroMQ socket offers no authentication, no encryption, and no integrity protection at the transport layer. Any process that can open a connection to the bound address can send requests and read responses. That behaviour is inherent to unmodified ZeroMQ over TCP, not a limitation of gr-linux-crypto alone.

For many local use cases this is acceptable. When the socket is bound to a loopback address and the host is not shared with untrusted processes, exposure is limited to other software on the same machine. That is the model the gr-linux-crypto ZMQ key store uses: loopback TCP only, with no transport security added by this repository. It is also the only deployment model this repository supports and tests.

Plain ZeroMQ is not appropriate for a socket bound to a network interface or otherwise reachable from remote hosts. In that situation, any party who can reach the port can interact with the service unless additional measures are applied outside or alongside the application.

## ZeroMQ CURVE

ZeroMQ includes a built-in security mechanism called CURVE. CURVE is based on the Curve25519 elliptic-curve Diffie-Hellman construction from the NaCl cryptographic library, exposed through libsodium. Peers establish authenticated, encrypted channels with forward secrecy. Both sides use Curve25519 keypairs; clients must know the server’s public key in advance before connecting.

CURVE operates within the ZeroMQ stack. It does not use OpenSSL and it is not TLS. When ZeroMQ itself is the only transport layer between peers on a network, CURVE is the mechanism ZeroMQ was designed for and is the natural first option for a developer adding network-facing ZMQ support on top of code derived from this project. gr-linux-crypto does not implement CURVE; adopting it would be the responsibility of the deploying project, including key distribution, socket options, and operational procedures.

## TLS wrapping with stunnel or a similar proxy

Another approach is to keep ZeroMQ on plain TCP between two proxy endpoints and place a TLS-terminating proxy in front of each side. Tools such as stunnel, an nginx stream proxy, or another TCP-level TLS proxy accept encrypted connections from clients, decrypt traffic, and forward the byte stream to the local ZeroMQ process. ZeroMQ itself remains unaware of TLS; the proxy layer provides confidentiality and server authentication according to the certificates and policies configured for that proxy.

The TLS library in use depends on the proxy (OpenSSL or a compatible implementation is common). This pattern tends to be more complex to operate than CURVE inside ZeroMQ because it adds certificate lifecycle management, proxy configuration, and failure modes separate from the application. It can still be a reasonable choice in environments that already run TLS certificate infrastructure and where policy explicitly requires TLS rather than an alternative authenticated-encryption design. gr-linux-crypto does not ship or document a TLS-wrapped key store configuration; that integration belongs in the deploying project’s own documentation and operations.

## ZeroMQ over Unix domain sockets

On a single machine, binding ZeroMQ to a Unix domain socket path instead of a TCP address is sometimes sufficient. ZeroMQ still does not encrypt traffic on the socket, but access is mediated by filesystem permissions on the socket file rather than by network reachability. Only users and processes granted permission to access that path can connect.

This option does not replace cryptographic protection of the byte stream. It can still improve isolation when localhost TCP is too permissive because many local processes can connect to loopback ports, yet filesystem permissions allow a tighter boundary. The gr-linux-crypto ZMQ key store server is not documented or tested with a Unix domain socket bind; adapting it would be a straightforward bind-address change in principle, but any such deployment would be outside what this repository supports.

## What this means for gr-linux-crypto

The ZMQ key store in this repository binds to localhost only. That is the sole supported and tested configuration. The data it serves is public-key material—mappings from callsigns to Brainpool public keys in PEM form—not private keys or plaintext payloads. Operational sensitivity may still apply to who can read or change those mappings.

The interface is unauthenticated at the transport layer: any local process that can reach the socket may query or, where the protocol allows, modify entries unless further restrictions are applied by the environment. If local process isolation matters in your threat model, Unix domain sockets with restrictive permissions or host-level controls that limit which processes may connect to the port may be worth considering. Those are environmental choices, not features of gr-linux-crypto.

If the key store must be reachable beyond localhost, transport security is required before exposure to a network. CURVE within ZeroMQ and TLS via an external proxy are the two broad families of solutions described above. Neither is implemented in this repository. Selecting, implementing, testing, and operating one of them is the responsibility of the project that deploys the key store on a network.

## References

- [ZeroMQ CURVE security (RFC 25)](https://rfc.zeromq.org/spec/25/)
- [libsodium documentation](https://doc.libsodium.org/)
- [stunnel documentation](https://www.stunnel.org/docs.html)
- [ZeroMQ Guide, Chapter 5: Advanced Architecture using ZeroMQ](https://zguide.zeromq.org/docs/chapter5/)
