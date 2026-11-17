// Direct (one-to-one) message encryption for meshport.
// X25519 key agreement -> HKDF-SHA256 -> ChaCha20-Poly1305 per message.
// Each message uses a per-key counter as its nonce; the caller must never reuse a counter with the same key.
#pragma once

#include <cstddef>
#include <cstdint>
#include <vector>

namespace meshport {

// Primitive backend. Host tests use OpenSSL; the device uses mbedtls.
bool x25519PublicKey(const uint8_t priv[32], uint8_t pub[32]);
bool x25519SharedSecret(const uint8_t priv[32], const uint8_t peerPub[32], uint8_t shared[32]);
bool hkdfSha256(const uint8_t *ikm, size_t ikmLen, const uint8_t *salt, size_t saltLen,
                const uint8_t *info, size_t infoLen, uint8_t *out, size_t outLen);
// In-place ChaCha20-Poly1305 encrypt; writes a 16-byte tag.
bool chachaPolySeal(const uint8_t key[32], const uint8_t nonce[12], const uint8_t *aad, size_t aadLen,
                    uint8_t *data, size_t len, uint8_t tag[16]);
// In-place decrypt; returns false (and leaves data unusable) if the tag does not match.
bool chachaPolyOpen(const uint8_t key[32], const uint8_t nonce[12], const uint8_t *aad, size_t aadLen,
                    uint8_t *data, size_t len, const uint8_t tag[16]);

// Symmetric key for a pair of nodes. Both sides get the same key.
bool deriveDirectKey(const uint8_t myPriv[32], const uint8_t theirPub[32], uint8_t key[32]);

// Encrypt a plaintext. Output is ciphertext followed by the 16-byte tag.
bool sealDirect(const uint8_t key[32], uint64_t counter, const uint8_t *aad, size_t aadLen,
                const uint8_t *plain, size_t plainLen, std::vector<uint8_t> &out);

// Decrypt ciphertext||tag. Returns false if authentication fails.
bool openDirect(const uint8_t key[32], uint64_t counter, const uint8_t *aad, size_t aadLen,
                const uint8_t *in, size_t inLen, std::vector<uint8_t> &plain);

} // namespace meshport
