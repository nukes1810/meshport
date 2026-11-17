// ChaCha20-Poly1305 AEAD (RFC 8439), portable C++ with no platform dependency.
// Used on the device, where the bundled mbedtls and PSA builds lack this AEAD.
#pragma once

#include <cstddef>
#include <cstdint>

namespace meshport {

// Encrypts data in place and writes the 16-byte tag.
bool chachaPolyEncrypt(const uint8_t key[32], const uint8_t nonce[12], const uint8_t *aad, size_t aadLen,
                       uint8_t *data, size_t len, uint8_t tag[16]);

// Verifies the tag, then decrypts data in place. Returns false and leaves data
// as ciphertext when the tag does not match.
bool chachaPolyDecrypt(const uint8_t key[32], const uint8_t nonce[12], const uint8_t *aad, size_t aadLen,
                       uint8_t *data, size_t len, const uint8_t tag[16]);

} // namespace meshport
