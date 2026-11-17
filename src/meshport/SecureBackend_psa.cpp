// Device backend for SecureDirect using the PSA Crypto API (Mbed TLS, bundled with ESP-IDF).
// Not compiled on the host. Untested until the device build and device test run.
#include "SecureDirect.h"

#include "psa/crypto.h"

#include <vector>

namespace meshport {

namespace {

bool psaReady()
{
    static bool ready = (psa_crypto_init() == PSA_SUCCESS);
    return ready;
}

bool importX25519(const uint8_t priv[32], psa_key_id_t &id)
{
    psa_key_attributes_t attr = PSA_KEY_ATTRIBUTES_INIT;
    psa_set_key_type(&attr, PSA_KEY_TYPE_ECC_KEY_PAIR(PSA_ECC_FAMILY_MONTGOMERY));
    psa_set_key_bits(&attr, 255);
    psa_set_key_usage_flags(&attr, PSA_KEY_USAGE_DERIVE | PSA_KEY_USAGE_EXPORT);
    psa_set_key_algorithm(&attr, PSA_ALG_ECDH);
    return psa_import_key(&attr, priv, 32, &id) == PSA_SUCCESS;
}

} // namespace

bool x25519PublicKey(const uint8_t priv[32], uint8_t pub[32])
{
    if (!psaReady()) return false;
    psa_key_id_t id = PSA_KEY_ID_NULL;
    if (!importX25519(priv, id)) return false;
    size_t len = 0;
    psa_status_t st = psa_export_public_key(id, pub, 32, &len);
    psa_destroy_key(id);
    return st == PSA_SUCCESS && len == 32;
}

bool x25519SharedSecret(const uint8_t priv[32], const uint8_t peerPub[32], uint8_t shared[32])
{
    if (!psaReady()) return false;
    psa_key_id_t id = PSA_KEY_ID_NULL;
    if (!importX25519(priv, id)) return false;
    size_t len = 0;
    psa_status_t st = psa_raw_key_agreement(PSA_ALG_ECDH, id, peerPub, 32, shared, 32, &len);
    psa_destroy_key(id);
    return st == PSA_SUCCESS && len == 32;
}

namespace {
int gHkdfFailStep = -1;
int gHkdfFailStatus = 0;
}

int psaHkdfFailStep() { return gHkdfFailStep; }
int psaHkdfFailStatus() { return gHkdfFailStatus; }

bool hkdfSha256(const uint8_t *ikm, size_t ikmLen, const uint8_t *salt, size_t saltLen,
                const uint8_t *info, size_t infoLen, uint8_t *out, size_t outLen)
{
    gHkdfFailStep = -1;
    gHkdfFailStatus = 0;
    if (!psaReady()) { gHkdfFailStep = 0; return false; }
    psa_key_derivation_operation_t op = PSA_KEY_DERIVATION_OPERATION_INIT;
    psa_key_id_t secret = PSA_KEY_ID_NULL;
    psa_key_attributes_t attr = PSA_KEY_ATTRIBUTES_INIT;
    psa_set_key_type(&attr, PSA_KEY_TYPE_DERIVE);
    psa_set_key_usage_flags(&attr, PSA_KEY_USAGE_DERIVE);
    psa_set_key_algorithm(&attr, PSA_ALG_HKDF(PSA_ALG_SHA_256));
    psa_status_t st;
    int step = 0;
    st = psa_import_key(&attr, ikm, ikmLen, &secret);
    if (st == PSA_SUCCESS) { step = 1; st = psa_key_derivation_setup(&op, PSA_ALG_HKDF(PSA_ALG_SHA_256)); }
    if (st == PSA_SUCCESS) { step = 2; if (saltLen) st = psa_key_derivation_input_bytes(&op, PSA_KEY_DERIVATION_INPUT_SALT, salt, saltLen); }
    if (st == PSA_SUCCESS) { step = 3; st = psa_key_derivation_input_key(&op, PSA_KEY_DERIVATION_INPUT_SECRET, secret); }
    if (st == PSA_SUCCESS) { step = 4; st = psa_key_derivation_input_bytes(&op, PSA_KEY_DERIVATION_INPUT_INFO, info, infoLen); }
    if (st == PSA_SUCCESS) { step = 5; st = psa_key_derivation_output_bytes(&op, out, outLen); }
    if (st != PSA_SUCCESS) {
        gHkdfFailStep = step;
        gHkdfFailStatus = (int)st;
    }
    psa_key_derivation_abort(&op);
    psa_destroy_key(secret);
    return st == PSA_SUCCESS;
}

namespace {

bool importChacha(const uint8_t key[32], psa_key_id_t &id)
{
    psa_key_attributes_t attr = PSA_KEY_ATTRIBUTES_INIT;
    psa_set_key_type(&attr, PSA_KEY_TYPE_CHACHA20);
    psa_set_key_bits(&attr, 256);
    psa_set_key_usage_flags(&attr, PSA_KEY_USAGE_ENCRYPT | PSA_KEY_USAGE_DECRYPT);
    psa_set_key_algorithm(&attr, PSA_ALG_CHACHA20_POLY1305);
    return psa_import_key(&attr, key, 32, &id) == PSA_SUCCESS;
}

} // namespace

bool chachaPolySeal(const uint8_t key[32], const uint8_t nonce[12], const uint8_t *aad, size_t aadLen,
                    uint8_t *data, size_t len, uint8_t tag[16])
{
    if (!psaReady()) return false;
    psa_key_id_t id = PSA_KEY_ID_NULL;
    if (!importChacha(key, id)) return false;
    std::vector<uint8_t> out(len + 16);
    size_t outLen = 0;
    psa_status_t st = psa_aead_encrypt(id, PSA_ALG_CHACHA20_POLY1305, nonce, 12, aad, aadLen, data, len,
                                       out.data(), out.size(), &outLen);
    psa_destroy_key(id);
    if (st != PSA_SUCCESS || outLen != len + 16) return false;
    for (size_t i = 0; i < len; i++) data[i] = out[i];
    for (size_t i = 0; i < 16; i++) tag[i] = out[len + i];
    return true;
}

bool chachaPolyOpen(const uint8_t key[32], const uint8_t nonce[12], const uint8_t *aad, size_t aadLen,
                    uint8_t *data, size_t len, const uint8_t tag[16])
{
    if (!psaReady()) return false;
    psa_key_id_t id = PSA_KEY_ID_NULL;
    if (!importChacha(key, id)) return false;
    std::vector<uint8_t> in(len + 16);
    for (size_t i = 0; i < len; i++) in[i] = data[i];
    for (size_t i = 0; i < 16; i++) in[len + i] = tag[i];
    std::vector<uint8_t> out(len > 0 ? len : 1);
    size_t outLen = 0;
    psa_status_t st = psa_aead_decrypt(id, PSA_ALG_CHACHA20_POLY1305, nonce, 12, aad, aadLen, in.data(), in.size(),
                                       out.data(), out.size(), &outLen);
    psa_destroy_key(id);
    if (st != PSA_SUCCESS || outLen != len) return false;
    for (size_t i = 0; i < len; i++) data[i] = out[i];
    return true;
}

} // namespace meshport
