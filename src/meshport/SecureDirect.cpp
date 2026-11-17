#include "SecureDirect.h"

#include <cstring>

namespace meshport {

namespace {

const char kDirectInfo[] = "meshport direct v1";

void nonceFromCounter(uint64_t counter, uint8_t nonce[12])
{
    std::memset(nonce, 0, 12);
    for (int i = 0; i < 8; i++) {
        nonce[4 + i] = static_cast<uint8_t>(counter >> (8 * i));
    }
}

} // namespace

bool deriveDirectKey(const uint8_t myPriv[32], const uint8_t theirPub[32], uint8_t key[32])
{
    uint8_t shared[32];
    if (!x25519SharedSecret(myPriv, theirPub, shared)) {
        return false;
    }
    bool ok = hkdfSha256(shared, sizeof(shared), nullptr, 0,
                         reinterpret_cast<const uint8_t *>(kDirectInfo), sizeof(kDirectInfo) - 1, key, 32);
    std::memset(shared, 0, sizeof(shared));
    return ok;
}

bool sealDirect(const uint8_t key[32], uint64_t counter, const uint8_t *aad, size_t aadLen,
                const uint8_t *plain, size_t plainLen, std::vector<uint8_t> &out)
{
    uint8_t nonce[12];
    nonceFromCounter(counter, nonce);
    out.assign(plain, plain + plainLen);
    uint8_t tag[16];
    if (!chachaPolySeal(key, nonce, aad, aadLen, out.data(), out.size(), tag)) {
        return false;
    }
    out.insert(out.end(), tag, tag + 16);
    return true;
}

bool openDirect(const uint8_t key[32], uint64_t counter, const uint8_t *aad, size_t aadLen,
                const uint8_t *in, size_t inLen, std::vector<uint8_t> &plain)
{
    if (inLen < 16) {
        return false;
    }
    uint8_t nonce[12];
    nonceFromCounter(counter, nonce);
    size_t n = inLen - 16;
    plain.assign(in, in + n);
    if (!chachaPolyOpen(key, nonce, aad, aadLen, plain.data(), plain.size(), in + n)) {
        plain.clear();
        return false;
    }
    return true;
}

} // namespace meshport
