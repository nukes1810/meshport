// Host tests for src/meshport/SecureDirect.* (OpenSSL primitive backend).
// Build: see the g++ line in README.md (or: test_secure_direct.cpp, SecureDirect.cpp,
// openssl_secure_backend.cpp, -lcrypto).
#include "SecureDirect.h"

#include <cstdio>
#include <cstring>
#include <string>

static int failures = 0;
#define CHECK(cond)                                                     \
    do {                                                                \
        if (!(cond)) {                                                  \
            std::printf("FAIL %s:%d: %s\n", __FILE__, __LINE__, #cond); \
            failures++;                                                 \
        }                                                               \
    } while (0)

using namespace meshport;

static void hexToBytes(const char *hex, uint8_t *out, size_t n)
{
    for (size_t i = 0; i < n; i++) {
        unsigned int b;
        std::sscanf(hex + 2 * i, "%2x", &b);
        out[i] = static_cast<uint8_t>(b);
    }
}

// RFC 7748 section 6.1 (Alice and Bob X25519 vectors)
static void testX25519Rfc7748()
{
    uint8_t alicePriv[32], alicePubExp[32], bobPriv[32], bobPubExp[32], sharedExp[32];
    hexToBytes("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a", alicePriv, 32);
    hexToBytes("8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a", alicePubExp, 32);
    hexToBytes("5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb", bobPriv, 32);
    hexToBytes("de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f", bobPubExp, 32);
    hexToBytes("4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742", sharedExp, 32);

    uint8_t pub[32], shared1[32], shared2[32];
    CHECK(x25519PublicKey(alicePriv, pub));
    CHECK(std::memcmp(pub, alicePubExp, 32) == 0);
    CHECK(x25519PublicKey(bobPriv, pub));
    CHECK(std::memcmp(pub, bobPubExp, 32) == 0);
    CHECK(x25519SharedSecret(alicePriv, bobPubExp, shared1));
    CHECK(x25519SharedSecret(bobPriv, alicePubExp, shared2));
    CHECK(std::memcmp(shared1, sharedExp, 32) == 0);
    CHECK(std::memcmp(shared2, sharedExp, 32) == 0);
}

// RFC 5869 test case 1 (HKDF-SHA256)
static void testHkdfRfc5869()
{
    uint8_t ikm[22], salt[13], info[10], okmExp[42], okm[42];
    std::memset(ikm, 0x0b, sizeof(ikm));
    for (int i = 0; i < 13; i++) salt[i] = static_cast<uint8_t>(i);
    for (int i = 0; i < 10; i++) info[i] = static_cast<uint8_t>(0xf0 + i);
    hexToBytes("3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865", okmExp, 42);
    CHECK(hkdfSha256(ikm, 22, salt, 13, info, 10, okm, 42));
    CHECK(std::memcmp(okm, okmExp, 42) == 0);
}

static void testDirectKeyAgreement()
{
    uint8_t aPriv[32], bPriv[32], aPub[32], bPub[32], kab[32], kba[32];
    for (int i = 0; i < 32; i++) { aPriv[i] = static_cast<uint8_t>(i * 3 + 1); bPriv[i] = static_cast<uint8_t>(255 - i * 5); }
    CHECK(x25519PublicKey(aPriv, aPub));
    CHECK(x25519PublicKey(bPriv, bPub));
    CHECK(deriveDirectKey(aPriv, bPub, kab));
    CHECK(deriveDirectKey(bPriv, aPub, kba));
    CHECK(std::memcmp(kab, kba, 32) == 0);
}

static void testSealOpenRoundTrip()
{
    uint8_t key[32];
    for (int i = 0; i < 32; i++) key[i] = static_cast<uint8_t>(i + 7);
    std::string msg = "meet at the north gate at 6";
    std::vector<uint8_t> ct, pt;
    CHECK(sealDirect(key, 1, nullptr, 0, reinterpret_cast<const uint8_t *>(msg.data()), msg.size(), ct));
    CHECK(ct.size() == msg.size() + 16);
    CHECK(openDirect(key, 1, nullptr, 0, ct.data(), ct.size(), pt));
    CHECK(std::string(pt.begin(), pt.end()) == msg);
}

static void testTamperDetected()
{
    uint8_t key[32] = {1};
    std::string msg = "pay nobody";
    std::vector<uint8_t> ct, pt;
    CHECK(sealDirect(key, 5, nullptr, 0, reinterpret_cast<const uint8_t *>(msg.data()), msg.size(), ct));
    ct[3] ^= 0x01; // flip one bit of the ciphertext
    CHECK(!openDirect(key, 5, nullptr, 0, ct.data(), ct.size(), pt));
    CHECK(pt.empty());
}

static void testWrongKeyOrCounterRejected()
{
    uint8_t key[32] = {9}, other[32] = {10};
    std::string msg = "hello";
    std::vector<uint8_t> ct, pt;
    CHECK(sealDirect(key, 1, nullptr, 0, reinterpret_cast<const uint8_t *>(msg.data()), msg.size(), ct));
    CHECK(!openDirect(other, 1, nullptr, 0, ct.data(), ct.size(), pt));
    CHECK(!openDirect(key, 2, nullptr, 0, ct.data(), ct.size(), pt));
}

static void testAadBound()
{
    uint8_t key[32] = {4};
    const uint8_t aad1[] = {'A'}, aad2[] = {'B'};
    std::string msg = "bound";
    std::vector<uint8_t> ct, pt;
    CHECK(sealDirect(key, 3, aad1, 1, reinterpret_cast<const uint8_t *>(msg.data()), msg.size(), ct));
    CHECK(!openDirect(key, 3, aad2, 1, ct.data(), ct.size(), pt));
    CHECK(openDirect(key, 3, aad1, 1, ct.data(), ct.size(), pt));
}

static void testSamePlainDifferentCounter()
{
    uint8_t key[32] = {2};
    std::string msg = "same text";
    std::vector<uint8_t> c1, c2;
    CHECK(sealDirect(key, 1, nullptr, 0, reinterpret_cast<const uint8_t *>(msg.data()), msg.size(), c1));
    CHECK(sealDirect(key, 2, nullptr, 0, reinterpret_cast<const uint8_t *>(msg.data()), msg.size(), c2));
    CHECK(c1 != c2);
}

int main()
{
    testX25519Rfc7748();
    testHkdfRfc5869();
    testDirectKeyAgreement();
    testSealOpenRoundTrip();
    testTamperDetected();
    testWrongKeyOrCounterRejected();
    testAadBound();
    testSamePlainDifferentCounter();
    if (failures == 0) {
        std::printf("all secure direct tests passed\n");
        return 0;
    }
    std::printf("%d failure(s)\n", failures);
    return 1;
}
