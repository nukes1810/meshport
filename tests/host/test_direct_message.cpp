// Host tests for src/meshport/DirectMessage.* (full frame path with OpenSSL primitives).
// Build: compile test_direct_message.cpp with DirectMessage, SecureDirect, MeshtasticFrame,
// MeshtasticProto, MeshtasticCrypto, MeshtasticWire, openssl_secure_backend.cpp, openssl_aes_backend.cpp; link -lcrypto.
#include "DirectMessage.h"

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

static uint8_t kChannelKey[16] = {0xd4, 0xf1, 0xbb, 0x3a, 0x20, 0x29, 0x07, 0x59,
                                  0xf0, 0xbc, 0xff, 0xab, 0xcf, 0x4e, 0x69, 0x01};

static Identity makeId(uint8_t seedByte)
{
    uint8_t seed[32];
    for (int i = 0; i < 32; i++) seed[i] = static_cast<uint8_t>(seedByte + i * 11);
    Identity id{};
    CHECK(identityFromSeed(seed, id));
    return id;
}

static void testRoundTrip()
{
    Identity alice = makeId(1), bob = makeId(100);
    uint32_t bobNode = nodeNumberFromPublicKey(bob.pub);
    std::vector<uint8_t> frame;
    CHECK(buildDirectFrame(kChannelKey, 16, 0x08, alice, bobNode, bob.pub, 1, "rendezvous at 6", 42, frame));

    ReplayGuard guard;
    uint32_t from = 0;
    std::string text;
    CHECK(openDirectFrame(kChannelKey, 16, bob, frame.data(), frame.size(), guard, from, text));
    CHECK(from == nodeNumberFromPublicKey(alice.pub));
    CHECK(text == "rendezvous at 6");
}

static void testPlaintextNotOnAir()
{
    Identity alice = makeId(2), bob = makeId(101);
    std::vector<uint8_t> frame;
    std::string secret = "the password is swordfish";
    CHECK(buildDirectFrame(kChannelKey, 16, 0x08, alice, nodeNumberFromPublicKey(bob.pub), bob.pub, 1, secret, 1, frame));
    std::string onAir(frame.begin(), frame.end());
    CHECK(onAir.find("swordfish") == std::string::npos);
}

static void testWrongRecipientCannotRead()
{
    Identity alice = makeId(3), bob = makeId(102), eve = makeId(103);
    std::vector<uint8_t> frame;
    CHECK(buildDirectFrame(kChannelKey, 16, 0x08, alice, nodeNumberFromPublicKey(bob.pub), bob.pub, 1, "for bob", 1, frame));
    ReplayGuard guard;
    uint32_t from = 0;
    std::string text;
    CHECK(!openDirectFrame(kChannelKey, 16, eve, frame.data(), frame.size(), guard, from, text));
}

static void testReplayRejected()
{
    Identity alice = makeId(4), bob = makeId(104);
    std::vector<uint8_t> frame;
    CHECK(buildDirectFrame(kChannelKey, 16, 0x08, alice, nodeNumberFromPublicKey(bob.pub), bob.pub, 7, "once", 9, frame));
    ReplayGuard guard;
    uint32_t from = 0;
    std::string text;
    CHECK(openDirectFrame(kChannelKey, 16, bob, frame.data(), frame.size(), guard, from, text));
    CHECK(!openDirectFrame(kChannelKey, 16, bob, frame.data(), frame.size(), guard, from, text));
}

static void testOlderCounterRejected()
{
    Identity alice = makeId(5), bob = makeId(105);
    uint32_t bobNode = nodeNumberFromPublicKey(bob.pub);
    std::vector<uint8_t> f5, f3;
    CHECK(buildDirectFrame(kChannelKey, 16, 0x08, alice, bobNode, bob.pub, 5, "five", 1, f5));
    CHECK(buildDirectFrame(kChannelKey, 16, 0x08, alice, bobNode, bob.pub, 3, "three", 2, f3));
    ReplayGuard guard;
    uint32_t from = 0;
    std::string text;
    CHECK(openDirectFrame(kChannelKey, 16, bob, f5.data(), f5.size(), guard, from, text));
    CHECK(!openDirectFrame(kChannelKey, 16, bob, f3.data(), f3.size(), guard, from, text));
}

static void testTamperRejected()
{
    Identity alice = makeId(6), bob = makeId(106);
    std::vector<uint8_t> frame;
    CHECK(buildDirectFrame(kChannelKey, 16, 0x08, alice, nodeNumberFromPublicKey(bob.pub), bob.pub, 1, "intact", 3, frame));
    frame[frame.size() - 1] ^= 0x01;
    ReplayGuard guard;
    uint32_t from = 0;
    std::string text;
    CHECK(!openDirectFrame(kChannelKey, 16, bob, frame.data(), frame.size(), guard, from, text));
}

static void testNodeNumberStable()
{
    Identity a = makeId(7);
    CHECK(nodeNumberFromPublicKey(a.pub) == nodeNumberFromPublicKey(a.pub));
    CHECK(nodeNumberFromPublicKey(a.pub) == (static_cast<uint32_t>(a.pub[0]) | (static_cast<uint32_t>(a.pub[1]) << 8) |
                                             (static_cast<uint32_t>(a.pub[2]) << 16) | (static_cast<uint32_t>(a.pub[3]) << 24)));
}

int main()
{
    testRoundTrip();
    testPlaintextNotOnAir();
    testWrongRecipientCannotRead();
    testReplayRejected();
    testOlderCounterRejected();
    testTamperRejected();
    testNodeNumberStable();
    if (failures == 0) {
        std::printf("all direct message tests passed\n");
        return 0;
    }
    std::printf("%d failure(s)\n", failures);
    return 1;
}
