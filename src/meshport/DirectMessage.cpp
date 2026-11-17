#include "DirectMessage.h"

#include <cstring>

namespace meshport {

bool identityFromSeed(const uint8_t seed[32], Identity &id)
{
    std::memcpy(id.priv, seed, 32);
    return x25519PublicKey(id.priv, id.pub);
}

uint32_t nodeNumberFromPublicKey(const uint8_t pub[32])
{
    return static_cast<uint32_t>(pub[0]) | (static_cast<uint32_t>(pub[1]) << 8) |
           (static_cast<uint32_t>(pub[2]) << 16) | (static_cast<uint32_t>(pub[3]) << 24);
}

bool ReplayGuard::accept(const uint8_t senderPub[32], uint64_t counter)
{
    for (Entry &e : entries_) {
        if (std::memcmp(e.pub, senderPub, 32) == 0) {
            if (counter <= e.last) {
                return false;
            }
            e.last = counter;
            return true;
        }
    }
    Entry e{};
    std::memcpy(e.pub, senderPub, 32);
    e.last = counter;
    entries_.push_back(e);
    return true;
}

namespace {

void putU64(std::vector<uint8_t> &v, uint64_t x)
{
    for (int i = 0; i < 8; i++) v.push_back(static_cast<uint8_t>(x >> (8 * i)));
}

uint64_t getU64(const uint8_t *p)
{
    uint64_t x = 0;
    for (int i = 0; i < 8; i++) x |= static_cast<uint64_t>(p[i]) << (8 * i);
    return x;
}

void aadFor(uint32_t fromNode, uint32_t toNode, uint8_t aad[8])
{
    for (int i = 0; i < 4; i++) {
        aad[i] = static_cast<uint8_t>(fromNode >> (8 * i));
        aad[4 + i] = static_cast<uint8_t>(toNode >> (8 * i));
    }
}

} // namespace

bool buildDirectFrame(const uint8_t channelPsk[32], size_t channelPskLen, uint8_t channelHash,
                      const Identity &me, uint32_t toNode, const uint8_t peerPub[32], uint64_t counter,
                      const std::string &text, uint32_t packetId, std::vector<uint8_t> &frame)
{
    uint8_t key[32];
    if (!deriveDirectKey(me.priv, peerPub, key)) {
        return false;
    }
    uint32_t fromNode = nodeNumberFromPublicKey(me.pub);
    uint8_t aad[8];
    aadFor(fromNode, toNode, aad);

    std::vector<uint8_t> sealed;
    if (!sealDirect(key, counter, aad, sizeof(aad),
                    reinterpret_cast<const uint8_t *>(text.data()), text.size(), sealed)) {
        return false;
    }

    Data d;
    d.portnum = kPortDirect;
    d.payload.push_back(kDirectVersion);
    d.payload.insert(d.payload.end(), me.pub, me.pub + 32);
    putU64(d.payload, counter);
    d.payload.insert(d.payload.end(), sealed.begin(), sealed.end());

    Header h{};
    h.to = toNode;
    h.from = fromNode;
    h.id = packetId;
    h.flags = 0x03 | (0x03 << kFlagHopStartShift);
    h.channel = channelHash;
    return sealFrame(channelPsk, channelPskLen, h, d, frame);
}

bool openDirectFrame(const uint8_t channelPsk[32], size_t channelPskLen, const Identity &me,
                     const uint8_t *frame, size_t len, ReplayGuard &guard, uint32_t &fromNode,
                     std::string &text)
{
    Header h{};
    Data d;
    if (!openFrame(channelPsk, channelPskLen, frame, len, h, d)) {
        return false;
    }
    if (d.portnum != kPortDirect || d.payload.size() <= kDirectHeaderLen) {
        return false;
    }
    if (h.to != nodeNumberFromPublicKey(me.pub)) {
        return false;
    }
    const uint8_t *p = d.payload.data();
    if (p[0] != kDirectVersion) {
        return false;
    }
    const uint8_t *senderPub = p + 1;
    uint64_t counter = getU64(p + 33);

    uint8_t key[32];
    if (!deriveDirectKey(me.priv, senderPub, key)) {
        return false;
    }
    uint8_t aad[8];
    aadFor(h.from, h.to, aad);

    // The sender's claimed node number must match its key.
    if (nodeNumberFromPublicKey(senderPub) != h.from) {
        return false;
    }

    std::vector<uint8_t> plain;
    if (!openDirect(key, counter, aad, sizeof(aad), p + kDirectHeaderLen,
                    d.payload.size() - kDirectHeaderLen, plain)) {
        return false;
    }
    if (!guard.accept(senderPub, counter)) {
        return false; // replay
    }
    fromNode = h.from;
    text.assign(plain.begin(), plain.end());
    return true;
}

} // namespace meshport
