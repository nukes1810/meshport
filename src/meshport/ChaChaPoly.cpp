#include "ChaChaPoly.h"

#include <cstring>
#include <vector>

namespace meshport {

namespace {

inline uint32_t rotl(uint32_t v, int n) { return (v << n) | (v >> (32 - n)); }

inline uint32_t le32(const uint8_t *p)
{
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) | ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

inline void store32(uint8_t *p, uint32_t v)
{
    p[0] = (uint8_t)v; p[1] = (uint8_t)(v >> 8); p[2] = (uint8_t)(v >> 16); p[3] = (uint8_t)(v >> 24);
}

void quarter(uint32_t &a, uint32_t &b, uint32_t &c, uint32_t &d)
{
    a += b; d ^= a; d = rotl(d, 16);
    c += d; b ^= c; b = rotl(b, 12);
    a += b; d ^= a; d = rotl(d, 8);
    c += d; b ^= c; b = rotl(b, 7);
}

void chachaBlock(const uint8_t key[32], const uint8_t nonce[12], uint32_t counter, uint8_t out[64])
{
    uint32_t s[16];
    s[0] = 0x61707865; s[1] = 0x3320646e; s[2] = 0x79622d32; s[3] = 0x6b206574;
    for (int i = 0; i < 8; i++) s[4 + i] = le32(key + 4 * i);
    s[12] = counter;
    for (int i = 0; i < 3; i++) s[13 + i] = le32(nonce + 4 * i);

    uint32_t x[16];
    std::memcpy(x, s, sizeof(x));
    for (int i = 0; i < 10; i++) {
        quarter(x[0], x[4], x[8], x[12]);
        quarter(x[1], x[5], x[9], x[13]);
        quarter(x[2], x[6], x[10], x[14]);
        quarter(x[3], x[7], x[11], x[15]);
        quarter(x[0], x[5], x[10], x[15]);
        quarter(x[1], x[6], x[11], x[12]);
        quarter(x[2], x[7], x[8], x[13]);
        quarter(x[3], x[4], x[9], x[14]);
    }
    for (int i = 0; i < 16; i++) store32(out + 4 * i, x[i] + s[i]);
}

void chachaXor(const uint8_t key[32], const uint8_t nonce[12], uint32_t counter, uint8_t *data, size_t len)
{
    uint8_t block[64];
    size_t off = 0;
    while (off < len) {
        chachaBlock(key, nonce, counter++, block);
        size_t n = (len - off) < 64 ? (len - off) : 64;
        for (size_t i = 0; i < n; i++) data[off + i] ^= block[i];
        off += n;
    }
}

// Poly1305 with 26-bit limbs (poly1305-donna 32-bit style), so no 128-bit integers are needed.
class Poly1305 {
public:
    explicit Poly1305(const uint8_t key[32])
    {
        r_[0] = le32(key + 0) & 0x3ffffff;
        r_[1] = (le32(key + 3) >> 2) & 0x3ffff03;
        r_[2] = (le32(key + 6) >> 4) & 0x3ffc0ff;
        r_[3] = (le32(key + 9) >> 6) & 0x3f03fff;
        r_[4] = (le32(key + 12) >> 8) & 0x00fffff;
        for (int i = 0; i < 5; i++) { h_[i] = 0; s_[i] = (i == 0) ? 0 : r_[i] * 5; }
        for (int i = 0; i < 4; i++) pad_[i] = le32(key + 16 + 4 * i);
    }

    // Processes whole 16-byte blocks; callers zero-pad the input to a multiple of 16.
    void blocks(const uint8_t *m, size_t bytes)
    {
        const uint32_t hibit = 1u << 24;
        const uint32_t *r = r_;
        const uint32_t s1 = s_[1], s2 = s_[2], s3 = s_[3], s4 = s_[4];
        uint32_t h0 = h_[0], h1 = h_[1], h2 = h_[2], h3 = h_[3], h4 = h_[4];
        while (bytes >= 16) {
            h0 += le32(m + 0) & 0x3ffffff;
            h1 += (le32(m + 3) >> 2) & 0x3ffffff;
            h2 += (le32(m + 6) >> 4) & 0x3ffffff;
            h3 += (le32(m + 9) >> 6) & 0x3ffffff;
            h4 += (le32(m + 12) >> 8) | hibit;

            uint64_t d0 = (uint64_t)h0 * r[0] + (uint64_t)h1 * s4 + (uint64_t)h2 * s3 + (uint64_t)h3 * s2 + (uint64_t)h4 * s1;
            uint64_t d1 = (uint64_t)h0 * r[1] + (uint64_t)h1 * r[0] + (uint64_t)h2 * s4 + (uint64_t)h3 * s3 + (uint64_t)h4 * s2;
            uint64_t d2 = (uint64_t)h0 * r[2] + (uint64_t)h1 * r[1] + (uint64_t)h2 * r[0] + (uint64_t)h3 * s4 + (uint64_t)h4 * s3;
            uint64_t d3 = (uint64_t)h0 * r[3] + (uint64_t)h1 * r[2] + (uint64_t)h2 * r[1] + (uint64_t)h3 * r[0] + (uint64_t)h4 * s4;
            uint64_t d4 = (uint64_t)h0 * r[4] + (uint64_t)h1 * r[3] + (uint64_t)h2 * r[2] + (uint64_t)h3 * r[1] + (uint64_t)h4 * r[0];

            uint32_t c = (uint32_t)(d0 >> 26); h0 = (uint32_t)d0 & 0x3ffffff;
            d1 += c; c = (uint32_t)(d1 >> 26); h1 = (uint32_t)d1 & 0x3ffffff;
            d2 += c; c = (uint32_t)(d2 >> 26); h2 = (uint32_t)d2 & 0x3ffffff;
            d3 += c; c = (uint32_t)(d3 >> 26); h3 = (uint32_t)d3 & 0x3ffffff;
            d4 += c; c = (uint32_t)(d4 >> 26); h4 = (uint32_t)d4 & 0x3ffffff;
            h0 += c * 5; c = h0 >> 26; h0 &= 0x3ffffff;
            h1 += c;

            m += 16;
            bytes -= 16;
        }
        h_[0] = h0; h_[1] = h1; h_[2] = h2; h_[3] = h3; h_[4] = h4;
    }

    void finish(uint8_t mac[16])
    {
        uint32_t h0 = h_[0], h1 = h_[1], h2 = h_[2], h3 = h_[3], h4 = h_[4];
        uint32_t c = h1 >> 26; h1 &= 0x3ffffff;
        h2 += c; c = h2 >> 26; h2 &= 0x3ffffff;
        h3 += c; c = h3 >> 26; h3 &= 0x3ffffff;
        h4 += c; c = h4 >> 26; h4 &= 0x3ffffff;
        h0 += c * 5; c = h0 >> 26; h0 &= 0x3ffffff;
        h1 += c;

        // Compute h - p; keep it only if h >= p.
        uint32_t g0 = h0 + 5; c = g0 >> 26; g0 &= 0x3ffffff;
        uint32_t g1 = h1 + c; c = g1 >> 26; g1 &= 0x3ffffff;
        uint32_t g2 = h2 + c; c = g2 >> 26; g2 &= 0x3ffffff;
        uint32_t g3 = h3 + c; c = g3 >> 26; g3 &= 0x3ffffff;
        uint32_t g4 = h4 + c - (1u << 26);

        uint32_t mask = (g4 >> 31) - 1;   // all ones when h >= p
        g0 &= mask; g1 &= mask; g2 &= mask; g3 &= mask; g4 &= mask;
        mask = ~mask;
        h0 = (h0 & mask) | g0;
        h1 = (h1 & mask) | g1;
        h2 = (h2 & mask) | g2;
        h3 = (h3 & mask) | g3;
        h4 = (h4 & mask) | g4;

        // Repack into four 32-bit words.
        uint32_t w0 = (h0) | (h1 << 26);
        uint32_t w1 = (h1 >> 6) | (h2 << 20);
        uint32_t w2 = (h2 >> 12) | (h3 << 14);
        uint32_t w3 = (h3 >> 18) | (h4 << 8);

        uint64_t f = (uint64_t)w0 + pad_[0];
        store32(mac + 0, (uint32_t)f);
        f = (uint64_t)w1 + pad_[1] + (f >> 32);
        store32(mac + 4, (uint32_t)f);
        f = (uint64_t)w2 + pad_[2] + (f >> 32);
        store32(mac + 8, (uint32_t)f);
        f = (uint64_t)w3 + pad_[3] + (f >> 32);
        store32(mac + 12, (uint32_t)f);
    }

private:
    uint32_t r_[5];
    uint32_t s_[5];
    uint32_t h_[5];
    uint32_t pad_[4];
};

void computeTag(const uint8_t key[32], const uint8_t nonce[12], const uint8_t *aad, size_t aadLen,
                const uint8_t *ct, size_t ctLen, uint8_t tag[16])
{
    uint8_t polyKey[64];
    chachaBlock(key, nonce, 0, polyKey);

    // MAC input: AAD padded to 16, ciphertext padded to 16, then both lengths as 64-bit LE.
    size_t aadPadded = (aadLen + 15) & ~(size_t)15;
    size_t ctPadded = (ctLen + 15) & ~(size_t)15;
    std::vector<uint8_t> in(aadPadded + ctPadded + 16, 0);
    if (aadLen) std::memcpy(in.data(), aad, aadLen);
    if (ctLen) std::memcpy(in.data() + aadPadded, ct, ctLen);
    uint8_t *lens = in.data() + aadPadded + ctPadded;
    for (int i = 0; i < 8; i++) {
        lens[i] = (uint8_t)((uint64_t)aadLen >> (8 * i));
        lens[8 + i] = (uint8_t)((uint64_t)ctLen >> (8 * i));
    }

    Poly1305 poly(polyKey);
    poly.blocks(in.data(), in.size());
    poly.finish(tag);
}

bool constTimeEqual(const uint8_t *a, const uint8_t *b, size_t n)
{
    uint8_t diff = 0;
    for (size_t i = 0; i < n; i++) diff |= (uint8_t)(a[i] ^ b[i]);
    return diff == 0;
}

} // namespace

bool chachaPolyEncrypt(const uint8_t key[32], const uint8_t nonce[12], const uint8_t *aad, size_t aadLen,
                       uint8_t *data, size_t len, uint8_t tag[16])
{
    chachaXor(key, nonce, 1, data, len);
    computeTag(key, nonce, aad, aadLen, data, len, tag);
    return true;
}

bool chachaPolyDecrypt(const uint8_t key[32], const uint8_t nonce[12], const uint8_t *aad, size_t aadLen,
                       uint8_t *data, size_t len, const uint8_t tag[16])
{
    uint8_t expected[16];
    computeTag(key, nonce, aad, aadLen, data, len, expected);
    if (!constTimeEqual(expected, tag, 16)) return false;
    chachaXor(key, nonce, 1, data, len);
    return true;
}

} // namespace meshport
