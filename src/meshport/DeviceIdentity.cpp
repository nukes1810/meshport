#ifdef ARDUINO

#include "DeviceIdentity.h"

#include <Preferences.h>
#include <esp_random.h>

namespace meshport {

namespace {
constexpr const char *kNamespace = "meshport";
constexpr const char *kSeedKey = "seed";
} // namespace

bool loadOrCreateIdentity(Identity &out)
{
    Preferences prefs;
    if (!prefs.begin(kNamespace, false)) {
        return false;
    }
    uint8_t seed[32];
    if (prefs.isKey(kSeedKey) && prefs.getBytesLength(kSeedKey) == 32) {
        prefs.getBytes(kSeedKey, seed, 32);
    } else {
        for (int i = 0; i < 32; i += 4) {
            uint32_t r = esp_random();
            seed[i] = static_cast<uint8_t>(r);
            seed[i + 1] = static_cast<uint8_t>(r >> 8);
            seed[i + 2] = static_cast<uint8_t>(r >> 16);
            seed[i + 3] = static_cast<uint8_t>(r >> 24);
        }
        if (prefs.putBytes(kSeedKey, seed, 32) != 32) {
            prefs.end();
            return false;
        }
    }
    prefs.end();
    return identityFromSeed(seed, out);
}

bool resetIdentity()
{
    Preferences prefs;
    if (!prefs.begin(kNamespace, false)) {
        return false;
    }
    bool ok = prefs.remove(kSeedKey);
    prefs.end();
    return ok;
}

} // namespace meshport

#endif // ARDUINO
