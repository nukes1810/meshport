// Per-device identity stored in flash (ESP32 Preferences / NVS). Device-only.
// The 32-byte seed is created once from the hardware RNG and kept across reboots.
// Compiled only on the device (ARDUINO); not part of the host tests.
#pragma once

#ifdef ARDUINO

#include "DirectMessage.h"

namespace meshport {

// Load the identity from flash, or create and save a new one on first boot.
// Call after the radio has started: the hardware RNG is only fully random while the RF subsystem runs.
bool loadOrCreateIdentity(Identity &out);

// Erase the stored identity. A new one is created on the next loadOrCreateIdentity().
bool resetIdentity();

} // namespace meshport

#endif // ARDUINO
