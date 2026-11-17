// meshport chat (serial console), first working build.
// Build: pio run -e meshport_chat -t upload    Monitor: pio device monitor -e meshport_chat
//
// ANTENNA MUST BE ATTACHED before running.
//
// Commands (type into the serial monitor, press Enter):
//   id            show this device's node number and public key
//   peer <hex>    set the other device's public key (64 hex characters)
//   send <text>   send an encrypted direct message to the peer
//   help          list commands
// Incoming direct messages are printed as they arrive.
//
// Unity build: the meshport sources are included directly.
#include <Arduino.h>
#include <SPI.h>
#include <RadioLib.h>

#include "../MeshtasticWire.cpp"
#include "../MeshtasticCrypto.cpp"
#include "../MeshtasticCryptoBackend_mbedtls.cpp"
#include "../MeshtasticProto.cpp"
#include "../MeshtasticFrame.cpp"
#include "../MeshtasticChannelPlan.cpp"
#include "../MeshtasticRadio.cpp"
#include "../SecureDirect.cpp"
#include "../SecureBackend_psa.cpp"
#include "../DirectMessage.cpp"
#include "../DeviceIdentity.cpp"

using namespace meshport;

// Meshtastic T-Deck pins (variants/esp32s3/t-deck/variant.h).
#define CHAT_LORA_SCK 40
#define CHAT_LORA_MISO 38
#define CHAT_LORA_MOSI 41
#define CHAT_LORA_CS 9
#define CHAT_LORA_RESET 17
#define CHAT_LORA_DIO1 45
#define CHAT_LORA_BUSY 13

// Default LongFast key (public). Direct messages are end-to-end encrypted on top of it.
static const uint8_t kChannelKey[16] = {0xd4, 0xf1, 0xbb, 0x3a, 0x20, 0x29, 0x07, 0x59,
                                        0xf0, 0xbc, 0xff, 0xab, 0xcf, 0x4e, 0x69, 0x01};

static const float kRegionStartMHz = 902.0f;
static const float kRegionEndMHz = 928.0f;

static SPIClass loraSpi;
static SX1262 *radio = nullptr;
static MeshtasticRadio *driver = nullptr;
static Identity me{};
static uint32_t myNode = 0;
static uint8_t channelByte = 0;
static bool havePeer = false;
static uint8_t peerPub[32] = {0};
static uint64_t sendCounter = 0;
static uint32_t packetCounter = 0;
static ReplayGuard guard;
static String line;

static void printHex(const uint8_t *p, size_t n)
{
    for (size_t i = 0; i < n; i++) Serial.printf("%02x", p[i]);
}

static bool parseHex(const String &s, uint8_t *out, size_t n)
{
    if (s.length() != n * 2) return false;
    for (size_t i = 0; i < n; i++) {
        char hi = s[2 * i], lo = s[2 * i + 1];
        auto nib = [](char c) -> int {
            if (c >= '0' && c <= '9') return c - '0';
            if (c >= 'a' && c <= 'f') return c - 'a' + 10;
            if (c >= 'A' && c <= 'F') return c - 'A' + 10;
            return -1;
        };
        int h = nib(hi), l = nib(lo);
        if (h < 0 || l < 0) return false;
        out[i] = static_cast<uint8_t>(h * 16 + l);
    }
    return true;
}

static void showId()
{
    Serial.printf("node %08lX\npublic key ", (unsigned long)myNode);
    printHex(me.pub, 32);
    Serial.println();
}

static void sendText(const String &text)
{
    if (!havePeer) {
        Serial.println("no peer set: use  peer <hex>");
        return;
    }
    sendCounter++;
    packetCounter++;
    std::vector<uint8_t> frame;
    uint32_t toNode = nodeNumberFromPublicKey(peerPub);
    if (!buildDirectFrame(kChannelKey, sizeof(kChannelKey), channelByte, me, toNode, peerPub, sendCounter,
                          std::string(text.c_str()), packetCounter, frame)) {
        Serial.println("could not build message");
        return;
    }
    if (driver->send(frame)) {
        Serial.printf("sent (%u bytes on air)\n", (unsigned)frame.size());
    } else {
        Serial.printf("send failed, RadioLib code %d\n", (int)driver->lastTxError());
    }
}

static void handleLine(String cmd)
{
    cmd.trim();
    if (cmd.length() == 0) return;
    if (cmd == "help") {
        Serial.println("id | peer <hex> | send <text> | help");
    } else if (cmd == "id") {
        showId();
    } else if (cmd.startsWith("peer ")) {
        if (parseHex(cmd.substring(5), peerPub, 32)) {
            havePeer = true;
            Serial.printf("peer set, node %08lX\n", (unsigned long)nodeNumberFromPublicKey(peerPub));
        } else {
            Serial.println("peer needs 64 hex characters");
        }
    } else if (cmd.startsWith("send ")) {
        sendText(cmd.substring(5));
    } else {
        Serial.println("unknown command, type help");
    }
}

void setup()
{
    Serial.begin(115200);
    delay(1500);
    Serial.println("meshport chat");

    // T-Deck peripheral power (LoRa radio). Must be HIGH before the radio responds.
    pinMode(10, OUTPUT);
    digitalWrite(10, HIGH);
    delay(200);

    loraSpi.begin(CHAT_LORA_SCK, CHAT_LORA_MISO, CHAT_LORA_MOSI, CHAT_LORA_CS);
    Module *mod = new Module(CHAT_LORA_CS, CHAT_LORA_DIO1, CHAT_LORA_RESET, CHAT_LORA_BUSY, loraSpi);
    radio = new SX1262(mod);
    driver = new MeshtasticRadio(*radio);

    uint32_t slot = defaultSlotForChannel("LongFast", kRegionStartMHz, kRegionEndMHz, kLongFastBandwidthKHz / 1000.0f);
    float freq = slotCenterMHz(kRegionStartMHz, kLongFastBandwidthKHz / 1000.0f, slot);
    RadioSettings s{};
    s.freqMHz = freq;
    s.bwKHz = kLongFastBandwidthKHz;
    s.sf = kLongFastSpreadingFactor;
    s.cr = kLongFastCodingRateDenom;
    s.syncWord = kLongFastSyncWord;
    s.preambleLen = kLongFastPreambleLen;
    s.powerDbm = 14;
    s.tcxoVoltage = 1.8f;
    s.useLdo = false;
    if (!driver->begin(s)) {
        Serial.printf("radio begin FAILED, RadioLib code %d\n", (int)driver->lastBeginError());
        while (true) delay(1000);
    }

    // Identity after the radio starts, so the hardware RNG is fully random.
    if (!loadOrCreateIdentity(me)) {
        Serial.println("identity FAILED");
        while (true) delay(1000);
    }
    myNode = nodeNumberFromPublicKey(me.pub);
    channelByte = static_cast<uint8_t>(channelHash("LongFast", kChannelKey, sizeof(kChannelKey)));
    Serial.printf("radio ok: %.3f MHz\n", freq);
    showId();
    Serial.println("type help for commands");
}

void loop()
{
    while (Serial.available()) {
        char c = static_cast<char>(Serial.read());
        if (c == '\n' || c == '\r') {
            if (line.length()) {
                handleLine(line);
                line = "";
            }
        } else {
            line += c;
        }
    }

    std::vector<uint8_t> rx;
    float rssi = 0, snr = 0;
    if (driver->poll(rx, rssi, snr)) {
        uint32_t from = 0;
        std::string text;
        if (openDirectFrame(kChannelKey, sizeof(kChannelKey), me, rx.data(), rx.size(), guard, from, text)) {
            Serial.printf("[%08lX] %s  (rssi %.0f)\n", (unsigned long)from, text.c_str(), rssi);
        }
        // Frames that are not direct messages for this device (other traffic) are ignored.
    }
}
