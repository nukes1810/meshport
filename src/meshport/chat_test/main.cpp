// meshport chat (serial console), first working build.
// Build: pio run -e meshport_chat -t upload    Monitor: pio device monitor -e meshport_chat
//
// ANTENNA MUST BE ATTACHED before running.
//
// Commands (type into the serial monitor, press Enter):
//   id            show this device's node number and public key
//   peer <hex>    set the other device's public key (64 hex characters)
//   send <text>   send an encrypted direct message to the peer
//   pub <text>    send a public message on the default LongFast channel
//                 (readable by any Meshtastic node on the default channel)
//   help          list commands
// Incoming direct messages are printed as they arrive.
//
// Unity build: the meshport sources are included directly.
#include <Arduino.h>
#include <cstring>
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
#include "../ChaChaPoly.cpp"
#include "../SecureBackend_psa.cpp"
#include "../DirectMessage.cpp"
#include "../DeviceIdentity.cpp"
#ifdef MESHPORT_TDECK_SCREEN
#include <Wire.h>
#include "TDeckScreen.h"
#include <WiFi.h>
#include <Preferences.h>
#include <SD.h>
#include <time.h>
#endif

using namespace meshport;
namespace meshport {
int psaHkdfFailStep();
int psaHkdfFailStatus();
}

#ifdef MESHPORT_BOARD_HELTEC_V3
// Heltec WiFi LoRa 32 V3 (ESP32-S3 + SX1262). Vext (GPIO 36) is active LOW.
#define CHAT_LORA_SCK 9
#define CHAT_LORA_MISO 11
#define CHAT_LORA_MOSI 10
#define CHAT_LORA_CS 8
#define CHAT_LORA_RESET 12
#define CHAT_LORA_DIO1 14
#define CHAT_LORA_BUSY 13
#define CHAT_POWER_PIN 36
#define CHAT_POWER_ON LOW
#else
// Meshtastic T-Deck pins (variants/esp32s3/t-deck/variant.h).
#define CHAT_LORA_SCK 40
#define CHAT_LORA_MISO 38
#define CHAT_LORA_MOSI 41
#define CHAT_LORA_CS 9
#define CHAT_LORA_RESET 17
#define CHAT_LORA_DIO1 45
#define CHAT_LORA_BUSY 13
#define CHAT_POWER_PIN 10
#define CHAT_POWER_ON HIGH
#endif

// Default LongFast key (public). Direct messages are end-to-end encrypted on top of it.
static int txDbm = 10;     // TX power in dBm, applied at boot
static int hopLimit = 3;   // hop limit for packets we send

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
static SeenCache seenPublic;
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

static bool sendPublic(const String &text)
{
    packetCounter++;
    Data d;
    d.portnum = kPortTextMessage;
    std::string body(text.c_str());
    d.payload.assign(body.begin(), body.end());
    Header h{};
    h.to = 0xFFFFFFFFu;            // broadcast
    h.from = myNode;
    h.id = packetCounter;
    h.flags = static_cast<uint8_t>(hopLimit | (hopLimit << kFlagHopStartShift));
    h.channel = channelByte;
    std::vector<uint8_t> frame;
    if (!sealFrame(kChannelKey, sizeof(kChannelKey), h, d, frame)) {
        Serial.println("could not build public message");
        return false;
    }
    if (driver->send(frame)) {
        Serial.printf("public sent (%u bytes on air)\n", (unsigned)frame.size());
        return true;
    }
    Serial.printf("send failed, RadioLib code %d\n", (int)driver->lastTxError());
    return false;
}

#ifdef MESHPORT_TDECK_SCREEN
static void setClock(int hh, int mm);
#endif
static void handleLine(String cmd)
{
    cmd.trim();
    if (cmd.length() == 0) return;
    if (cmd == "help") {
        Serial.println("id | peer <hex> | send <text> | pub <text> | diag | help");
    } else if (cmd == "id") {
        showId();
    } else if (cmd == "diag") {
        uint8_t t1[32], t2[32], k[32];
        Serial.printf("x25519 public: %s\n", x25519PublicKey(me.priv, t1) ? "ok" : "FAIL");
        Serial.printf("x25519 shared: %s\n", x25519SharedSecret(me.priv, me.pub, t2) ? "ok" : "FAIL");
        Serial.printf("hkdf derive:   %s\n", deriveDirectKey(me.priv, me.pub, k) ? "ok" : "FAIL");
        Serial.printf("  hkdf failed at step %d (0 import,1 setup,2 salt,3 secret,4 info,5 output), psa status %d\n",
                      psaHkdfFailStep(), psaHkdfFailStatus());
        std::vector<uint8_t> ct;
        uint8_t dummy[4] = {1, 2, 3, 4};
        Serial.printf("seal:          %s\n", sealDirect(k, 1, nullptr, 0, dummy, 4, ct) ? "ok" : "FAIL");
    } else if (cmd.startsWith("peer ")) {
        if (parseHex(cmd.substring(5), peerPub, 32)) {
            havePeer = true;
            Serial.printf("peer set, node %08lX\n", (unsigned long)nodeNumberFromPublicKey(peerPub));
        } else {
            Serial.println("peer needs 64 hex characters");
        }
    } else if (cmd.startsWith("send ")) {
        sendText(cmd.substring(5));
    } else if (cmd.startsWith("pub ")) {
        sendPublic(cmd.substring(4));
#ifdef MESHPORT_TDECK_SCREEN
    } else if (cmd.startsWith("time ") && cmd.length() == 9) {
        int hh = cmd.substring(5, 7).toInt();
        int mm = cmd.substring(7, 9).toInt();
        if (hh >= 0 && hh < 24 && mm >= 0 && mm < 60) {
            setClock(hh, mm);
            Serial.printf("clock set to %02d:%02d\n", hh, mm);
        } else {
            Serial.println("time needs HHMM, e.g. time 1046");
        }
#endif
    } else {
        Serial.println("unknown command, type help");
    }
}

#ifdef MESHPORT_TDECK_SCREEN
// On-device UI: home screen with app tiles, public chat, nodes, settings, and themes.
// Keys: w/a/s/d move, Enter opens or activates, q or Backspace (empty input) goes back.
static LGFX_TDeck lcd;
static LGFX_Sprite canvas(&lcd);
static std::vector<String> chatLines;
static std::vector<uint32_t> chatSeq;   // message number for each chat line
static uint32_t msgSeq = 0;
static int unreadChat = 0;              // incoming messages not yet seen on the Chat screen
static String inputBuf;
static constexpr int kMaxLines = 12;
static constexpr int kLineChars = 36;
static constexpr uint8_t kKeyboardAddr = 0x55;

struct Theme {
    const char *name;
    uint16_t bg, fg, accent, panel;
};
static const Theme kThemes[] = {
    {"Cobalt Ice",   0x0842, 0xF7BE, 0x3DDF, 0x10A4}, // Deep midnight blue + electric cyan
    {"Emerald Dark", 0x0841, 0xF7BE, 0x07EC, 0x10C3}, // Obsidian slate + crisp mint green
    {"Amber Night",  0x0820, 0xFFDF, 0xFD20, 0x18A1}, // Warm carbon + tactical amber
    {"Daylight",     0xEF7D, 0x10A2, 0x039B, 0xFFFF}, // Soft cool gray + crisp white cards
};
static constexpr int kThemeCount = 4;
static int themeIndex = 1;   // Emerald Dark default

enum class Screen { Home, Public, Nodes, Settings, Spectrum, Signal, Soon, Calibrate,
                    SettingsDevice, SettingsLora, SettingsGps, SettingsDisplay, NodeInfo, Map,
                    SettingsWifi, WifiPassword };
static Screen screen = Screen::Home;
static int homeSel = 0;
static int settingsSel = 0;
static const char *kTiles[] = {"Public", "Contacts", "Nodes", "Spectrum", "Signal", "Settings"};
static constexpr int kTileCount = 6;
static const char *soonName = "";

struct NodeEntry {
    uint32_t id;
    float rssi;
    float snr;
    uint32_t firstMs;
    uint32_t lastMs;
    uint32_t count;     // packets heard from this node
    double lat;
    double lon;
    bool hasPos;           // set from the node's POSITION_APP packets
};
static std::vector<NodeEntry> nodes;
static int nodeSel = 0;   // selected row on the Nodes screen, and the node shown in Node Info
static constexpr size_t kMaxNodes = 16;

static void noteNode(uint32_t id, float rssi, float snr)
{
    for (NodeEntry &n : nodes) {
        if (n.id == id) {
            n.rssi = rssi;
            n.snr = snr;
            n.lastMs = millis();
            n.count++;
            return;
        }
    }
    if (nodes.size() < kMaxNodes) nodes.push_back({id, rssi, snr, millis(), millis(), 1, 0.0, 0.0, false});
}

// Meshtastic POSITION_APP payload (protobuf Position): latitude_i is field 1 and
// longitude_i is field 2, both sfixed32 in units of 1e-7 degrees.
static constexpr uint32_t kPortPositionApp = 3;

static bool readVarint(const std::vector<uint8_t> &b, size_t &i, uint64_t &v)
{
    v = 0;
    for (int shift = 0; shift < 64 && i < b.size(); shift += 7) {
        uint8_t c = b[i++];
        v |= static_cast<uint64_t>(c & 0x7F) << shift;
        if (!(c & 0x80)) return true;
    }
    return false;
}

static void notePosition(uint32_t id, const std::vector<uint8_t> &payload)
{
    size_t i = 0;
    bool gotLat = false, gotLon = false;
    int32_t latI = 0, lonI = 0;
    while (i < payload.size()) {
        uint64_t key = 0;
        if (!readVarint(payload, i, key)) break;
        uint32_t field = static_cast<uint32_t>(key >> 3);
        uint8_t wire = static_cast<uint8_t>(key & 7);
        if (wire == 5) {                                   // fixed32
            if (i + 4 > payload.size()) break;
            uint32_t v = payload[i] | (static_cast<uint32_t>(payload[i + 1]) << 8) |
                         (static_cast<uint32_t>(payload[i + 2]) << 16) |
                         (static_cast<uint32_t>(payload[i + 3]) << 24);
            i += 4;
            if (field == 1) { latI = static_cast<int32_t>(v); gotLat = true; }
            else if (field == 2) { lonI = static_cast<int32_t>(v); gotLon = true; }
        } else if (wire == 0) {                            // varint: skip
            uint64_t skip = 0;
            if (!readVarint(payload, i, skip)) break;
        } else if (wire == 2) {                            // length-delimited: skip
            uint64_t len = 0;
            if (!readVarint(payload, i, len)) break;
            i += static_cast<size_t>(len);
        } else {
            break;
        }
    }
    if (!gotLat || !gotLon) return;
    for (NodeEntry &n : nodes) {
        if (n.id == id) {
            n.lat = latI * 1e-7;
            n.lon = lonI * 1e-7;
            n.hasPos = true;
            return;
        }
    }
}

static const Theme &theme() { return kThemes[themeIndex]; }
static bool isLightTheme() { return themeIndex == 3; }

// Spectrum analyzer and signal analyzer.
static float loraFreqMHz = 906.875f;
static constexpr int kSpecPoints = 104;      // 902.00 to 927.75 MHz
static constexpr float kSpecStartMHz = 902.0f;
static constexpr float kSpecStepMHz = 0.25f;
static constexpr int kSpecDbMin = -130;      // plot and color range
static constexpr int kSpecDbMax = -90;
static constexpr int kWfRows = 33;           // waterfall history, 2 px per row
static int specDb[kSpecPoints];
static uint8_t wfRows[kWfRows][kSpecPoints]; // palette index per sweep and point
static int wfHead = 0;                       // next row to write
static bool specScanned = false;
static bool specLive = true;                 // re-sweep continuously while the screen is open
static uint32_t specSweepMs = 0;
static uint16_t specPalette[256];
static bool specPaletteReady = false;
static constexpr size_t kSignalSamples = 60;
static std::vector<float> rssiHist;
static float lastSnr = 0;

static void pushRssi(float rssi)
{
    rssiHist.push_back(rssi);
    if (rssiHist.size() > kSignalSamples) rssiHist.erase(rssiHist.begin());
}

// Heat palette for the waterfall: blue (quiet), cyan, green, yellow, red (loud).
static void buildSpecPalette()
{
    static const int kStops[5][3] = {{0, 0, 255}, {0, 255, 255}, {0, 255, 0}, {255, 255, 0}, {255, 0, 0}};
    for (int i = 0; i < 256; i++) {
        int seg = i * 4 / 256;
        int t = i * 4 - seg * 256;
        int c[3];
        for (int k = 0; k < 3; k++) {
            c[k] = kStops[seg][k] + (kStops[seg + 1][k] - kStops[seg][k]) * t / 255;
        }
        specPalette[i] = static_cast<uint16_t>(((c[0] >> 3) << 11) | ((c[1] >> 2) << 5) | (c[2] >> 3));
    }
    specPaletteReady = true;
}

static int specLevelIndex(int db)
{
    return constrain((constrain(db, kSpecDbMin, kSpecDbMax) - kSpecDbMin) * 255 / (kSpecDbMax - kSpecDbMin), 0, 255);
}

static void sweepSpectrum()
{
    for (int i = 0; i < kSpecPoints; i++) {
        radio->setFrequency(kSpecStartMHz + kSpecStepMHz * i);
        radio->startReceive();
        delayMicroseconds(3000);
        specDb[i] = constrain(static_cast<int>(radio->getRSSI()), -140, -40);
    }
    radio->setFrequency(loraFreqMHz);
    radio->startReceive();
    for (int i = 0; i < kSpecPoints; i++) wfRows[wfHead][i] = static_cast<uint8_t>(specLevelIndex(specDb[i]));
    wfHead = (wfHead + 1) % kWfRows;
    specScanned = true;
    specSweepMs = millis();
}

static const uint16_t kBackgrounds[] = {0, 0x0000, 0x0843, 0x10A2, 0x08C1};
static const char *kBackgroundNames[] = {"Theme", "Pure Black", "Midnight", "Graphite", "Deep Pine"};
static constexpr int kBackgroundCount = 5;
static int bgIndex = 0;
static uint16_t bgColor() { return bgIndex == 0 ? theme().bg : kBackgrounds[bgIndex]; }

static int calStep = 0;
static bool wifiOn = false;
static String wifiSsid, wifiPass;           // saved network
static String wifiPickSsid, wifiPassBuf;    // network chosen on the password screen
static constexpr int kWifiListMax = 4;      // strongest networks shown in the list
static String wifiNames[kWifiListMax];
static int wifiRssis[kWifiListMax];
static bool wifiSecure[kWifiListMax];
static int wifiFound = 0;
static bool wifiNtpStarted = false;
static uint32_t wifiNtpMs = 0;
static void saveWifiCreds();
static bool btOn = false;
static bool gpsOn = false;
static int gpsSats = 0;   // satellites in fix; stays 0 until the GPS module is wired
static constexpr int kSettingsCount = 6;
static constexpr int kWidgetFirst = 6;

static void toggleWifi()
{
    wifiOn = !wifiOn;
    if (wifiOn) {
        WiFi.mode(WIFI_STA);
        if (wifiSsid.length()) WiFi.begin(wifiSsid.c_str(), wifiPass.c_str());
    } else {
        WiFi.disconnect(true);
        WiFi.mode(WIFI_OFF);
        wifiNtpStarted = false;
    }
    saveWifiCreds();
    Serial.printf("wifi %s\n", wifiOn ? "on" : "off");
}

static void toggleBt()
{
    btOn = !btOn;
    Serial.printf("bluetooth %s (radio stack not wired yet)\n", btOn ? "on" : "off");
}

static void toggleGps()
{
    gpsOn = !gpsOn;
    if (!gpsOn) gpsSats = 0;
    Serial.printf("gps %s\n", gpsOn ? "on" : "off");
}

static void addLine(const String &s)
{
    chatLines.push_back(s.substring(0, kLineChars));
    chatSeq.push_back(++msgSeq);
    while (chatLines.size() > kMaxLines) {
        chatLines.erase(chatLines.begin());
        chatSeq.erase(chatSeq.begin());
    }
}

// --- Drawing system -------------------------------------------------------
static constexpr uint16_t kMuted = 0x8C71;
static constexpr uint16_t kBorder = 0x2965;
static constexpr uint16_t kTrackOff = 0x3186;

static void useFontSmall() { canvas.setFont(&fonts::Font0); }
static void useFont()      { canvas.setFont(&fonts::Font2); }
static void useFontLarge() { canvas.setFont(&fonts::Font4); }

static uint16_t mix(uint16_t a, uint16_t b, int t)
{
    int ar = (a >> 11) & 31, ag = (a >> 5) & 63, ab = a & 31;
    int br = (b >> 11) & 31, bg = (b >> 5) & 63, bb = b & 31;
    int r = ar + (br - ar) * t / 255;
    int g = ag + (bg - ag) * t / 255;
    int bl = ab + (bb - ab) * t / 255;
    return static_cast<uint16_t>((r << 11) | (g << 5) | bl);
}

static uint16_t backdropAt(int y)
{
    uint16_t top = mix(bgColor(), theme().accent, isLightTheme() ? 18 : 22);
    return mix(top, bgColor(), constrain(y, 0, 239) * 255 / 239);
}

static uint16_t glassBase()
{
    return isLightTheme() ? theme().panel : mix(theme().panel, bgColor(), 55);
}

static uint16_t subCardBase()
{
    return isLightTheme() ? mix(theme().panel, bgColor(), 90) : mix(glassBase(), bgColor(), 95);
}

static uint16_t mutedText()
{
    return isLightTheme() ? 0x5AEB : 0x94B2;
}

static void drawBackdrop()
{
    uint16_t top = mix(bgColor(), theme().accent, isLightTheme() ? 18 : 22);
    uint16_t bottom = bgColor();
    for (int y = 0; y < 240; y++) {
        canvas.drawFastHLine(0, y, 320, mix(top, bottom, y * 255 / 239));
    }
}

// Elevated card with subtle border and top specular edge
static void glassCard(int x, int y, int w, int h, int r, bool active = false)
{
    uint16_t fill = glassBase();
    uint16_t rim = active ? theme().accent : mix(theme().accent, bgColor(), isLightTheme() ? 170 : 185);
    canvas.fillRoundRect(x, y, w, h, r, fill);
    canvas.drawRoundRect(x, y, w, h, r, rim);
    if (!isLightTheme() && w > 2 * r + 4) {
        canvas.drawFastHLine(x + r, y + 1, w - 2 * r, mix(fill, TFT_WHITE, active ? 65 : 28));
    }
}

static void putText(int x, int y, const char *s, uint16_t fg, uint16_t bg)
{
    canvas.setTextColor(fg, bg);
    canvas.setCursor(x, y);
    canvas.print(s);
}

static void centerText(int cx, int y, const char *s, uint16_t fg, uint16_t bg)
{
    canvas.setTextColor(fg, bg);
    canvas.setCursor(cx - static_cast<int>(canvas.textWidth(s)) / 2, y);
    canvas.print(s);
}

static void drawHeader(const String &title)
{
    useFont();
    uint16_t hdrBg = isLightTheme() ? theme().panel : mix(theme().panel, bgColor(), 40);
    canvas.fillRect(0, 0, 320, 23, hdrBg);
    canvas.drawFastHLine(0, 23, 320, mix(theme().accent, hdrBg, 100));

    // Back pill button (touch zone: x < 66, y < 22)
    uint16_t backBg = mix(theme().accent, hdrBg, 200);
    canvas.fillRoundRect(4, 3, 56, 17, 6, backBg);
    canvas.drawLine(11, 11, 15, 7, theme().accent);
    canvas.drawLine(11, 11, 15, 15, theme().accent);
    canvas.drawLine(12, 11, 16, 7, theme().accent);
    canvas.drawLine(12, 11, 16, 15, theme().accent);
    putText(21, 4, "Home", theme().accent, backBg);

    centerText(160, 4, title.c_str(), theme().fg, hdrBg);
}

static void drawPanel(int x, int y, int w, int h)
{
    glassCard(x, y, w, h, 10, false);
}

// Glossy highlight: a lighter band across the top of a control. Only use where no text
// sits on the same area, because text backgrounds would show as a box against the band.
static void glossTop(int x, int y, int w, int hBand, int r, uint16_t base)
{
    canvas.fillRoundRect(x, y, w, hBand, r, mix(base, TFT_WHITE, 48));
}

static void drawToggle(int x, int y, bool on)
{
    uint16_t track = on ? theme().accent : (isLightTheme() ? 0xC618 : kTrackOff);
    canvas.fillRoundRect(x, y, 36, 18, 9, track);
    glossTop(x + 4, y + 2, 28, 6, 3, track);
    if (!on) {
        canvas.drawRoundRect(x, y, 36, 18, 9, mix(theme().fg, track, 190));
    }
    uint16_t knob = (on && !isLightTheme()) ? bgColor() : TFT_WHITE;
    canvas.fillCircle(on ? x + 27 : x + 9, y + 9, 6, knob);
}

// --- Clock, GPS interval, and saved settings --------------------------------
static bool clockSet = false;
static uint32_t clockEpochSec = 0;
static uint32_t clockSetMs = 0;
static int gpsIntervalIdx = 1;
static const char *kGpsIntervals[4] = {"15 s", "30 s", "1 min", "5 min"};

static void setClock(int hh, int mm)
{
    clockEpochSec = static_cast<uint32_t>(hh * 3600 + mm * 60);
    clockSetMs = millis();
    clockSet = true;
}

static const char *clockText()
{
    static char buf[8];
    if (!clockSet) {
        snprintf(buf, sizeof(buf), "--:--");
        return buf;
    }
    uint32_t secs = (clockEpochSec + (millis() - clockSetMs) / 1000) % 86400;
    snprintf(buf, sizeof(buf), "%02lu:%02lu", (unsigned long)(secs / 3600), (unsigned long)((secs / 60) % 60));
    return buf;
}

static void loadSettings()
{
    Preferences p;
    p.begin("meshport", true);
    txDbm = p.getInt("txDbm", txDbm);
    hopLimit = p.getInt("hop", hopLimit);
    gpsIntervalIdx = p.getInt("gpsInt", gpsIntervalIdx);
    themeIndex = p.getInt("theme", themeIndex);
    bgIndex = p.getInt("bg", bgIndex);
    gpsOn = p.getBool("gpsOn", gpsOn);
    wifiSsid = p.getString("wifiSsid", "");
    wifiPass = p.getString("wifiPass", "");
    wifiOn = p.getBool("wifiOn", wifiOn);
    p.end();
}

static void saveSettings()
{
    Preferences p;
    p.begin("meshport", false);
    p.putInt("txDbm", txDbm);
    p.putInt("hop", hopLimit);
    p.putInt("gpsInt", gpsIntervalIdx);
    p.putInt("theme", themeIndex);
    p.putInt("bg", bgIndex);
    p.putBool("gpsOn", gpsOn);
    p.end();
}

// --- WiFi: scan, join with a password, and sync the clock over NTP ---------
// The saved password is stored in the device's flash in plain text.
static void saveWifiCreds()
{
    Preferences p;
    p.begin("meshport", false);
    p.putString("wifiSsid", wifiSsid);
    p.putString("wifiPass", wifiPass);
    p.putBool("wifiOn", wifiOn);
    p.end();
}

static void connectWifi(const String &ssid, const String &pass)
{
    wifiSsid = ssid;
    wifiPass = pass;
    wifiOn = true;
    wifiNtpStarted = false;
    WiFi.mode(WIFI_STA);
    WiFi.begin(ssid.c_str(), pass.c_str());
    saveWifiCreds();
    Serial.printf("wifi joining %s\n", ssid.c_str());
}

static void forgetWifi()
{
    wifiSsid = "";
    wifiPass = "";
    WiFi.disconnect(true);
    wifiNtpStarted = false;
    saveWifiCreds();
}

// Keeps the strongest kWifiListMax networks found in the scan.
static void scanWifi()
{
    if (WiFi.getMode() == WIFI_OFF) WiFi.mode(WIFI_STA);
    int n = WiFi.scanNetworks();
    wifiFound = 0;
    for (int i = 0; i < n; i++) {
        String name = WiFi.SSID(i);
        if (name.length() == 0) continue;
        int rssi = WiFi.RSSI(i);
        int slot = -1;
        if (wifiFound < kWifiListMax) {
            slot = wifiFound++;
        } else {
            int weakest = 0;
            for (int k = 1; k < kWifiListMax; k++) {
                if (wifiRssis[k] < wifiRssis[weakest]) weakest = k;
            }
            if (rssi > wifiRssis[weakest]) slot = weakest;
        }
        if (slot < 0) continue;
        wifiNames[slot] = name;
        wifiRssis[slot] = rssi;
        wifiSecure[slot] = WiFi.encryptionType(i) != WIFI_AUTH_OPEN;
    }
    WiFi.scanDelete();
    Serial.printf("wifi scan: %d networks\n", wifiFound);
}

static String wifiStatusText()
{
    if (!wifiOn) return "Off";
    if (WiFi.status() == WL_CONNECTED) return String("Joined ") + WiFi.SSID();
    if (wifiSsid.length() == 0) return "No network saved";
    return "Joining " + wifiSsid;
}

// Joins the saved network at boot, and sets the clock from NTP once connected.
static void pollWifi()
{
    static bool started = false;
    if (!started) {
        started = true;
        if (wifiOn) {
            WiFi.mode(WIFI_STA);
            if (wifiSsid.length()) WiFi.begin(wifiSsid.c_str(), wifiPass.c_str());
        }
    }
    if (!wifiOn || WiFi.status() != WL_CONNECTED) return;
    if (!wifiNtpStarted) {
        // Eastern time with US daylight saving. Change the zone string for another place.
        configTzTime("EST5EDT,M3.2.0,M11.1.0", "pool.ntp.org", "time.google.com");
        wifiNtpStarted = true;
        wifiNtpMs = 0;
    }
    if (wifiNtpMs != 0 && millis() - wifiNtpMs < 60000) return;
    struct tm tm;
    if (getLocalTime(&tm, 0) && tm.tm_year > 100) {
        setClock(tm.tm_hour, tm.tm_min);
        wifiNtpMs = millis();
        Serial.printf("clock set over NTP %02d:%02d\n", tm.tm_hour, tm.tm_min);
    }
}

// --- GPS receiver: NMEA over UART (satellites, altitude, and time) ----------
// T-Deck Plus GPS module, 38400 baud. Wadamesh names the pins from the module's side
// (its PIN_GPS_TX = 44 is the pin the ESP32 receives on), so the ESP32 receives on 44
// and transmits on 43.
static constexpr int kGpsRxPin = 44;
static constexpr int kGpsTxPin = 43;
static constexpr int kUtcOffsetHours = -5;   // Eastern time; change for another zone
static HardwareSerial gpsSerial(1);
static bool gpsStarted = false;
static float gpsAltM = 0;
static double gpsLat = 0, gpsLon = 0;
static bool gpsHasPos = false;
static char gpsLine[120];
static size_t gpsLen = 0;

static int nmeaSplit(char *s, char *fields[], int maxFields)
{
    int n = 0;
    fields[n++] = s;
    for (char *p = s; *p && n < maxFields; p++) {
        if (*p == ',') {
            *p = '\0';
            fields[n++] = p + 1;
        }
    }
    return n;
}

// NMEA coordinates are ddmm.mmmm with a hemisphere letter.
static double nmeaCoord(const char *v, const char *hemi)
{
    double x = atof(v);
    int deg = static_cast<int>(x / 100.0);
    double d = deg + (x - deg * 100.0) / 60.0;
    if (hemi[0] == 'S' || hemi[0] == 'W') d = 0.0 - d;
    return d;
}

static void parseNmea(char *s)
{
    if (s[0] != '$') return;
    char *star = strchr(s, '*');
    if (star) *star = '\0';
    char *f[16];
    int n = nmeaSplit(s + 1, f, 16);
    if (n < 10 || strlen(f[0]) < 5) return;
    const char *kind = f[0] + 2;   // RMC or GGA, whatever the talker prefix

    if (strcmp(kind, "RMC") == 0 && f[2][0] == 'A' && strlen(f[1]) >= 6) {
        int utcHour = (f[1][0] - '0') * 10 + (f[1][1] - '0');
        int utcMin = (f[1][2] - '0') * 10 + (f[1][3] - '0');
        int localMin = ((utcHour * 60 + utcMin + kUtcOffsetHours * 60) % 1440 + 1440) % 1440;
        setClock(localMin / 60, localMin % 60);
        gpsLat = nmeaCoord(f[3], f[4]);
        gpsLon = nmeaCoord(f[5], f[6]);
        gpsHasPos = true;
    } else if (strcmp(kind, "GGA") == 0) {
        int fix = atoi(f[6]);
        gpsSats = fix > 0 ? atoi(f[7]) : 0;
        gpsAltM = atof(f[9]);
        gpsHasPos = fix > 0 && f[2][0] != '\0';
        if (gpsHasPos) {
            gpsLat = nmeaCoord(f[2], f[3]);
            gpsLon = nmeaCoord(f[4], f[5]);
        }
    }
}

// Baud rates to try, in order, until bytes arrive. Most GNSS modules are 9600 or 38400.
static const uint32_t kGpsBauds[] = {38400, 9600, 115200};
static int gpsBaudIdx = 0;
static uint32_t gpsBytes = 0;          // raw bytes received on the GPS UART
static uint32_t gpsSentences = 0;      // NMEA sentences parsed
static uint32_t gpsOpenedMs = 0;
static uint32_t gpsReportMs = 0;

static void openGps(int idx)
{
    gpsBaudIdx = idx;
    gpsSerial.end();
    gpsSerial.begin(kGpsBauds[gpsBaudIdx], SERIAL_8N1, kGpsRxPin, kGpsTxPin);
    gpsOpenedMs = millis();
    gpsLen = 0;
    Serial.printf("gps uart at %lu baud\n", (unsigned long)kGpsBauds[gpsBaudIdx]);
}

static void pollGps()
{
    if (!gpsOn) return;
    if (!gpsStarted) {
        openGps(0);
        gpsStarted = true;
    }
    while (gpsSerial.available()) {
        char c = static_cast<char>(gpsSerial.read());
        gpsBytes++;
        if (c == '\n' || c == '\r') {
            if (gpsLen > 0) {
                gpsLine[gpsLen] = '\0';
                if (gpsLine[0] == '$' && gpsSentences < 3) Serial.printf("gps: %s\n", gpsLine);
                parseNmea(gpsLine);
                gpsSentences++;
                gpsLen = 0;
            }
        } else if (gpsLen < sizeof(gpsLine) - 1) {
            gpsLine[gpsLen++] = c;
        } else {
            gpsLen = 0;
        }
    }
    // No bytes yet: try the next baud rate every 3 seconds.
    if (gpsBytes == 0 && millis() - gpsOpenedMs > 3000) {
        openGps((gpsBaudIdx + 1) % 3);
    }
    if (millis() - gpsReportMs > 10000) {
        gpsReportMs = millis();
        Serial.printf("gps: %lu bytes, %lu sentences, %d sats\n", (unsigned long)gpsBytes,
                      (unsigned long)gpsSentences, gpsSats);
    }
}

// Round badge with a count, drawn on a tile corner.
static void drawBadge(int cx, int cy, int count)
{
    char buf[4];
    if (count > 9) snprintf(buf, sizeof(buf), "9+");
    else snprintf(buf, sizeof(buf), "%d", count);
    const uint16_t red = 0xF800;
    canvas.fillCircle(cx, cy, 8, red);
    useFontSmall();
    centerText(cx, cy - 4, buf, TFT_WHITE, red);
    useFont();
}

// --- Crisp Vector Primitives ------------------------------------------------
static constexpr uint16_t kOnBlue = 0x25DF;
static constexpr uint16_t kOffGrey = 0x6B4D;

static const int kArcCos[7] = {707, 500, 259, 0, -259, -500, -707};
static const int kArcSin[7] = {707, 866, 966, 1000, 966, 866, 707};

static void strokeSeg(int x0, int y0, int x1, int y1, uint16_t col, int w)
{
    for (int k = 0; k < w; k++) canvas.drawLine(x0, y0 + k, x1, y1 + k, col);
}

static void drawTopArc(int cx, int cy, int r, uint16_t col, int w)
{
    int px = 0, py = 0;
    for (int k = 0; k < 7; k++) {
        int x = cx + r * kArcCos[k] / 1000;
        int y = cy - r * kArcSin[k] / 1000;
        if (k > 0) strokeSeg(px, py, x, y, col, w);
        px = x;
        py = y;
    }
}

static void drawWifi(int cx, int cy, uint16_t col, bool big)
{
    canvas.fillCircle(cx, cy, big ? 2 : 1, col);
    if (big) {
        drawTopArc(cx, cy, 5, col, 2);
        drawTopArc(cx, cy, 9, col, 2);
        drawTopArc(cx, cy, 13, col, 2);
    } else {
        drawTopArc(cx, cy, 3, col, 1);
        drawTopArc(cx, cy, 6, col, 1);
        drawTopArc(cx, cy, 9, col, 1);
    }
}

static void drawGpsIcon(int cx, int cy, uint16_t col, bool on, int frame)
{
    canvas.fillRoundRect(cx - 3, cy - 3, 6, 6, 1, col);
    canvas.fillRect(cx - 9, cy - 2, 5, 4, col);
    canvas.fillRect(cx + 4, cy - 2, 5, 4, col);
    canvas.drawFastHLine(cx - 4, cy, 1, col);
    canvas.drawFastHLine(cx + 3, cy, 1, col);
    canvas.fillCircle(cx, cy - 6, 2, col);
    if (on) {
        int phase = frame % 2;
        for (int k = 0; k < 2; k++) {
            int r = 3 + ((phase + k) % 2) * 3;
            drawTopArc(cx, cy - 6, r, col, 1);
        }
    }
}

static void drawBtBubble(int cx, int cy, bool on)
{
    canvas.fillCircle(cx, cy, 8, on ? kOnBlue : kOffGrey);
    uint16_t rune = TFT_WHITE;
    canvas.drawLine(cx - 3, cy - 4, cx + 3, cy + 2, rune);
    canvas.drawLine(cx + 3, cy + 2, cx, cy + 5, rune);
    canvas.drawLine(cx, cy + 5, cx, cy - 5, rune);
    canvas.drawLine(cx, cy - 5, cx + 3, cy - 2, rune);
    canvas.drawLine(cx + 3, cy - 2, cx - 3, cy + 4, rune);
}

static void drawGear(int cx, int cy, uint16_t col, uint16_t hole)
{
    static const int kToothX[8] = {9, 6, 0, -6, -9, -6, 0, 6};
    static const int kToothY[8] = {0, 6, 9, 6, 0, -6, -9, -6};
    canvas.fillCircle(cx, cy, 6, col);
    for (int k = 0; k < 8; k++) canvas.fillCircle(cx + kToothX[k], cy + kToothY[k], 2, col);
    canvas.fillCircle(cx, cy, 3, hole);
}

static void drawAppIcon(int idx, int cx, int cy, uint16_t col, uint16_t fill)
{
    switch (idx) {
    case 0: // Chat: speech bubble with lines
        canvas.fillRoundRect(cx - 9, cy - 7, 18, 12, 4, col);
        canvas.fillTriangle(cx - 5, cy + 4, cx, cy + 4, cx - 6, cy + 9, col);
        canvas.drawFastHLine(cx - 5, cy - 3, 10, fill);
        canvas.drawFastHLine(cx - 5, cy, 7, fill);
        break;
    case 1: // Peers: two people silhouettes
        canvas.fillCircle(cx - 4, cy - 4, 3, col);
        canvas.fillRoundRect(cx - 9, cy + 1, 10, 7, 3, col);
        canvas.drawCircle(cx + 4, cy - 4, 3, col);
        canvas.drawRoundRect(cx, cy + 1, 9, 7, 3, col);
        break;
    case 2: // Nodes: mesh topology triangle
        canvas.drawLine(cx, cy - 7, cx - 8, cy + 6, col);
        canvas.drawLine(cx, cy - 7, cx + 8, cy + 6, col);
        canvas.drawLine(cx - 8, cy + 6, cx + 8, cy + 6, col);
        canvas.fillCircle(cx, cy - 7, 3, col);
        canvas.fillCircle(cx - 8, cy + 6, 3, col);
        canvas.fillCircle(cx + 8, cy + 6, 3, col);
        break;
    case 3: // Spectrum: 2px crisp waveform
        strokeSeg(cx - 10, cy, cx - 5, cy, col, 2);
        strokeSeg(cx - 5, cy, cx - 2, cy - 7, col, 2);
        strokeSeg(cx - 2, cy - 7, cx + 2, cy + 7, col, 2);
        strokeSeg(cx + 2, cy + 7, cx + 5, cy, col, 2);
        strokeSeg(cx + 5, cy, cx + 10, cy, col, 2);
        break;
    case 4: // Signal: 4 rounded bars
        canvas.fillRoundRect(cx - 9, cy + 2, 3, 6, 1, col);
        canvas.fillRoundRect(cx - 4, cy - 1, 3, 9, 1, col);
        canvas.fillRoundRect(cx + 1, cy - 5, 3, 13, 1, col);
        canvas.fillRoundRect(cx + 6, cy - 9, 3, 17, 1, col);
        break;
    case 5: // Settings: gear
        drawGear(cx, cy, col, fill);
        break;
    }
}

static void drawHome()
{
    drawBackdrop();
    int frame = static_cast<int>(millis() / 180);

    // --- Top Status Bar ---
    uint16_t strip = backdropAt(4);
    canvas.fillCircle(10, 11, 4, mix(0x07E0, strip, 160));
    canvas.fillCircle(10, 11, 2, 0x07E0);

    useFont();
    unsigned long mins = millis() / 60000;
    char up[24];
    snprintf(up, sizeof(up), "Up %luh %02lum", mins / 60, mins % 60);
    putText(18, 3, up, theme().fg, strip);
    centerText(156, 3, clockText(), theme().fg, strip);

    bool linkOn[3] = {wifiOn, gpsOn, btOn};
    const int pillX[3] = {190, 226, 278};
    // Icons sit directly on the status bar, with no outline pills around them.
    drawWifi(pillX[0] + 16, 12, linkOn[0] ? kOnBlue : kOffGrey, false);
    drawGpsIcon(pillX[1] + 8, 11, linkOn[1] ? kOnBlue : kOffGrey, linkOn[1], frame);
    useFontSmall();
    putText(pillX[1] + 20, 7, "GPS", linkOn[1] ? kOnBlue : kOffGrey, strip);
    drawBtBubble(pillX[2] + 14, 11, linkOn[2]);
    canvas.drawFastHLine(0, 23, 320, mix(theme().accent, bgColor(), 140));

    // --- Left Card: Mesh Telemetry & Alerts ---
    drawPanel(6, 30, 150, 100);
    useFontSmall();
    putText(16, 37, "MESH TELEMETRY", theme().accent, glassBase());

    // SNR Pill
    char snr[16];
    snprintf(snr, sizeof(snr), "SNR %+.1f", lastSnr);
    uint16_t pill = mix(theme().accent, glassBase(), 195);
    canvas.fillRoundRect(92, 34, 56, 14, 7, pill);
    centerText(120, 37, snr, theme().accent, pill);

    // Big Node Count Stat + Radio Frequency Info
    uint16_t subBg = subCardBase();
    canvas.fillRoundRect(12, 52, 54, 46, 7, subBg);
    canvas.drawRoundRect(12, 52, 54, 46, 7, mix(theme().accent, subBg, 180));
    char sats[12];
    snprintf(sats, sizeof(sats), "%d", gpsSats);
    useFontLarge();
    centerText(39, 57, sats, theme().accent, subBg);
    useFontSmall();
    centerText(39, 84, "SATS", mutedText(), subBg);

    // Right sub-stack: Frequency & Preset
    canvas.fillRoundRect(70, 52, 80, 21, 6, subBg);
    useFont();
    putText(76, 54, "LongFast", theme().fg, subBg);

    canvas.fillRoundRect(70, 77, 80, 21, 6, subBg);
    putText(76, 79, "906.9 MHz", theme().accent, subBg);

    // Bottom Row: Latest Message Preview
    canvas.fillRoundRect(12, 103, 138, 20, 6, subBg);
    canvas.fillCircle(20, 113, 3, nodes.empty() ? mutedText() : 0x07E0);
    char heardLine[24];
    snprintf(heardLine, sizeof(heardLine), "%u nodes heard", (unsigned)nodes.size());
    useFont();
    putText(28, 105, heardLine, nodes.empty() ? mutedText() : theme().fg, subBg);

    // --- Right Card: Quick Radio Toggles (Widgets) ---
    drawPanel(164, 30, 150, 100);
    useFontSmall();
    putText(174, 37, "RADIOS", theme().accent, glassBase());
    putText(284, 37, "PWR", mutedText(), glassBase());

    const char *names[3] = {"WiFi", "GPS", "BT"};
    for (int i = 0; i < 3; i++) {
        int x = 176 + i * 46;
        bool sel = (homeSel == kWidgetFirst + i);
        uint16_t slotBg = sel ? mix(theme().accent, glassBase(), 210) : subCardBase();
        canvas.fillRoundRect(x - 5, 50, 46, 73, 7, slotBg);
        if (sel) {
            canvas.drawRoundRect(x - 5, 50, 46, 73, 7, theme().accent);
        }

        uint16_t col = linkOn[i] ? kOnBlue : mutedText();
        if (i == 0) drawWifi(x + 18, 65, col, true);
        else if (i == 1) drawGpsIcon(x + 18, 63, col, linkOn[1], frame);
        else drawBtBubble(x + 18, 61, linkOn[2]);

        useFont();
        centerText(x + 18, 74, names[i], theme().fg, slotBg);
        drawToggle(x, 93, linkOn[i]);
        useFontSmall();
        centerText(x + 18, 114, linkOn[i] ? "ON" : "OFF", linkOn[i] ? theme().accent : mutedText(), slotBg);
    }

    // --- Bottom Card: App Launcher Dock ---
    drawPanel(6, 136, 308, 96);
    useFontSmall();
    putText(16, 143, "APPLICATIONS", theme().accent, glassBase());
    static const char *kShort[kTileCount] = {"Chat", "Maps", "Nodes", "Spec", "Signal", "Setup"};
    for (int i = 0; i < kTileCount; i++) {
        int cx = 31 + i * 51, cy = 178;
        bool sel = (homeSel == i);
        if (sel) {
            canvas.fillRoundRect(cx - 20, cy - 20, 40, 40, 11, theme().accent);
            glossTop(cx - 17, cy - 18, 34, 10, 7, theme().accent);
            drawAppIcon(i, cx, cy, isLightTheme() ? TFT_WHITE : bgColor(), theme().accent);
        } else {
            uint16_t tileBg = subCardBase();
            canvas.fillRoundRect(cx - 20, cy - 20, 40, 40, 11, tileBg);
            glossTop(cx - 17, cy - 18, 34, 10, 7, tileBg);
            canvas.drawRoundRect(cx - 20, cy - 20, 40, 40, 11, mix(theme().accent, tileBg, 165));
            drawAppIcon(i, cx, cy, theme().accent, tileBg);
        }
        useFont();
        centerText(cx, 204, kShort[i], sel ? theme().accent : theme().fg, glassBase());
        if (i == 0 && unreadChat > 0) drawBadge(cx + 17, cy - 17, unreadChat);
    }
}

static void drawPublic()
{
    useFont();
    drawBackdrop();
    drawHeader("Public Channel");
    // Settings shortcut, top right.
    canvas.fillRoundRect(256, 3, 58, 17, 6, theme().accent);
    centerText(285, 4, "SETUP", isLightTheme() ? TFT_WHITE : bgColor(), theme().accent);

    // Newest messages as distinct chat rows.
    size_t first = chatLines.size() > 8 ? chatLines.size() - 8 : 0;
    int row = 0;
    for (size_t i = first; i < chatLines.size(); i++, row++) {
        int y = 28 + row * 21;
        bool isMe = chatLines[i].startsWith("me: ");
        uint16_t rowBg = isMe ? mix(theme().accent, glassBase(), 205) : glassBase();
        canvas.fillRoundRect(6, y, 308, 18, 6, rowBg);
        if (isMe) {
            canvas.drawRoundRect(6, y, 308, 18, 6, mix(theme().accent, rowBg, 130));
        }
        putText(14, y + 1, chatLines[i].c_str(), isMe ? theme().accent : theme().fg, rowBg);

        // Message number, top right of the bubble.
        char num[12];
        snprintf(num, sizeof(num), "#%lu", (unsigned long)chatSeq[i]);
        useFontSmall();
        canvas.setTextColor(mutedText(), rowBg);
        canvas.setCursor(308 - static_cast<int>(canvas.textWidth(num)), y + 5);
        canvas.print(num);
        useFont();
    }

    // Composer bar.
    glassCard(6, 200, 308, 34, 8, inputBuf.length() > 0);
    putText(14, 209, ">", theme().accent, glassBase());
    if (inputBuf.length() == 0) {
        putText(28, 209, "Broadcast to LongFast...", mutedText(), glassBase());
    } else {
        int start = inputBuf.length() > 33 ? static_cast<int>(inputBuf.length()) - 33 : 0;
        String shown = inputBuf.substring(start);
        if ((millis() / 500) % 2 == 0) shown += "_";
        putText(28, 209, shown.c_str(), theme().fg, glassBase());
    }
}

// First node shown in the Nodes list, so the selected row stays visible.
static int nodeTop() { return nodeSel >= 6 ? nodeSel - 5 : 0; }

static void drawNodes()
{
    useFont();
    drawBackdrop();
    char title[24];
    snprintf(title, sizeof(title), "Mesh Nodes (%u)", (unsigned)nodes.size());
    drawHeader(title);

    if (nodes.empty()) {
        drawPanel(16, 68, 288, 84);
        centerText(160, 86, "Listening on 906.875 MHz...", theme().fg, glassBase());
        useFontSmall();
        centerText(160, 114, "NEARBY MESHTASTIC NODES APPEAR HERE", mutedText(), glassBase());
        return;
    }

    // Six rows at a time; the window follows the selection.
    int top = nodeTop();
    uint32_t now = millis();
    for (int row = 0; row < 6 && top + row < static_cast<int>(nodes.size()); row++) {
        size_t i = static_cast<size_t>(top + row);
        int y = 30 + row * 33;
        glassCard(6, y, 308, 28, 7, static_cast<int>(i) == nodeSel);

        // Node badge
        uint16_t badgeBg = mix(theme().accent, glassBase(), 200);
        canvas.fillRoundRect(12, y + 4, 78, 20, 5, badgeBg);
        char id[12];
        snprintf(id, sizeof(id), "%08lX", (unsigned long)nodes[i].id);
        centerText(51, y + 6, id, theme().accent, badgeBg);

        // Signal bar: -120 dBm (empty) to -50 dBm (full).
        int r = static_cast<int>(nodes[i].rssi);
        if (r < -120) r = -120;
        if (r > -50) r = -50;
        int bar = (r + 120) * 76 / 70;
        uint16_t col = r > -90 ? 0x07E0 : (r > -105 ? theme().accent : 0xFD20);
        canvas.fillRoundRect(100, y + 11, 76, 6, 3, isLightTheme() ? 0xC618 : kTrackOff);
        if (bar > 2) canvas.fillRoundRect(100, y + 11, bar, 6, 3, col);

        char info[24];
        snprintf(info, sizeof(info), "%ddBm  %lus", r, (unsigned long)((now - nodes[i].lastMs) / 1000));
        putText(186, y + 6, info, theme().fg, glassBase());
    }
}

// Human-readable time since an event, e.g. "42s ago", "5m ago".
static void formatAgo(uint32_t ms, char *out, size_t n)
{
    uint32_t s = ms / 1000;
    if (s < 60) snprintf(out, n, "%lus ago", (unsigned long)s);
    else if (s < 3600) snprintf(out, n, "%lum ago", (unsigned long)(s / 60));
    else snprintf(out, n, "%luh ago", (unsigned long)(s / 3600));
}

// --- Map: raw RGB565 tiles on the SD card ----------------------------------
// Tiles live at /maps/<zoom>/<x>/<y>.bin, each 256x256 little-endian RGB565 pixels
// (made by tools/maps/png_to_rgb565.py). Coordinates are Web Mercator, the usual
// slippy-map scheme. The SD chip select (GPIO 39) is unverified on the T-Deck Plus.
static constexpr int kSdCsPin = 39;
static constexpr int kTilePx = 256;
static constexpr int kMapY = 24;            // map area starts below the header
static constexpr int kMapW = 320;
static constexpr int kMapH = 216;
static constexpr int kTileSlots = 4;
static constexpr int kMaxZoom = 18;
static bool sdTried = false;
static bool sdReady = false;
static int mapZoom = 15;
static double mapCx = 0, mapCy = 0;         // map center in world pixels at mapZoom
static bool mapFollow = true;               // keep the map centered on my GPS position

struct TileSlot {
    int z = -1, x = 0, y = 0;
    uint16_t *px = nullptr;
    uint32_t used = 0;
};
static TileSlot tileSlots[kTileSlots];

static double mercX(double lon, int z)
{
    return (lon + 180.0) / 360.0 * kTilePx * static_cast<double>(1 << z);
}

static double mercY(double lat, int z)
{
    const double kMaxLatRad = 1.4844;       // about 85.05 degrees, the Web Mercator limit
    double r = lat * 3.14159265358979 / 180.0;
    if (r > kMaxLatRad) r = kMaxLatRad;
    if (r < 0.0 - kMaxLatRad) r = 0.0 - kMaxLatRad;
    return (1.0 - log(tan(r) + 1.0 / cos(r)) / 3.14159265358979) / 2.0 * kTilePx *
           static_cast<double>(1 << z);
}

// Pixels of one tile, loaded from the SD card into a small cache. Null if missing.
static uint16_t *tileData(int z, int x, int y)
{
    for (TileSlot &s : tileSlots) {
        if (s.px && s.z == z && s.x == x && s.y == y) {
            s.used = millis();
            return s.px;
        }
    }
    TileSlot *slot = &tileSlots[0];
    for (TileSlot &s : tileSlots) {
        if (!s.px) { slot = &s; break; }
        if (s.used < slot->used) slot = &s;
    }
    if (!slot->px) {
        slot->px = static_cast<uint16_t *>(ps_malloc(kTilePx * kTilePx * 2));
        if (!slot->px) return nullptr;
    }
    slot->z = -1;
    char path[48];
    snprintf(path, sizeof(path), "/maps/%d/%d/%d.bin", z, x, y);
    File f = SD.open(path);
    if (!f) return nullptr;
    size_t got = f.read(reinterpret_cast<uint8_t *>(slot->px), kTilePx * kTilePx * 2);
    f.close();
    if (got != static_cast<size_t>(kTilePx * kTilePx * 2)) return nullptr;
    slot->z = z;
    slot->x = x;
    slot->y = y;
    slot->used = millis();
    return slot->px;
}

// Paints one tile whose top-left corner is at screen (sx, sy), clipped to the map area.
static void drawTile(int z, int x, int y, int sx, int sy)
{
    int x0 = sx < 0 ? 0 : sx;
    int x1 = sx + kTilePx > kMapW ? kMapW : sx + kTilePx;
    if (x1 <= x0) return;
    uint16_t *px = tileData(z, x, y);
    if (!px) {
        int y0 = sy < kMapY ? kMapY : sy;
        int y1 = sy + kTilePx > kMapY + kMapH ? kMapY + kMapH : sy + kTilePx;
        if (y1 > y0) canvas.fillRect(x0, y0, x1 - x0, y1 - y0, mix(bgColor(), TFT_WHITE, 20));
        return;
    }
    for (int r = 0; r < kTilePx; r++) {
        int yy = sy + r;
        if (yy < kMapY || yy >= kMapY + kMapH) continue;
        canvas.pushImage(x0, yy, x1 - x0, 1, px + r * kTilePx + (x0 - sx));
    }
}

static int mapScreenX(double wx) { return static_cast<int>(wx - (mapCx - kMapW / 2.0)); }
static int mapScreenY(double wy) { return kMapY + static_cast<int>(wy - (mapCy - kMapH / 2.0)); }

static void mapPan(double dx, double dy)
{
    mapFollow = false;
    mapCx += dx;
    mapCy += dy;
}

static void mapZoomBy(int dz)
{
    int nz = mapZoom + dz;
    if (nz < 0 || nz > kMaxZoom) return;
    double scale = dz > 0 ? 2.0 : 0.5;
    mapCx *= scale;
    mapCy *= scale;
    mapZoom = nz;
}

static void drawMap()
{
    if (!sdTried) {
        sdTried = true;
        sdReady = SD.begin(kSdCsPin, loraSpi, 4000000);
        Serial.printf("sd card %s\n", sdReady ? "ready" : "not found");
    }
    useFont();
    drawBackdrop();
    drawHeader("Map");
    if (!sdReady) {
        centerText(160, 100, "No SD card with maps", theme().fg, backdropAt(100));
        centerText(160, 122, "Put tiles in /maps and reboot", mutedText(), backdropAt(122));
        return;
    }
    if (mapFollow && gpsHasPos) {
        mapCx = mercX(gpsLon, mapZoom);
        mapCy = mercY(gpsLat, mapZoom);
    }

    double left = mapCx - kMapW / 2.0;
    double top = mapCy - kMapH / 2.0;
    int n = 1 << mapZoom;
    int tx0 = static_cast<int>(floor(left / kTilePx));
    int tx1 = static_cast<int>(floor((left + kMapW) / kTilePx));
    int ty0 = static_cast<int>(floor(top / kTilePx));
    int ty1 = static_cast<int>(floor((top + kMapH) / kTilePx));
    for (int ty = ty0; ty <= ty1; ty++) {
        if (ty < 0 || ty >= n) continue;
        for (int tx = tx0; tx <= tx1; tx++) {
            int wrapped = ((tx % n) + n) % n;
            drawTile(mapZoom, wrapped, ty, static_cast<int>(tx * kTilePx - left),
                     static_cast<int>(kMapY + ty * kTilePx - top));
        }
    }

    // Other nodes that have sent a position.
    useFontSmall();
    for (const NodeEntry &nd : nodes) {
        if (!nd.hasPos) continue;
        int sx = mapScreenX(mercX(nd.lon, mapZoom));
        int sy = mapScreenY(mercY(nd.lat, mapZoom));
        if (sx < 0 || sx >= kMapW || sy < kMapY || sy >= kMapY + kMapH) continue;
        canvas.fillCircle(sx, sy, 4, theme().accent);
        canvas.drawCircle(sx, sy, 4, TFT_BLACK);
        char label[8];
        snprintf(label, sizeof(label), "%04lX", (unsigned long)(nd.id & 0xFFFF));
        canvas.setTextColor(TFT_WHITE, TFT_BLACK);
        canvas.setCursor(sx + 6, sy - 4);
        canvas.print(label);
    }

    // My position.
    if (gpsHasPos) {
        int sx = mapScreenX(mercX(gpsLon, mapZoom));
        int sy = mapScreenY(mercY(gpsLat, mapZoom));
        canvas.fillCircle(sx, sy, 6, TFT_WHITE);
        canvas.fillCircle(sx, sy, 4, kOnBlue);
    }

    // Status bar along the bottom of the map.
    canvas.fillRect(0, kMapY + kMapH - 14, kMapW, 14, TFT_BLACK);
    char status[48];
    snprintf(status, sizeof(status), "z%d  %s%s", mapZoom, gpsHasPos ? "GPS fix" : "no GPS fix",
             mapFollow ? "  follow" : "  panned");
    putText(4, kMapY + kMapH - 13, status, TFT_WHITE, TFT_BLACK);
}

// Password entry for the chosen network. Typed characters show as dots.
static void drawWifiPassword()
{
    useFont();
    drawBackdrop();
    drawHeader("Wi-Fi password");
    glassCard(8, 40, 304, 58, 10, false);
    useFontSmall();
    putText(20, 50, "Network", mutedText(), glassBase());
    useFont();
    putText(20, 66, wifiPickSsid.c_str(), theme().fg, glassBase());

    glassCard(8, 110, 304, 36, 8, true);
    String dots = "";
    for (size_t k = 0; k < wifiPassBuf.length() && k < 28; k++) dots += '*';
    if ((millis() / 500) % 2 == 0) dots += '_';
    putText(18, 120, dots.c_str(), theme().fg, glassBase());

    useFontSmall();
    centerText(160, 160, "Type the password, then press Enter to join", mutedText(), glassBase());
    centerText(160, 176, "Backspace on an empty box goes back", mutedText(), glassBase());
}

// Node Info: everything we know about the selected node.
static void drawNodeInfo()
{
    useFont();
    drawBackdrop();
    drawHeader("Node Info");
    if (nodeSel < 0 || nodeSel >= static_cast<int>(nodes.size())) {
        centerText(160, 100, "Node not found", theme().fg, glassBase());
        return;
    }
    const NodeEntry &n = nodes[nodeSel];
    glassCard(8, 30, 304, 200, 10, false);

    char idText[16], shortText[8], rssiText[16], snrText[16], countText[12], firstText[16], lastText[16];
    snprintf(idText, sizeof(idText), "!%08lx", (unsigned long)n.id);
    snprintf(shortText, sizeof(shortText), "%04lX", (unsigned long)(n.id & 0xFFFF));
    snprintf(rssiText, sizeof(rssiText), "%.0f dBm", n.rssi);
    snprintf(snrText, sizeof(snrText), "%+.1f dB", n.snr);
    snprintf(countText, sizeof(countText), "%lu", (unsigned long)n.count);
    formatAgo(millis() - n.firstMs, firstText, sizeof(firstText));
    formatAgo(millis() - n.lastMs, lastText, sizeof(lastText));

    char posText[32];
    if (n.hasPos) snprintf(posText, sizeof(posText), "%.4f, %.4f", n.lat, n.lon);
    else snprintf(posText, sizeof(posText), "not received");

    const char *labels[8] = {"Node ID", "Short name", "Signal (RSSI)", "SNR", "Packets heard",
                             "First heard", "Last heard", "Position"};
    const char *values[8] = {idText, shortText, rssiText, snrText, countText, firstText, lastText, posText};
    for (int i = 0; i < 8; i++) {
        int y = 38 + i * 22;
        putText(20, y, labels[i], mutedText(), glassBase());
        canvas.setTextColor(theme().accent, glassBase());
        canvas.setCursor(308 - static_cast<int>(canvas.textWidth(values[i])), y);
        canvas.print(values[i]);
    }
    useFontSmall();
    centerText(160, 216, "Long name: not decoded yet", mutedText(), glassBase());
}

static bool isSettingsScreen(Screen s)
{
    return s == Screen::Settings || s == Screen::SettingsDevice || s == Screen::SettingsLora ||
           s == Screen::SettingsGps || s == Screen::SettingsDisplay || s == Screen::SettingsWifi;
}

static int buildSettingItems(Screen s, char items[][40])
{
    switch (s) {
    case Screen::Settings:
        snprintf(items[0], 40, "Device Identity");
        snprintf(items[1], 40, "LoRa Radio");
        snprintf(items[2], 40, "GPS Receiver");
        snprintf(items[3], 40, "Display & Theme");
        snprintf(items[4], 40, "WiFi Network");
        snprintf(items[5], 40, "Calibrate Touchscreen");
        snprintf(items[6], 40, "Back to Home");
        return 7;
    case Screen::SettingsWifi: {
        snprintf(items[0], 40, "Status: %s", wifiStatusText().c_str());
        int n = 1;
        for (int k = 0; k < wifiFound; k++) {
            snprintf(items[n++], 40, "%s: %d dBm%s", wifiNames[k].c_str(), wifiRssis[k],
                     wifiSecure[k] ? " *" : "");
        }
        snprintf(items[n++], 40, "Rescan networks");
        snprintf(items[n++], 40, "Forget saved network");
        snprintf(items[n++], 40, "Back");
        return n;
    }
    case Screen::SettingsDevice:
        snprintf(items[0], 40, "Node ID: %08lX", (unsigned long)myNode);
        snprintf(items[1], 40, "Role: Client");
        snprintf(items[2], 40, "Clock: %s", clockText());
        snprintf(items[3], 40, "Short Name: %04lX", (unsigned long)(myNode & 0xFFFF));
        snprintf(items[4], 40, "Back");
        return 5;
    case Screen::SettingsLora:
        snprintf(items[0], 40, "Region: US 902-928 MHz");
        snprintf(items[1], 40, "Modem: LongFast");
        snprintf(items[2], 40, "Frequency: %.3f MHz", loraFreqMHz);
        snprintf(items[3], 40, "TX Power: %d dBm (reboot)", txDbm);
        snprintf(items[4], 40, "Hop Limit: %d hops", hopLimit);
        snprintf(items[5], 40, "Back");
        return 6;
    case Screen::SettingsGps:
        snprintf(items[0], 40, "GPS Power: %s", gpsOn ? "ON" : "OFF");
        snprintf(items[1], 40, "Update Interval: %s", kGpsIntervals[gpsIntervalIdx]);
        if (gpsSats > 0) snprintf(items[2], 40, "Fix: %d sats, %.0f m", gpsSats, gpsAltM);
        else if (gpsBytes == 0) snprintf(items[2], 40, "Fix: no data, check wiring");
        else snprintf(items[2], 40, "Fix: searching");
        snprintf(items[3], 40, "Back");
        return 4;
    case Screen::SettingsDisplay:
        snprintf(items[0], 40, "Theme: %s", kThemes[themeIndex].name);
        snprintf(items[1], 40, "Backdrop: %s", kBackgroundNames[bgIndex]);
        snprintf(items[2], 40, "Back");
        return 3;
    default:
        return 0;
    }
}

static void drawSettingsScreen(Screen s)
{
    useFont();
    drawBackdrop();
    const char *title = "Settings";
    switch (s) {
    case Screen::SettingsDevice:  title = "Device Identity"; break;
    case Screen::SettingsLora:    title = "LoRa Radio"; break;
    case Screen::SettingsGps:     title = "GPS Receiver"; break;
    case Screen::SettingsDisplay: title = "Display & Theme"; break;
    case Screen::SettingsWifi:    title = "WiFi Network"; break;
    default: break;
    }
    drawHeader(title);
    char items[8][40];
    int n = buildSettingItems(s, items);
    if (settingsSel >= n) settingsSel = n - 1;
    if (settingsSel < 0) settingsSel = 0;

    for (int i = 0; i < n; i++) {
        int y = 32 + i * 28;
        bool sel = (i == settingsSel);
        uint16_t rowBg = sel ? theme().accent : glassBase();
        uint16_t rowFg = sel ? (isLightTheme() ? TFT_WHITE : bgColor()) : theme().fg;

        if (sel) {
            canvas.fillRoundRect(8, y, 304, 24, 7, rowBg);
        } else {
            glassCard(8, y, 304, 24, 7, false);
        }

        // Split "Label: Value" into left label and right value badge when ':' is present
        char *colon = strchr(items[i], ':');
        if (colon != nullptr) {
            *colon = '\0';
            const char *val = colon + 2;
            putText(18, y + 4, items[i], rowFg, rowBg);

            uint16_t valBg = sel ? mix(rowFg, rowBg, 210) : subCardBase();
            uint16_t valFg = sel ? rowFg : theme().accent;
            int vw = static_cast<int>(canvas.textWidth(val)) + 12;
            canvas.fillRoundRect(304 - vw, y + 3, vw, 18, 5, valBg);
            centerText(304 - vw / 2, y + 4, val, valFg, valBg);
        } else {
            putText(18, y + 4, items[i], rowFg, rowBg);
            if (i < n - 1) {
                putText(294, y + 4, ">", sel ? rowFg : mutedText(), rowBg);
            }
        }
    }
}
static void drawSoon()
{
    useFont();
    drawBackdrop();
    drawHeader(soonName);
    centerText(160, 100, "Coming in a later build", theme().fg, backdropAt(100));
}

static int signalY(float rssi)
{
    int v = static_cast<int>(rssi);
    if (v < -130) v = -130;
    if (v > -40) v = -40;
    return 186 - (v + 130) * 160 / 90;
}

// Plot geometry: trace on top, waterfall below, shared x axis from x 40 to 311.
static constexpr int kPlotX = 40;
static constexpr int kPlotW = 272;
static constexpr int kTraceTop = 50;
static constexpr int kTraceBot = 114;
static constexpr int kWfTop = 122;
static constexpr uint16_t kPeakYellow = 0xFFE0;

static int traceX(int i) { return kPlotX + i * (kPlotW - 1) / (kSpecPoints - 1); }

static int traceY(int db)
{
    int v = constrain(db, kSpecDbMin, kSpecDbMax);
    return kTraceBot - (v - kSpecDbMin) * (kTraceBot - kTraceTop) / (kSpecDbMax - kSpecDbMin);
}

static void drawSpectrum()
{
    if (!specPaletteReady) buildSpecPalette();
    useFont();
    drawBackdrop();
    drawHeader(specLive ? "Spectrum" : "Spectrum paused");
    glassCard(2, 26, 316, 212, 8);
    uint16_t plotBg = mix(glassBase(), TFT_BLACK, 120);

    // Readout row: span on the left, peak on the right.
    putText(10, 29, "span 25.75 MHz", kMuted, glassBase());
    int peak = 0;
    for (int i = 1; i < kSpecPoints; i++) {
        if (specDb[i] > specDb[peak]) peak = i;
    }
    if (specScanned) {
        char pk[40];
        snprintf(pk, sizeof(pk), "peak %d @ %.2f", specDb[peak], kSpecStartMHz + kSpecStepMHz * peak);
        canvas.setTextColor(kPeakYellow, glassBase());
        canvas.setCursor(312 - static_cast<int>(canvas.textWidth(pk)), 29);
        canvas.print(pk);
    }

    // Trace plot with dBm axis.
    canvas.fillRect(kPlotX, kTraceTop, kPlotW, kTraceBot - kTraceTop + 1, plotBg);
    canvas.drawRect(kPlotX, kTraceTop, kPlotW, kTraceBot - kTraceTop + 1, kBorder);
    canvas.drawFastHLine(kPlotX, traceY(-110), kPlotW, kBorder);
    putText(6, traceY(-90) - 8, "-90", kMuted, glassBase());
    putText(6, traceY(-110) - 8, "-110", kMuted, glassBase());
    putText(6, traceY(-130) - 8, "-130", kMuted, glassBase());
    if (specScanned) {
        for (int i = 1; i < kSpecPoints; i++) {
            canvas.drawLine(traceX(i - 1), traceY(specDb[i - 1]), traceX(i), traceY(specDb[i]), theme().accent);
        }
        canvas.fillCircle(traceX(peak), traceY(specDb[peak]), 3, kPeakYellow);
    } else {
        centerText(kPlotX + kPlotW / 2, 74, "Scanning 902 to 928 MHz", kMuted, plotBg);
    }

    // Waterfall: newest sweep on top, 2 px per sweep.
    canvas.fillRect(kPlotX, kWfTop, kPlotW, kWfRows * 2, plotBg);
    if (specScanned) {
        for (int r = 0; r < kWfRows; r++) {
            int row = (wfHead - 1 - r + kWfRows) % kWfRows;
            int y = kWfTop + r * 2;
            for (int i = 0; i < kSpecPoints; i++) {
                int x0 = kPlotX + i * kPlotW / kSpecPoints;
                int x1 = kPlotX + (i + 1) * kPlotW / kSpecPoints;
                canvas.fillRect(x0, y, x1 - x0, 2, specPalette[wfRows[row][i]]);
            }
        }
    }

    // Color legend: quiet at the bottom, loud at the top.
    const int legendH = kWfRows * 2;
    for (int y = 0; y < legendH; y++) {
        canvas.drawFastHLine(4, kWfTop + y, 6, specPalette[255 - y * 255 / (legendH - 1)]);
    }
    putText(13, kWfTop - 2, "-90", kMuted, glassBase());
    putText(13, kWfTop + legendH - 14, "-130", kMuted, glassBase());

    // Frequency axis.
    putText(kPlotX, 194, "902.00", kMuted, glassBase());
    centerText(kPlotX + kPlotW / 2, 194, "915.00 MHz", kMuted, glassBase());
    canvas.setTextColor(kMuted, glassBase());
    canvas.setCursor(312 - static_cast<int>(canvas.textWidth("927.75")), 194);
    canvas.print("927.75");

    centerText(160, 216, specLive ? "Enter pauses" : "Enter resumes", kMuted, glassBase());
}

static void drawSignal()
{
    useFont();
    drawBackdrop();
    drawHeader("Signal");
    drawPanel(4, 28, 312, 168);
    canvas.drawFastHLine(10, signalY(-60), 300, kBorder);
    canvas.drawFastHLine(10, signalY(-100), 300, kBorder);
    if (rssiHist.size() < 2) {
        centerText(160, 110, "Waiting for packets", kMuted, glassBase());
    }
    for (size_t i = 1; i < rssiHist.size(); i++) {
        int x0 = 10 + static_cast<int>((i - 1) * 5), x1 = 10 + static_cast<int>(i * 5);
        int y0 = signalY(rssiHist[i - 1]), y1 = signalY(rssiHist[i]);
        canvas.drawLine(x0, y0, x1, y1, theme().accent);
        canvas.drawLine(x0, y0 + 1, x1, y1 + 1, theme().accent);
    }
    char line[48];
    float last = rssiHist.empty() ? 0 : rssiHist.back();
    snprintf(line, sizeof(line), "RSSI %.0f dBm   SNR %.1f dB", last, lastSnr);
    putText(10, 202, line, theme().fg, backdropAt(202));
}

static void drawContacts()
{
    useFont();
    drawBackdrop();
    drawHeader("Contacts");
    drawPanel(4, 34, 312, 120);
    centerText(160, 64, "Encrypted contacts", theme().fg, glassBase());
    centerText(160, 92, "Coming after the two-device test", kMuted, glassBase());
}

static void drawCalibrate()
{
    useFont();
    drawBackdrop();
    static const int kTargetX[4] = {12, 307, 12, 307};
    static const int kTargetY[4] = {34, 34, 227, 227};
    for (int i = 0; i < 4; i++) {
        uint16_t col = (i == calStep) ? theme().accent : kMuted;
        canvas.drawCircle(kTargetX[i], kTargetY[i], 8, col);
        canvas.drawFastHLine(kTargetX[i] - 10, kTargetY[i], 21, col);
        canvas.drawFastVLine(kTargetX[i], kTargetY[i] - 10, 21, col);
    }
    drawPanel(48, 92, 224, 62);
    centerText(160, 104, "Tap the glowing crosshair", theme().fg, glassBase());
    char step[24];
    snprintf(step, sizeof(step), "Corner %d of 4", calStep + 1);
    centerText(160, 126, step, theme().accent, glassBase());
}

static void drawScreen()
{
    switch (screen) {
    case Screen::Calibrate: drawCalibrate(); break;
    case Screen::Spectrum: drawSpectrum(); break;
    case Screen::Signal: drawSignal(); break;
    case Screen::Soon: drawContacts(); break;
    case Screen::Home: drawHome(); break;
    case Screen::Public: drawPublic(); break;
    case Screen::Nodes: drawNodes(); break;
    case Screen::NodeInfo: drawNodeInfo(); break;
    case Screen::Map: drawMap(); break;
    case Screen::Settings:
    case Screen::SettingsDevice:
    case Screen::SettingsLora:
    case Screen::SettingsGps:
    case Screen::SettingsDisplay:
    case Screen::SettingsWifi: drawSettingsScreen(screen); break;
    case Screen::WifiPassword: drawWifiPassword(); break;
    }
    canvas.pushSprite(&lcd, 0, 0);
}
static void goHome()
{
    screen = Screen::Home;
}

static void openTile(int i)
{
    switch (i) {
    case 0: screen = Screen::Public; unreadChat = 0; break;
    case 1:
        screen = Screen::Map;
        mapFollow = true;
        mapCx = mercX(0.0, mapZoom);
        mapCy = mercY(0.0, mapZoom);
        break;
    case 2: screen = Screen::Nodes; break;
    case 5: screen = Screen::Settings; settingsSel = 0; break;
    case 3:
        screen = Screen::Spectrum;
        specLive = true;
        break;
    case 4:
        screen = Screen::Signal;
        break;
    default:
        soonName = kTiles[i];
        screen = Screen::Soon;
        break;
    }
}

// Back from a settings screen: sub-screens return to Settings, Settings returns home.
static void openNodeInfo(int i)
{
    if (i < 0 || i >= static_cast<int>(nodes.size())) return;
    nodeSel = i;
    screen = Screen::NodeInfo;
}

static void backFrom(Screen s)
{
    settingsSel = 0;
    if (s == Screen::WifiPassword) screen = Screen::SettingsWifi;
    else if (s == Screen::NodeInfo) screen = Screen::Nodes;
    else if (s == Screen::Nodes) goHome();
    else if (s == Screen::Settings) goHome();
    else if (isSettingsScreen(s)) screen = Screen::Settings;
    else goHome();
}

static void activateSettingItem(Screen s, int i)
{
    switch (s) {
    case Screen::Settings:
        settingsSel = 0;
        if (i == 0) screen = Screen::SettingsDevice;
        else if (i == 1) screen = Screen::SettingsLora;
        else if (i == 2) screen = Screen::SettingsGps;
        else if (i == 3) screen = Screen::SettingsDisplay;
        else if (i == 4) { screen = Screen::SettingsWifi; settingsSel = 0; }
        else if (i == 5) { calStep = 0; screen = Screen::Calibrate; }
        else goHome();
        break;
    case Screen::SettingsWifi: {
        int networkRows = wifiFound;
        if (i == 0) {
            // Status row: nothing to activate.
        } else if (i <= networkRows) {
            int k = i - 1;
            if (wifiSecure[k]) {
                wifiPickSsid = wifiNames[k];
                wifiPassBuf = "";
                screen = Screen::WifiPassword;
            } else {
                connectWifi(wifiNames[k], "");
            }
        } else if (i == networkRows + 1) {
            scanWifi();
        } else if (i == networkRows + 2) {
            forgetWifi();
        } else if (i == networkRows + 3) {
            backFrom(s);
        }
        break;
    }
    case Screen::SettingsDevice:
        if (i == 4) backFrom(s);
        break;
    case Screen::SettingsLora:
        if (i == 3) {
            txDbm = (txDbm == 10) ? 14 : (txDbm == 14) ? 17 : (txDbm == 17) ? 20 : 10;
            saveSettings();
        } else if (i == 4) {
            hopLimit = hopLimit % 7 + 1;
            saveSettings();
        } else if (i == 5) {
            backFrom(s);
        }
        break;
    case Screen::SettingsGps:
        if (i == 0) toggleGps();
        else if (i == 1) gpsIntervalIdx = (gpsIntervalIdx + 1) % 4;
        else if (i == 3) backFrom(s);
        saveSettings();
        break;
    case Screen::SettingsDisplay:
        if (i == 0) themeIndex = (themeIndex + 1) % kThemeCount;
        else if (i == 1) bgIndex = (bgIndex + 1) % kBackgroundCount;
        else if (i == 2) backFrom(s);
        saveSettings();
        break;
    default:
        break;
    }
}

static void activateWidget(int i)
{
    // Widget order on screen is WiFi, GPS, BT.
    if (i == 0) toggleWifi();
    else if (i == 1) toggleGps();
    else toggleBt();
}

static void handleKey(int c)
{
    Serial.printf("key 0x%02X\n", c);
    // Trackball codes 0x80-0x84 (up, down, left, right, center).
    const bool track = (c >= 0x80 && c <= 0x84);
    if (track && screen == Screen::WifiPassword) return;   // the trackball must not type into the password
    if (track && screen == Screen::Public) {
        // Trackball never types into the chat: left leaves, center sends or leaves when empty.
        if (c == 0x80 && inputBuf.length() == 0) {
            openTile(kTileCount - 1);
            drawScreen();
            return;
        }
        if (c == 0x80 || c == 0x81 || c == 0x83) return;
        if (c == 0x82 || (c == 0x84 && inputBuf.length() == 0)) {
            goHome();
            drawScreen();
            return;
        }
        c = '\r';
    } else if (track) {
        c = (c == 0x80) ? 'w' : (c == 0x81) ? 's' : (c == 0x82) ? 'a' : (c == 0x83) ? 'd' : '\r';
    }
    if (c == 27) {
        goHome();
    } else if (screen == Screen::Home) {
        if (homeSel >= kWidgetFirst) {
            int w = homeSel - kWidgetFirst;
            if (c == 'a') homeSel = kWidgetFirst + (w + 2) % 3;
            else if (c == 'd') homeSel = kWidgetFirst + (w + 1) % 3;
            else if (c == 's') homeSel = (w * 2 < kTileCount) ? w * 2 : kTileCount - 1;
            else if (c == '\r' || c == '\n') activateWidget(w);
        } else {
            if (c == 'a') homeSel = (homeSel + kTileCount - 1) % kTileCount;
            else if (c == 'd') homeSel = (homeSel + 1) % kTileCount;
            else if (c == 'w') homeSel = kWidgetFirst + (homeSel / 2 < 2 ? homeSel / 2 : 2);
            else if (c == '\r' || c == '\n') openTile(homeSel);
        }
    } else if (screen == Screen::Public) {
        if (c == '\r' || c == '\n') {
            if (inputBuf.length()) {
                String text = inputBuf;
                inputBuf = "";
                if (sendPublic(text)) {
                    addLine("me: " + text);
                } else {
                    addLine("! not sent, see USB log");
                }
            }
        } else if (c == 8 || c == 127) {
            if (inputBuf.length()) inputBuf.remove(inputBuf.length() - 1);
            else goHome();
        } else if (c >= 32 && c < 127) {
            inputBuf += static_cast<char>(c);
        }
    } else if (isSettingsScreen(screen)) {
        char tmp[8][40];
        int n = buildSettingItems(screen, tmp);
        if (n > 0) {
            if (c == 'w') settingsSel = (settingsSel + n - 1) % n;
            else if (c == 's') settingsSel = (settingsSel + 1) % n;
            else if (c == '\r' || c == '\n') activateSettingItem(screen, settingsSel);
            else if (c == 'q' || c == 8 || c == 127) backFrom(screen);
        }
    } else if (screen == Screen::Spectrum && (c == 'r' || c == '\r' || c == '\n')) {
        specLive = !specLive;
    } else if (screen == Screen::Nodes) {
        int n = static_cast<int>(nodes.size());
        if (n > 0) {
            if (c == 'w') nodeSel = (nodeSel + n - 1) % n;
            else if (c == 's') nodeSel = (nodeSel + 1) % n;
            else if (c == '\r' || c == '\n') openNodeInfo(nodeSel);
        }
        if (c == 'q' || c == 8 || c == 127) goHome();
    } else if (screen == Screen::NodeInfo) {
        if (c == 'q' || c == 8 || c == 127 || c == '\r' || c == '\n') screen = Screen::Nodes;
    } else if (screen == Screen::WifiPassword) {
        if (c == '\r' || c == '\n') {
            connectWifi(wifiPickSsid, wifiPassBuf);
            wifiPassBuf = "";
            screen = Screen::SettingsWifi;
            settingsSel = 0;
        } else if (c == 8 || c == 127) {
            if (wifiPassBuf.length()) wifiPassBuf.remove(wifiPassBuf.length() - 1);
            else screen = Screen::SettingsWifi;
        } else if (c >= 32 && c < 127) {
            wifiPassBuf += static_cast<char>(c);
        }
    } else if (screen == Screen::Map) {
        if (c == 'w') mapPan(0, -kTilePx / 8);
        else if (c == 's') mapPan(0, kTilePx / 8);
        else if (c == 'a') mapPan(-kTilePx / 8, 0);
        else if (c == 'd') mapPan(kTilePx / 8, 0);
        else if (c == '+' || c == '=') mapZoomBy(1);
        else if (c == '-') mapZoomBy(-1);
        else if (c == '\r' || c == '\n') mapFollow = true;
        if (c == 'q' || c == 8 || c == 127) goHome();
    } else {
        if (c == 'q' || c == 8 || c == 127) goHome();
    }
    drawScreen();
}

static void pollKeyboard()
{
    static uint32_t last = 0;
    if (millis() - last < 20) return;
    last = millis();
    Wire.requestFrom(kKeyboardAddr, (uint8_t)1);
    if (Wire.available()) {
        int c = Wire.read();
        if (c > 0) handleKey(c);
    }
}

// Trackball switches (T-Deck). The pin map is unverified: each press is logged with its pin
// so a swapped direction shows up on the USB console.
struct TrackPin {
    int pin;
    int key;
    bool lastHigh;
    uint32_t lastMs;
};
static TrackPin trackPins[] = {
    {3, 0x80, true, 0},   // up
    {15, 0x81, true, 0},  // down
    {1, 0x82, true, 0},   // left
    {2, 0x83, true, 0},   // right
    {0, 0x84, true, 0},   // center press (BOOT), acts as Enter
};

static void setupTrackball()
{
    for (TrackPin &t : trackPins) pinMode(t.pin, INPUT_PULLUP);
}

static void pollTrackball()
{
    uint32_t now = millis();
    for (TrackPin &t : trackPins) {
        bool high = digitalRead(t.pin) != 0;
        if (!high && t.lastHigh && now - t.lastMs > 40) {
            t.lastMs = now;
            Serial.printf("trackball pin %d -> key 0x%02X\n", t.pin, t.key);
            handleKey(t.key);
        }
        t.lastHigh = high;
    }
}
// GT911 capacitive touch (T-Deck Plus). Raw touch coordinates are logged on each tap;
// the screen mapping assumes a landscape display and is verified on the device.
static uint8_t gt911Addr = 0;

static bool gt911Probe(uint8_t a)
{
    Wire.beginTransmission(a);
    return Wire.endTransmission() == 0;
}

static bool gt911Read(uint16_t reg, uint8_t *buf, size_t len)
{
    Wire.beginTransmission(gt911Addr);
    Wire.write(static_cast<uint8_t>(reg >> 8));
    Wire.write(static_cast<uint8_t>(reg & 0xFF));
    if (Wire.endTransmission(false) != 0) return false;
    size_t got = Wire.requestFrom(gt911Addr, static_cast<uint8_t>(len));
    if (got != len) return false;
    for (size_t i = 0; i < len; i++) buf[i] = Wire.read();
    return true;
}

static bool gt911Write(uint16_t reg, uint8_t v)
{
    Wire.beginTransmission(gt911Addr);
    Wire.write(static_cast<uint8_t>(reg >> 8));
    Wire.write(static_cast<uint8_t>(reg & 0xFF));
    Wire.write(v);
    return Wire.endTransmission() == 0;
}

static void setupTouch()
{
    if (gt911Probe(0x5D)) gt911Addr = 0x5D;
    else if (gt911Probe(0x14)) gt911Addr = 0x14;
    if (gt911Addr) Serial.printf("touch GT911 at 0x%02X\n", gt911Addr);
    else Serial.println("no touch controller found (standard T-Deck has none)");
}

// Touch calibration: four taps on the + marks give the mapping from raw touch to screen.
struct CalData {
    int32_t L, R, T, B;
    uint8_t swap;
    uint8_t valid;
    uint8_t pad[2];
};
static CalData cal = {0, 0, 0, 0, 0, 0, {0, 0}};
static uint16_t calRawX[4], calRawY[4];

static void loadCal()
{
    Preferences p;
    p.begin("meshport", true);
    if (p.getBytesLength("calv2") == sizeof(cal)) p.getBytes("calv2", &cal, sizeof(cal));
    p.end();
}

static void saveCal()
{
    Preferences p;
    p.begin("meshport", false);
    p.putBytes("calv2", &cal, sizeof(cal));
    p.end();
}

static void touchToScreen(uint16_t x, uint16_t y, int &sx, int &sy)
{
    if (!cal.valid) {
        // Mapping verified on this panel (Wadamesh T-Deck driver): screen x follows touch y,
        // screen y is the mirrored touch x.
        sx = constrain(static_cast<int>(y), 0, 319);
        sy = constrain(239 - static_cast<int>(x), 0, 239);
        return;
    }
    int32_t v = cal.swap ? static_cast<int32_t>(y) : static_cast<int32_t>(x);
    int32_t w = cal.swap ? static_cast<int32_t>(x) : static_cast<int32_t>(y);
    int32_t dx = cal.R - cal.L;
    if (dx == 0) dx = 1;
    int32_t dy = cal.B - cal.T;
    if (dy == 0) dy = 1;
    sx = constrain(12 + static_cast<int>((v - cal.L) * 295 / dx), 0, 319);
    sy = constrain(12 + static_cast<int>((w - cal.T) * 215 / dy), 0, 239);
}

static void computeCal()
{
    // Taps: 0 top-left, 1 top-right, 2 bottom-left, 3 bottom-right.
    int32_t colDeltaX = static_cast<int32_t>(calRawX[1]) + calRawX[3] - calRawX[0] - calRawX[2];
    int32_t colDeltaY = static_cast<int32_t>(calRawY[1]) + calRawY[3] - calRawY[0] - calRawY[2];
    if (colDeltaX < 0) colDeltaX = -colDeltaX;
    if (colDeltaY < 0) colDeltaY = -colDeltaY;
    if (colDeltaY > colDeltaX) {
        cal.swap = 1;
        cal.L = (static_cast<int32_t>(calRawY[0]) + calRawY[2]) / 2;
        cal.R = (static_cast<int32_t>(calRawY[1]) + calRawY[3]) / 2;
        cal.T = (static_cast<int32_t>(calRawX[0]) + calRawX[1]) / 2;
        cal.B = (static_cast<int32_t>(calRawX[2]) + calRawX[3]) / 2;
    } else {
        cal.swap = 0;
        cal.L = (static_cast<int32_t>(calRawX[0]) + calRawX[2]) / 2;
        cal.R = (static_cast<int32_t>(calRawX[1]) + calRawX[3]) / 2;
        cal.T = (static_cast<int32_t>(calRawY[0]) + calRawY[1]) / 2;
        cal.B = (static_cast<int32_t>(calRawY[2]) + calRawY[3]) / 2;
    }
    int32_t spanX = cal.R - cal.L;
    if (spanX < 0) spanX = -spanX;
    int32_t spanY = cal.B - cal.T;
    if (spanY < 0) spanY = -spanY;
    Serial.printf("touch calibration swap=%u L=%ld R=%ld T=%ld B=%ld spanX=%ld spanY=%ld\n", cal.swap,
                  (long)cal.L, (long)cal.R, (long)cal.T, (long)cal.B, (long)spanX, (long)spanY);
    if (spanX < 200 || spanY < 200) {
        cal.valid = 0;
        saveCal();
        Serial.println("calibration rejected: taps too close together, run it again");
        return;
    }
    cal.valid = 1;
    saveCal();
    Serial.println("calibration saved");
}

static void recordCalTap(uint16_t x, uint16_t y)
{
    static const int kTargetX[4] = {12, 307, 12, 307};
    static const int kTargetY[4] = {12, 12, 227, 227};
    (void)kTargetX;
    (void)kTargetY;
    calRawX[calStep] = x;
    calRawY[calStep] = y;
    calStep++;
    if (calStep >= 4) {
        calStep = 0;
        computeCal();
        screen = Screen::Settings;
    }
}

static void handleTouchTap(uint16_t x, uint16_t y)
{
    int sx = 0, sy = 0;
    touchToScreen(x, y, sx, sy);
    Serial.printf("tap screen x=%d y=%d\n", sx, sy);
    if (screen != Screen::Home && sy < 22 && sx < 66) {
        backFrom(screen);
    } else if (screen == Screen::Public && sy < 22 && sx >= 250) {
        openTile(kTileCount - 1);
    } else if (screen == Screen::Home) {
        if (sy >= 30 && sy < 130 && sx >= 162) {
            int w = constrain((sx - 162) / 51, 0, 2);
            homeSel = kWidgetFirst + w;
            activateWidget(w);
        } else if (sy >= 140 && sy < 194) {
            int idx = constrain(sx / 53, 0, kTileCount - 1);
            homeSel = idx;
            openTile(idx);
        }
    } else if (isSettingsScreen(screen)) {
        char tmp[8][40];
        int n = buildSettingItems(screen, tmp);
        if (sy >= 36 && sy < 36 + n * 26) {
            int i = constrain((sy - 36) / 26, 0, n - 1);
            settingsSel = i;
            activateSettingItem(screen, i);
        }
    } else if (screen == Screen::Nodes && sy >= 30 && sy < 30 + 6 * 33) {
        int idx = nodeTop() + (sy - 30) / 33;
        if (idx < static_cast<int>(nodes.size())) openNodeInfo(idx);
    } else if (screen == Screen::Spectrum && sy >= 18) {
        specLive = !specLive;
    } else if (sy < 18) {
        goHome();
    }
    drawScreen();
}

static void pollTouch()
{
    static bool wasDown = false;
    static uint32_t lastTap = 0;
    static uint32_t last = 0;
    if (!gt911Addr) return;
    if (millis() - last < 30) return;
    last = millis();
    uint8_t status = 0;
    if (!gt911Read(0x814E, &status, 1)) return;
    static uint32_t lastFrame = 0;
    if (!(status & 0x80)) {
        if (wasDown && millis() - lastFrame > 250) wasDown = false;
        return;
    }
    lastFrame = millis();
    uint8_t points = status & 0x0F;
    if (points > 0) {
        uint8_t p[8];
        if (gt911Read(0x8150, p, 8) && !wasDown && millis() - lastTap > 400) {
            lastTap = millis();
            // Measured layout: X low/high at bytes 0-1, Y low/high at bytes 2-3, size at byte 4.
            uint16_t x = p[0] | (p[1] << 8);
            uint16_t y = p[2] | (p[3] << 8);
            Serial.printf("touch bytes %02X %02X %02X %02X %02X %02X %02X %02X\n", p[0], p[1], p[2], p[3],
                          p[4], p[5], p[6], p[7]);
            Serial.printf("touch raw x=%u y=%u\n", x, y);
            if (screen == Screen::Calibrate) {
                recordCalTap(x, y);
                drawScreen();
            } else {
                handleTouchTap(x, y);
            }
        }
        wasDown = true;
    } else {
        wasDown = false;
    }
    gt911Write(0x814E, 0);
}
#endif

// Routing acknowledgment for a received packet that asked for one. The sender
// marks a message "Failed to deliver" until it sees this, so every packet with
// want_ack gets one, including duplicates.
static void sendAck(const Header &req)
{
    packetCounter++;
    Data d;
    d.portnum = 5;               // ROUTING_APP
    d.payload = {0x18, 0x00};    // Routing { error_reason: NONE }
    d.requestId = req.id;
    Header h{};
    h.to = req.from;
    h.from = myNode;
    h.id = packetCounter;
    h.flags = 0x03 | (0x03 << kFlagHopStartShift);
    h.channel = channelByte;
    std::vector<uint8_t> frame;
    if (sealFrame(kChannelKey, sizeof(kChannelKey), h, d, frame)) {
        if (driver->send(frame)) {
            Serial.printf("ack sent for %08lX\n", (unsigned long)req.id);
        }
    }
}

void setup()
{
    Serial.begin(115200);
    delay(1500);
    Serial.println("meshport chat");

    // T-Deck peripheral power (LoRa radio). Must be HIGH before the radio responds.
#ifdef MESHPORT_TDECK_SCREEN
    loadSettings();
#endif
    pinMode(CHAT_POWER_PIN, OUTPUT);
    digitalWrite(CHAT_POWER_PIN, CHAT_POWER_ON);
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
    s.powerDbm = txDbm;   // set in Settings > LoRa radio, applied at boot
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
    packetCounter = (uint32_t)random(1, 0x7fffffff);
    channelByte = static_cast<uint8_t>(channelHash("LongFast", kChannelKey, sizeof(kChannelKey)));
#ifdef MESHPORT_TDECK_SCREEN
    loraFreqMHz = freq;
#endif
    Serial.printf("radio ok: %.3f MHz\n", freq);
    showId();
    Serial.println("type help for commands");
#ifdef MESHPORT_TDECK_SCREEN
    pinMode(42, OUTPUT);       // backlight
    digitalWrite(42, HIGH);
    Wire.begin(18, 8);         // T-Deck I2C (keyboard)
    WiFi.mode(WIFI_OFF);
    setupTrackball();
    setupTouch();
    lcd.init();
    lcd.setRotation(1);
    canvas.setPsram(true);
    if (!canvas.createSprite(320, 240)) {
        canvas.setPsram(false);
        if (!canvas.createSprite(320, 240)) Serial.println("draw buffer FAILED");
    }
    loadCal();
    addLine("Enter on a tile to open it");
    drawScreen();
#endif
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
#ifdef MESHPORT_TDECK_SCREEN
    pollKeyboard();
    pollTrackball();
    pollTouch();
    pollGps();
    pollWifi();
    if (screen == Screen::Spectrum && specLive && millis() - specSweepMs > 150) {
        sweepSpectrum();
        drawScreen();
    }
    static uint32_t lastAnim = 0;
    if (screen == Screen::Home && gpsOn && millis() - lastAnim > 180) {
        lastAnim = millis();
        drawScreen();
    }
#endif

    if (driver->poll(rx, rssi, snr)) {
        if (rx.size() >= 16) {
            Header req = unpackHeader(rx.data());
            if ((req.flags & kFlagWantAckMask) && req.from != myNode &&
                (req.to == myNode || req.to == 0xFFFFFFFFu)) {
                sendAck(req);
            }
        }
#ifdef MESHPORT_TDECK_SCREEN
        if (rx.size() >= 16) {
            Header seen = unpackHeader(rx.data());
            if (seen.from != myNode) {
                noteNode(seen.from, rssi, snr);
                pushRssi(rssi);
                lastSnr = snr;
            }
        }
#endif
        // Debug: every frame heard, decodable or not.
        if (rx.size() >= 16) {
            Header dbg = unpackHeader(rx.data());
            Serial.printf("rx %u bytes from %08lX to %08lX (rssi %.0f)\n", (unsigned)rx.size(),
                          (unsigned long)dbg.from, (unsigned long)dbg.to, rssi);
        } else {
            Serial.printf("rx %u bytes (too short)\n", (unsigned)rx.size());
        }
        // Relay: rebroadcast each broadcast packet once, with the hop limit reduced.
        // Meshtastic senders wait for a neighbor to repeat their broadcast as confirmation.
        bool fresh = false;
        if (rx.size() >= 16) {
            Header rh = unpackHeader(rx.data());
            fresh = rh.from != myNode && !seenPublic.checkAndInsert(rh.from, rh.id);
            if (fresh && rh.to == 0xFFFFFFFFu && decrementHopLimit(rh)) {
                std::vector<uint8_t> out = rx;
                packHeader(rh, out.data());
                delay(random(50, 250));
                if (driver->send(out)) {
                    Serial.printf("relayed %08lX\n", (unsigned long)rh.id);
                }
            }
        }
        uint32_t from = 0;
        std::string text;
        if (openDirectFrame(kChannelKey, sizeof(kChannelKey), me, rx.data(), rx.size(), guard, from, text)) {
            Serial.printf("[%08lX] %s  (rssi %.0f)\n", (unsigned long)from, text.c_str(), rssi);
        } else {
            Header h{};
            Data d;
            bool decoded = openFrame(kChannelKey, sizeof(kChannelKey), rx.data(), rx.size(), h, d);
#ifdef MESHPORT_TDECK_SCREEN
            if (decoded && d.portnum == kPortPositionApp) notePosition(h.from, d.payload);
#endif
            if (decoded && d.portnum == kPortTextMessage && h.to == 0xFFFFFFFFu && h.from != myNode &&
                fresh) {
                std::string body(d.payload.begin(), d.payload.end());
                Serial.printf("[PUBLIC %08lX] %s  (rssi %.0f)\n", (unsigned long)h.from, body.c_str(), rssi);
#ifdef MESHPORT_TDECK_SCREEN
                char who[12];
                snprintf(who, sizeof(who), "%08lX", (unsigned long)h.from);
                addLine(String(who) + ": " + String(body.c_str()));
                if (screen != Screen::Public) unreadChat++;
                drawScreen();
#endif
            }
        }
        // Frames that are not direct messages for this device (other traffic) are ignored.
    }
}
