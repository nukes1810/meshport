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
    h.flags = 0x03 | (0x03 << kFlagHopStartShift);
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
    } else {
        Serial.println("unknown command, type help");
    }
}

#ifdef MESHPORT_TDECK_SCREEN
// On-device UI: home screen with app tiles, public chat, nodes, settings, and themes.
// Keys: w/a/s/d move, Enter opens or activates, q or Backspace (empty input) goes back.
static LGFX_TDeck lcd;
static std::vector<String> chatLines;
static String inputBuf;
static constexpr int kMaxLines = 12;
static constexpr int kLineChars = 24;
static constexpr uint8_t kKeyboardAddr = 0x55;

struct Theme {
    const char *name;
    uint16_t bg, fg, accent, panel;
};
static const Theme kThemes[] = {
    {"Neon Blue", 0x0021, TFT_WHITE, 0x06FF, 0x08A5},
    {"Neon Green", 0x0021, TFT_WHITE, 0x07E0, 0x0320},
    {"Light", TFT_WHITE, TFT_BLACK, TFT_BLUE, 0xDEFB},
    {"Dark", TFT_BLACK, TFT_WHITE, TFT_CYAN, 0x2104},
};
static constexpr int kThemeCount = 4;
static int themeIndex = 0;

enum class Screen { Home, Public, Nodes, Settings, Spectrum, Signal, Soon };
static Screen screen = Screen::Home;
static int homeSel = 0;
static int settingsSel = 0;
static const char *kTiles[] = {"Public", "Contacts", "Nodes", "Spectrum", "Signal", "Settings"};
static constexpr int kTileCount = 6;
static const char *soonName = "";

struct NodeEntry {
    uint32_t id;
    float rssi;
    uint32_t lastMs;
};
static std::vector<NodeEntry> nodes;
static constexpr size_t kMaxNodes = 16;

static void noteNode(uint32_t id, float rssi)
{
    for (NodeEntry &n : nodes) {
        if (n.id == id) {
            n.rssi = rssi;
            n.lastMs = millis();
            return;
        }
    }
    if (nodes.size() < kMaxNodes) nodes.push_back({id, rssi, millis()});
}

static const Theme &theme() { return kThemes[themeIndex]; }

// Spectrum and signal analyzers.
static float loraFreqMHz = 906.875f;
static constexpr int kSpecPoints = 52;   // 902.0 MHz to 927.5 MHz in 0.5 MHz steps
static float specDb[kSpecPoints];
static bool specScanned = false;
static constexpr size_t kSignalSamples = 60;
static std::vector<float> rssiHist;
static float lastSnr = 0;

static void pushRssi(float rssi)
{
    rssiHist.push_back(rssi);
    if (rssiHist.size() > kSignalSamples) rssiHist.erase(rssiHist.begin());
}

static void sweepSpectrum()
{
    for (int i = 0; i < kSpecPoints; i++) {
        float f = 902.0f + 0.5f * i;
        radio->setFrequency(f);
        radio->startReceive();
        delayMicroseconds(3000);
        specDb[i] = radio->getRSSI();
    }
    radio->setFrequency(loraFreqMHz);
    radio->startReceive();
    specScanned = true;
    Serial.println("spectrum sweep done");
}

static const uint16_t kBackgrounds[] = {0, TFT_BLACK, TFT_NAVY, 0x2104, TFT_DARKGREEN};
static const char *kBackgroundNames[] = {"Theme", "Black", "Navy", "Charcoal", "Forest"};
static constexpr int kBackgroundCount = 5;
static int bgIndex = 0;
static uint16_t bgColor() { return bgIndex == 0 ? theme().bg : kBackgrounds[bgIndex]; }

static bool wifiOn = false;
static bool btOn = false;
static bool gpsOn = false;
static constexpr int kSettingsCount = 6;
static constexpr int kWidgetFirst = 6;

static void toggleWifi()
{
    wifiOn = !wifiOn;
    WiFi.mode(wifiOn ? WIFI_STA : WIFI_OFF);
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
    Serial.printf("gps %s (GPS pins not wired yet)\n", gpsOn ? "on" : "off");
}

static void addLine(const String &s)
{
    chatLines.push_back(s.substring(0, kLineChars));
    while (chatLines.size() > kMaxLines) chatLines.erase(chatLines.begin());
}

static void drawHeader(const String &title)
{
    lcd.fillRect(0, 0, 320, 18, theme().accent);
    lcd.setTextColor(bgColor(), theme().accent);
    lcd.setTextSize(2);
    lcd.setCursor(4, 1);
    lcd.print(title);
}

static void drawPanel(int x, int y, int w, int h)
{
    lcd.fillRoundRect(x, y, w, h, 10, theme().panel);
    lcd.drawRoundRect(x, y, w, h, 10, theme().accent);
    lcd.drawRoundRect(x + 1, y + 1, w - 2, h - 2, 9, theme().accent);
}

static void drawToggle(int x, int y, bool on)
{
    lcd.fillRoundRect(x, y, 36, 18, 9, on ? theme().accent : 0x2104);
    lcd.fillCircle(on ? x + 27 : x + 9, y + 9, 7, TFT_WHITE);
}

static void drawHome()
{
    lcd.fillScreen(bgColor());

    // Status bar
    lcd.setTextSize(2);
    lcd.setTextColor(theme().accent, bgColor());
    lcd.setCursor(4, 2);
    lcd.print("meshport");
    char node[24];
    snprintf(node, sizeof(node), "node %08lX", (unsigned long)myNode);
    lcd.setTextSize(1);
    lcd.setTextColor(theme().fg, bgColor());
    lcd.setCursor(200, 8);
    lcd.print(node);
    lcd.drawFastHLine(0, 22, 320, theme().accent);

    // Status card
    drawPanel(4, 30, 150, 100);
    lcd.setTextSize(2);
    lcd.setTextColor(theme().fg, theme().panel);
    lcd.setCursor(14, 42);
    lcd.print("Mesh online");
    char up[32];
    snprintf(up, sizeof(up), "Up %lu min", (unsigned long)(millis() / 60000));
    lcd.setTextSize(1);
    lcd.setTextColor(theme().accent, theme().panel);
    lcd.setCursor(14, 72);
    lcd.print(up);
    char heard[32];
    snprintf(heard, sizeof(heard), "Nodes heard: %u", (unsigned)nodes.size());
    lcd.setCursor(14, 86);
    lcd.print(heard);
    lcd.setCursor(14, 100);
    lcd.print("LongFast 906.9 MHz");

    // Widget panel: WiFi, GPS, Bluetooth toggles
    drawPanel(162, 30, 154, 100);
    const char *names[3] = {"WiFi", "GPS", "BT"};
    bool states[3] = {wifiOn, gpsOn, btOn};
    for (int i = 0; i < 3; i++) {
        int x = 170 + i * 50;
        lcd.setTextSize(1);
        lcd.setTextColor(theme().fg, theme().panel);
        lcd.setCursor(x, 42);
        lcd.print(names[i]);
        bool sel = (homeSel == kWidgetFirst + i);
        if (sel) lcd.drawRoundRect(x - 4, 66, 44, 26, 8, TFT_WHITE);
        drawToggle(x, 70, states[i]);
        lcd.setTextColor(theme().accent, theme().panel);
        lcd.setCursor(x, 96);
        lcd.print(states[i] ? "ON" : "off");
    }

    // App row
    for (int i = 0; i < kTileCount; i++) {
        int cx = 26 + i * 53, cy = 165;
        bool sel = (homeSel == i);
        lcd.fillCircle(cx, cy, 18, sel ? theme().accent : theme().panel);
        lcd.drawCircle(cx, cy, 18, theme().accent);
        lcd.setTextSize(2);
        lcd.setTextColor(sel ? bgColor() : theme().fg, sel ? theme().accent : theme().panel);
        lcd.setCursor(cx - 6, cy - 8);
        lcd.print(kTiles[i][0]);
        lcd.setTextSize(1);
        lcd.setTextColor(theme().fg, bgColor());
        lcd.setCursor(cx - static_cast<int>(strlen(kTiles[i])) * 3, 190);
        lcd.print(kTiles[i]);
    }

    lcd.setTextSize(1);
    lcd.setTextColor(theme().accent, bgColor());
    lcd.setCursor(0, 226);
    lcd.print("w s a d move   Enter opens");
}

static void drawPublic()
{
    lcd.fillScreen(bgColor());
    drawHeader("Public chat");
    lcd.setTextColor(theme().fg, bgColor());
    lcd.setTextSize(2);
    for (size_t i = 0; i < chatLines.size(); i++) {
        lcd.setCursor(0, 22 + static_cast<int>(i) * 16);
        lcd.print(chatLines[i]);
    }
    lcd.setTextColor(theme().accent, bgColor());
    lcd.setCursor(0, 220);
    lcd.print("> ");
    lcd.print(inputBuf.substring(0, kLineChars - 2));
}

static void drawNodes()
{
    lcd.fillScreen(bgColor());
    char title[24];
    snprintf(title, sizeof(title), "Nodes (%u)", (unsigned)nodes.size());
    drawHeader(title);
    lcd.setTextColor(theme().fg, bgColor());
    lcd.setTextSize(2);
    uint32_t now = millis();
    for (size_t i = 0; i < nodes.size(); i++) {
        char line[32];
        snprintf(line, sizeof(line), "%08lX %4.0fdBm %lus", (unsigned long)nodes[i].id, nodes[i].rssi,
                 (unsigned long)((now - nodes[i].lastMs) / 1000));
        lcd.setCursor(0, 22 + static_cast<int>(i) * 16);
        lcd.print(line);
    }
    if (nodes.empty()) {
        lcd.setCursor(0, 22);
        lcd.print("No nodes heard yet");
    }
    lcd.setTextColor(theme().accent, bgColor());
    lcd.setCursor(0, 220);
    lcd.print("q: back");
}

static void drawSettings()
{
    lcd.fillScreen(bgColor());
    drawHeader("Settings");
    lcd.setTextSize(2);
    char items[kSettingsCount][32];
    snprintf(items[0], sizeof(items[0]), "Theme: %s", kThemes[themeIndex].name);
    snprintf(items[1], sizeof(items[1]), "Background: %s", kBackgroundNames[bgIndex]);
    snprintf(items[2], sizeof(items[2]), "WiFi: %s", wifiOn ? "on" : "off");
    snprintf(items[3], sizeof(items[3]), "Bluetooth: %s", btOn ? "on" : "off");
    snprintf(items[4], sizeof(items[4]), "GPS: %s", gpsOn ? "on" : "off");
    snprintf(items[5], sizeof(items[5]), "Back");
    for (int i = 0; i < kSettingsCount; i++) {
        bool sel = (i == settingsSel);
        int y = 40 + i * 30;
        lcd.fillRoundRect(4, y, 312, 26, 6, sel ? theme().accent : bgColor());
        lcd.setTextColor(sel ? bgColor() : theme().fg, sel ? theme().accent : bgColor());
        lcd.setCursor(12, y + 4);
        lcd.print(items[i]);
    }
    lcd.setTextColor(theme().accent, bgColor());
    lcd.setCursor(0, 222);
    lcd.print("Enter: change  q: back");
}

static void drawSoon()
{
    lcd.fillScreen(bgColor());
    drawHeader(soonName);
    lcd.setTextColor(theme().fg, bgColor());
    lcd.setTextSize(2);
    lcd.setCursor(0, 60);
    lcd.print("Coming in a later build");
    lcd.setTextColor(theme().accent, bgColor());
    lcd.setCursor(0, 220);
    lcd.print("q: back");
}

static void drawSpectrum()
{
    lcd.fillScreen(bgColor());
    drawHeader("Spectrum 902-928 MHz");
    if (!specScanned) {
        lcd.setTextColor(theme().fg, bgColor());
        lcd.setTextSize(2);
        lcd.setCursor(0, 100);
        lcd.print("Press Enter to scan");
    } else {
        for (int i = 0; i < kSpecPoints; i++) {
            float level = constrain(specDb[i], -120.0f, -50.0f);
            int h = static_cast<int>((level + 120.0f) / 70.0f * 170.0f);
            int x = 4 + i * 6;
            lcd.fillRect(x, 220 - h, 5, h, theme().accent);
        }
    }
    lcd.setTextColor(theme().accent, bgColor());
    lcd.setTextSize(1);
    lcd.setCursor(0, 226);
    lcd.print("Enter: scan   q: back");
}

static void drawSignal()
{
    lcd.fillScreen(bgColor());
    drawHeader("Signal");
    lcd.drawLine(0, 30, 319, 30, theme().fg);
    lcd.drawLine(0, 220, 319, 220, theme().fg);
    for (size_t i = 1; i < rssiHist.size(); i++) {
        auto yOf = [](float r) {
            float v = constrain(r, -130.0f, -40.0f);
            return static_cast<int>(220 - (v + 130.0f) / 90.0f * 190.0f);
        };
        int x0 = static_cast<int>((i - 1) * 5), x1 = static_cast<int>(i * 5);
        lcd.drawLine(x0, yOf(rssiHist[i - 1]), x1, yOf(rssiHist[i]), theme().accent);
    }
    lcd.setTextColor(theme().fg, bgColor());
    lcd.setTextSize(1);
    lcd.setCursor(0, 226);
    char line[48];
    float last = rssiHist.empty() ? 0 : rssiHist.back();
    snprintf(line, sizeof(line), "last RSSI %.0f dBm  SNR %.1f dB  q: back", last, lastSnr);
    lcd.print(line);
}

static void drawContacts()
{
    lcd.fillScreen(bgColor());
    drawHeader("Contacts");
    lcd.setTextColor(theme().fg, bgColor());
    lcd.setTextSize(2);
    lcd.setCursor(0, 60);
    lcd.print("Encrypted contacts");
    lcd.setCursor(0, 84);
    lcd.print("come next, after the");
    lcd.setCursor(0, 108);
    lcd.print("two-device test.");
    lcd.setTextColor(theme().accent, bgColor());
    lcd.setCursor(0, 220);
    lcd.print("q: back");
}

static void drawScreen()
{
    switch (screen) {
    case Screen::Spectrum: drawSpectrum(); break;
    case Screen::Signal: drawSignal(); break;
    case Screen::Soon: drawContacts(); break;
    case Screen::Home: drawHome(); break;
    case Screen::Public: drawPublic(); break;
    case Screen::Nodes: drawNodes(); break;
    case Screen::Settings: drawSettings(); break;
    }
}

static void goHome()
{
    screen = Screen::Home;
}

static void openTile(int i)
{
    switch (i) {
    case 0: screen = Screen::Public; break;
    case 2: screen = Screen::Nodes; break;
    case 5: screen = Screen::Settings; settingsSel = 0; break;
    case 3:
        screen = Screen::Spectrum;
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

static void activateSetting(int i)
{
    switch (i) {
    case 0: themeIndex = (themeIndex + 1) % kThemeCount; break;
    case 1: bgIndex = (bgIndex + 1) % kBackgroundCount; break;
    case 2: toggleWifi(); break;
    case 3: toggleBt(); break;
    case 4: toggleGps(); break;
    default: goHome(); break;
    }
}

static void activateWidget(int i)
{
    if (i == 0) toggleWifi();
    else if (i == 1) toggleBt();
    else toggleGps();
}

static void handleKey(int c)
{
    Serial.printf("key 0x%02X\n", c);
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
    } else if (screen == Screen::Settings) {
        if (c == 'w') settingsSel = (settingsSel + kSettingsCount - 1) % kSettingsCount;
        else if (c == 's') settingsSel = (settingsSel + 1) % kSettingsCount;
        else if (c == '\r' || c == '\n') activateSetting(settingsSel);
        else if (c == 'q' || c == 8 || c == 127) goHome();
    } else if (screen == Screen::Spectrum && (c == 'r' || c == '\r' || c == '\n')) {
        sweepSpectrum();
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
    {3, 'w', true, 0},   // up
    {15, 's', true, 0},  // down
    {1, 'a', true, 0},   // left
    {2, 'd', true, 0},   // right
    {0, 13, true, 0},    // center press (BOOT), acts as Enter
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
        if (!high && t.lastHigh && now - t.lastMs > 150) {
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

static void handleTouchTap(uint16_t x, uint16_t y)
{
    // Touch is in portrait (240 wide, 320 tall). The landscape screen is that rotated 90 degrees clockwise.
    int sx = constrain(319 - static_cast<int>(y), 0, 319);
    int sy = constrain(static_cast<int>(x), 0, 239);
    Serial.printf("tap screen x=%d y=%d\n", sx, sy);
    if (screen == Screen::Home) {
        if (sy >= 30 && sy < 130 && sx >= 162) {
            int w = constrain((sx - 162) / 51, 0, 2);
            homeSel = kWidgetFirst + w;
            activateWidget(w);
        } else if (sy >= 140 && sy < 194) {
            int idx = constrain(sx / 53, 0, kTileCount - 1);
            homeSel = idx;
            openTile(idx);
        }
    } else if (screen == Screen::Settings) {
        if (sy >= 40 && sy < 40 + kSettingsCount * 30) {
            int i = constrain((sy - 40) / 30, 0, kSettingsCount - 1);
            settingsSel = i;
            activateSetting(i);
        } else if (sy < 18) {
            goHome();
        }
    } else if (screen == Screen::Spectrum && sy >= 18) {
        sweepSpectrum();
    } else if (sy < 18) {
        goHome();
    }
    drawScreen();
}

static void pollTouch()
{
    static bool wasDown = false;
    static uint32_t last = 0;
    if (!gt911Addr) return;
    if (millis() - last < 30) return;
    last = millis();
    uint8_t status = 0;
    if (!gt911Read(0x814E, &status, 1)) return;
    if (!(status & 0x80)) return;
    uint8_t points = status & 0x0F;
    if (points > 0) {
        uint8_t p[8];
        if (gt911Read(0x8150, p, 8) && !wasDown) {
            // Measured layout: X low/high at bytes 0-1, Y low/high at bytes 2-3, size at byte 4.
            uint16_t x = p[0] | (p[1] << 8);
            uint16_t y = p[2] | (p[3] << 8);
            Serial.printf("touch bytes %02X %02X %02X %02X %02X %02X %02X %02X\n", p[0], p[1], p[2], p[3],
                          p[4], p[5], p[6], p[7]);
            Serial.printf("touch raw x=%u y=%u\n", x, y);
            handleTouchTap(x, y);
        }
        wasDown = true;
    } else {
        wasDown = false;
    }
    gt911Write(0x814E, 0);
}
#endif

void setup()
{
    Serial.begin(115200);
    delay(1500);
    Serial.println("meshport chat");

    // T-Deck peripheral power (LoRa radio). Must be HIGH before the radio responds.
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
    s.powerDbm = 10;   // lower TX power reduces current spikes on weak supplies
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
    loraFreqMHz = freq;
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
#endif

    if (driver->poll(rx, rssi, snr)) {
#ifdef MESHPORT_TDECK_SCREEN
        if (rx.size() >= 16) {
            Header seen = unpackHeader(rx.data());
            if (seen.from != myNode) {
                noteNode(seen.from, rssi);
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
        uint32_t from = 0;
        std::string text;
        if (openDirectFrame(kChannelKey, sizeof(kChannelKey), me, rx.data(), rx.size(), guard, from, text)) {
            Serial.printf("[%08lX] %s  (rssi %.0f)\n", (unsigned long)from, text.c_str(), rssi);
        } else {
            Header h{};
            Data d;
            if (openFrame(kChannelKey, sizeof(kChannelKey), rx.data(), rx.size(), h, d) &&
                d.portnum == kPortTextMessage && h.to == 0xFFFFFFFFu && h.from != myNode &&
                !seenPublic.checkAndInsert(h.from, h.id)) {
                std::string body(d.payload.begin(), d.payload.end());
                Serial.printf("[PUBLIC %08lX] %s  (rssi %.0f)\n", (unsigned long)h.from, body.c_str(), rssi);
#ifdef MESHPORT_TDECK_SCREEN
                char who[12];
                snprintf(who, sizeof(who), "%08lX", (unsigned long)h.from);
                addLine(String(who) + ": " + String(body.c_str()));
                drawScreen();
#endif
            }
        }
        // Frames that are not direct messages for this device (other traffic) are ignored.
    }
}
