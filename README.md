# meshport

Secure LoRa messaging firmware for the LILYGO T-Deck (ESP32-S3, SX1262).

Meshtastic-compatible: the radio layer uses the Meshtastic LongFast settings and the
Meshtastic packet format, so it talks to standard Meshtastic nodes on the default channel.

## Status

- Radio: send and receive verified on T-Deck hardware (LongFast, 906.875 MHz on US).
- Packet header, channel hash, AES-CTR channel encryption, protobuf Data codec: host-tested.
- Next: secure end-to-end messaging layer, node list, and UI.

## Layout

- `src/meshport/` protocol and radio code (Meshtastic wire format, crypto, frames, radio driver)
- `src/meshport/radio_test/` on-device radio test
- `tests/host/` host tests (no hardware needed)

## Host tests

The AES tests use OpenSSL as the block cipher on the host:

    cd tests/host
    g++ -std=c++17 -Wall -Wextra -fsanitize=address,undefined -I ../../src/meshport \
      test_meshtastic_crypto.cpp ../../src/meshport/MeshtasticCrypto.cpp \
      ../../src/meshport/MeshtasticWire.cpp openssl_aes_backend.cpp -lcrypto -o t && ./t

## Safety

Attach an antenna before transmitting. Transmitting without one can damage the radio.

## License

GPL-3.0. See LICENSE.
