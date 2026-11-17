// LovyanGFX display driver for the LILYGO T-Deck (ST7789, 320x240 landscape).
// Pins from the LILYGO T-Deck documentation: SCK 40, MOSI 41, DC 11, CS 12.
#pragma once

#include <LovyanGFX.hpp>

class LGFX_TDeck : public lgfx::LGFX_Device {
public:
    LGFX_TDeck()
    {
        {
            auto cfg = bus_.config();
            cfg.spi_host = SPI3_HOST;
            cfg.spi_mode = 0;
            cfg.freq_write = 40000000;
            cfg.freq_read = 16000000;
            cfg.spi_3wire = false;
            cfg.use_lock = true;
            cfg.dma_channel = SPI_DMA_CH_AUTO;
            cfg.pin_sclk = 40;
            cfg.pin_mosi = 41;
            cfg.pin_miso = -1;
            cfg.pin_dc = 11;
            bus_.config(cfg);
            panel_.setBus(&bus_);
        }
        {
            auto cfg = panel_.config();
            cfg.pin_cs = 12;
            cfg.pin_rst = -1;
            cfg.pin_busy = -1;
            cfg.panel_width = 240;
            cfg.panel_height = 320;
            cfg.memory_width = 240;
            cfg.memory_height = 320;
            // Measured on device: the right-side labels stop about 5 mm (~28 px) short of the edge.
            cfg.offset_x = 0;
            cfg.offset_y = 0;
            cfg.readable = false;
            cfg.invert = true;
            cfg.rgb_order = false;
            cfg.bus_shared = true;
            panel_.config(cfg);
        }
        setPanel(&panel_);
    }

private:
    lgfx::Bus_SPI bus_;
    lgfx::Panel_ST7789 panel_;
};
