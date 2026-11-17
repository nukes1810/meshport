#ifdef MESHPORT_RADIO_ENABLED

#include "MeshtasticRadio.h"

namespace meshport {

volatile bool MeshtasticRadio::rxFlag_ = false;

MeshtasticRadio::MeshtasticRadio(SX1262 &radio) : radio_(radio) {}

void MeshtasticRadio::onDio1()
{
    rxFlag_ = true;
}

bool MeshtasticRadio::begin(const RadioSettings &s)
{
    int16_t st = radio_.begin(s.freqMHz, s.bwKHz, s.sf, s.cr, s.syncWord, s.powerDbm, s.preambleLen,
                              s.tcxoVoltage, s.useLdo);
    lastBeginError_ = st;
    if (st != RADIOLIB_ERR_NONE) {
        return false;
    }
    // Settings verified on T-Deck hardware: no DIO2 RF switch,
    // 140 mA current limit, boosted RX gain.
    radio_.setCurrentLimit(140);
#ifndef MESHPORT_DIO2_RF_SWITCH
#define MESHPORT_DIO2_RF_SWITCH 0
#endif
    radio_.setDio2AsRfSwitch(MESHPORT_DIO2_RF_SWITCH != 0);
    radio_.setRxBoostedGainMode(true);
    radio_.setDio1Action(onDio1);
    return startReceive();
}

bool MeshtasticRadio::send(const std::vector<uint8_t> &frame)
{
    if (frame.empty() || frame.size() > 255) {
        return false;
    }
    radio_.clearDio1Action();
    int16_t st = radio_.transmit(frame.data(), frame.size());
    lastTxError_ = st;
    radio_.setDio1Action(onDio1);
    // Always return to receive, even after a failed transmit, so the radio never stays deaf.
    bool rxOk = startReceive();
    return st == RADIOLIB_ERR_NONE && rxOk;
}

bool MeshtasticRadio::startReceive()
{
    rxFlag_ = false;
    return radio_.startReceive() == RADIOLIB_ERR_NONE;
}

bool MeshtasticRadio::poll(std::vector<uint8_t> &frame, float &rssiDbm, float &snrDb)
{
    if (!rxFlag_) {
        return false;
    }
    rxFlag_ = false;
    size_t len = radio_.getPacketLength();
    frame.assign(len, 0);
    int16_t st = radio_.readData(frame.data(), len);
    rssiDbm = radio_.getRSSI();
    snrDb = radio_.getSNR();
    startReceive();
    return st == RADIOLIB_ERR_NONE;
}

} // namespace meshport

#endif // MESHPORT_RADIO_ENABLED
