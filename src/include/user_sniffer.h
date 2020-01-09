#ifndef _USER_SNIFFER_H
#define _USER_SNIFFER_H

#include <queue.h>

#include "user_config.h"

/**
 * Sniffing foundations from:
 *
 * https://github.com/n0w/esp8266-simple-sniffer
 * https://github.com/SmingHub/Sming
 * https://github.com/espressif/esp8266-rtos-sample-code/tree/master/03Wifi/Sniffer_DEMO
 */

// Espressif Structures -------

struct lenseq {
    uint16_t length;                // length of packet
    uint16_t seq;                   // serial number of packet, the high 12bits are serial
                                    // low 14 bits are Fragment number (usually be 0)
    uint8_t address3[MAC_ADDR_LEN]; // the third address in packet
};

// Metadata Packet
struct rx_control {
    signed rssi:8;                  // signal intensity of packet
    unsigned rate:4;
    unsigned is_group:1;
    unsigned :1;
    unsigned sig_mode:2;            // if 0: is not 11n packet; if non-0: is 11n packet
    unsigned legacy_length:12;      // if not 11n packet, shows length of packet
    unsigned damatch0:1;
    unsigned damatch1:1;
    unsigned bssidmatch0:1;
    unsigned bssidmatch1:1;
    unsigned mcs:7;                 // if is 11n packet, shows the modulation and code used (range from 0 to 76)
    unsigned cwb:1;                 // if is 11n packet, shows if is HT40 packet
    unsigned ht_length:16;          // if is 11n packet, shows length of packet
    unsigned smoothing:1;
    unsigned not_sounding:1;
    unsigned :1;
    unsigned aggregation:1;
    unsigned stbc:2;
    unsigned fec_coding:1;          // if is 11n packet, shows if is LDPC
    unsigned sgi:1;
    unsigned rxend_state:8;
    unsigned ampdu_cnt:8;
    unsigned channel:4;             // which channel this packet in
    unsigned:12;
};

// Data Packet (Espressif "sniffer_buf")
struct sniffer_data_pkt {
    struct rx_control rx_ctrl;
    uint8_t buf[36];                // head of ieee80211 packet
    uint16_t cnt;                   // number count of packet
    struct lenseq lenseq[1];        // length of packet
};

// Management Packet (Espressif "sniffer_buf2")
struct sniffer_mgmt_pkt {
    struct rx_control rx_ctrl;
    uint8_t buf[112];
    uint16_t cnt;
    uint16_t len;                   // length of packet
};

// Abstract Sniffer Packet (Management or Data)
struct sniffer_pkt {
    struct rx_control rx_ctrl;      // metadata header
    uint8_t payload[0];             // Length of payload is described by rx_ctrl.sig_len (ESP32 only).
};

// 802.11 Structures -------

// Type of sniffer_pkt
typedef enum
{
    PKT_MGMT,
    PKT_CTRL,
    PKT_DATA,
    PKT_MISC,
} sniffer_pkt_t;

// Type of sniffer_mgmt_pkt
typedef enum
{
    ASSOCIATION_REQ,
    ASSOCIATION_RES,
    REASSOCIATION_REQ,
    REASSOCIATION_RES,
    PROBE_REQ,
    PROBE_RES,
    NU1,
    NU2,
    BEACON,
    ATIM,
    DISASSOCIATION,
    AUTHENTICATION,
    DEAUTHENTICATION,
    ACTION,
    ACTION_NACK,
} sniffer_mgmt_pkt_t;

// 802.11 Frame Control
struct frame_control_info {
    unsigned protocol:2;
    unsigned type:2;
    unsigned subtype:4;
    unsigned to_ds:1;
    unsigned from_ds:1;
    unsigned more_frag:1;
    unsigned retry:1;
    unsigned pwr_mgmt:1;
    unsigned more_data:1;
    unsigned wep:1;
    unsigned strict:1;
};

// 802.11 Header
struct ieee80211_hdr {
    struct frame_control_info frame_control;
    uint16_t duration_id;
    uint8_t addr1[MAC_ADDR_LEN];
    uint8_t addr2[MAC_ADDR_LEN];
    uint8_t addr3[MAC_ADDR_LEN];
    uint16_t seq_ctrl;
    uint8_t addr4[MAC_ADDR_LEN];     // optional
};

// 802.11 Packet
struct ieee80211_pkt {
    struct ieee80211_hdr hdr;
    uint8_t payload[2];             // network data ended with 4 bytes csum (CRC32)
};


// Other Structures -------

struct beacon_info {
	uint8_t bssid[MAC_ADDR_LEN];
	uint8_t ssid[MAX_SSID_LEN + 1];
	uint8_t ssid_len;
	uint8_t channel;
	int8_t err;
	int8_t rssi;
	uint8_t capa[2];
};

struct client_info {
	uint8_t bssid[MAC_ADDR_LEN];
	uint8_t station[MAC_ADDR_LEN];
	uint8_t ap[MAC_ADDR_LEN];
	uint8_t channel;
	int8_t err;
	int8_t rssi;
	uint16_t seq_n;
};

struct router_info {
    SLIST_ENTRY(router_info) next;
    uint8_t bssid[MAC_ADDR_LEN];
    uint8_t channel;
    uint8_t authmode;
    uint16_t rx_seq;
    uint8_t encrytion_mode;
    uint8_t iv[8];
    uint8_t iv_check;
};

struct channel_data {
    uint8_t lookup;
    uint8_t current;
    uint16_t bits;
};

void user_sniffer_update(const uint32_t millis);
void user_sniffer_init(void);

#endif