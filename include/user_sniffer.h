#ifndef _USER_SNIFFER_H
#define _USER_SNIFFER_H

#define SNAP_LEN  2324

#include <c_types.h>

#include "user_config.h"

// Expressif Structures -------

// Metadata Packet
struct rx_control_pkt {
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

    // Hacked from ESP32 SDK
    // unsigned:12;                 // dropped
    unsigned secondary_channel:4;   // secondary channel on which this packet is received. 0: none; 1: above; 2: below
    unsigned :8;
    unsigned timestamp:32;          // timestamp. The local time when this packet is received. It is precise only if modem sleep or light sleep is not enabled. unit: microsecond
    unsigned :32;
    unsigned :31;
    unsigned ant:1;                 // antenna number from which this packet is received. 0: WiFi antenna 0; 1: WiFi antenna 1
    unsigned sig_len:12;            // length of packet including Frame Check Sequence(FCS)
    unsigned :12;
    unsigned rx_state:8;            // state of the packet. 0: no error; others: error numbers which
};

struct lenseq_pkt {
    uint16_t length;                // length of packet
    uint16_t seq;                   // serial number of packet, the high 12bits are serial
                                    // low 14 bits are Fragment number (usually be 0)
    uint8_t  address3[6];           // the third address in packet
};

// Data Packet (Expressif calls it "sniffer_buf")
struct sniffer_data_pkt {
    struct rx_control_pkt rx_ctrl;
    uint8_t buf[36];                // head of ieee80211 packet
    uint16_t cnt;                   // number count of packet
    struct lenseq_pkt lenseq[1];    // length of packet
};

// Management Packet (Expressif calls it "sniffer_buf2")
struct sniffer_mgmt_pkt {
    struct rx_control_pkt rx_ctrl;
    uint8_t buf[112];
    uint16_t cnt;
    uint16_t len;                   // length of packet
};

// Abstract Sniffer Packet (Management or Data)
struct sniffer_pkt {
    struct rx_control_pkt rx_ctrl;  // metadata header
    uint8_t payload[0];             // Data or management payload. Length of payload is described by rx_ctrl.sig_len.
                                    // Type of content determined by packet type argument of callback.
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
    NU1,                    /* ......................*/
    NU2,                    /* 0110, 0111 not used */
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

// 802.11 Beacon
struct beacon_info {
  unsigned interval:16;
  unsigned capability:16;
  unsigned tag_number:8;
  unsigned tag_length:8;
  char ssid[0];
  uint8 rates[1];
};

// 802.11 Header
struct ieee80211_hdr {
	struct frame_control_info frame_control;
	// uint16_t duration_id;        // dropped (hacked)
	uint8_t addr1[ETH_MAC_LEN];
	uint8_t addr2[ETH_MAC_LEN];
	uint8_t addr3[ETH_MAC_LEN];
	uint16_t seq_ctrl;
    uint8_t addr4[ETH_MAC_LEN];     // optional
};

// 802.11 Packet
struct ieee80211_pkt {
    struct ieee80211_hdr hdr;
    uint8_t payload[2];             // network data ended with 4 bytes csum (CRC32)
};


// Other Structures -------

// Router info
struct router_info {
    SLIST_ENTRY(router_info) next;
    uint8_t bssid[6];
    uint8_t channel;
    uint8_t authmode;
    uint16_t rx_seq;
    uint8_t encrytion_mode;
    uint8_t iv[8];
    uint8_t iv_check;
};

void user_sniffer_init(void);

#endif