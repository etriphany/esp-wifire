#ifndef _USER_PCAP_H
#define _USER_PCAP_H

/**
 * See:
 * https://wiki.wireshark.org/Development/LibpcapFileFormat
 * https://www.tcpdump.org/linktypes.html
 */

typedef struct {
    uint32_t magic_number;   // magic number
    uint16_t version_major;  // major version number
    uint16_t version_minor;  // minor version number
    int32_t  thiszone;       // GMT to local correction
    uint32_t sigfigs;        // accuracy of timestamps
    uint32_t snaplen;        // max length of captured packets, in octets
    uint32_t network;        // data link type
} pcap_file_hdr_t;

typedef struct {
    uint32_t ts_sec;         // timestamp seconds
    uint32_t ts_usec;        // timestamp microseconds
    uint32_t incl_len;       // number of octets of packet saved in file
    uint32_t orig_len;       // actual length of packet
} pcap_rec_hdr_t;

void user_pcap_init(void);
void user_pcap_record(uint8_t *pkt, uint16_t pkt_len);

#endif