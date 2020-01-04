#include <c_types.h>
#include <mem.h>
#include <ets_sys.h>
#include <osapi.h>
#include <user_interface.h>

#include "user_config.h"
#include "user_pcap.h"
#include "user_time.h"

/**
 * See:
 * https://wiki.wireshark.org/Development/LibpcapFileFormat
 * https://www.tcpdump.org/linktypes.html
 */

// Features
static const pcap_file_hdr_t file_header = { 0xa1b2c3d4, 2, 4, 0, 0, sizeof(int), 105 }; // 105 = IEEE 802.11 packet

/******************************************************************************
 * Send PCAP file header
 *******************************************************************************/
void ICACHE_FLASH_ATTR
tx_file_header(coid)
{
    uart0_tx_buffer((char*)&file_header, sizeof(file_header));
}

/******************************************************************************
 * Send PCAP record header
 *******************************************************************************/
void ICACHE_FLASH_ATTR
tx_record_header(uint8_t *pkt, uint16_t pkt_len){
    pcap_rec_hdr_t record_header;

    record_header.ts_sec = millis() / 1000;
    record_header.ts_usec = micros_64();
    record_header.incl_len = (uint32_t) pkt_len;
    record_header.orig_len = (uint32_t) pkt_len;

    uart0_tx_buffer((char*)&record_header, sizeof(record_header));
}

/******************************************************************************
 * Initialize PCAP transmission
 *******************************************************************************/
void ICACHE_FLASH_ATTR
user_pcap_init(void)
{
    // Sinalize start to SerialShark.py
    uart0_tx_buffer("\n", 1);
    uart0_tx_buffer("<pcap_pipe>", os_strlen("<pcap_pipe>"));
    uart0_tx_buffer("\n", 1);

    // File header
    tx_file_header();
}

/******************************************************************************
 * Serialize packet as PCAP record
 *******************************************************************************/
void ICACHE_FLASH_ATTR
user_pcap_record(uint8_t *pkt, uint16_t pkt_len)
{
    // Record header
    tx_record_header(pkt, pkt_len);

    // Record Data
    uart0_tx_buffer(pkt, pkt_len);
}