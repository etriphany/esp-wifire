#include <c_types.h>
#include <mem.h>
#include <ets_sys.h>
#include <osapi.h>
#include <user_interface.h>
#include <queue.h>


#ifdef PRINTER_MODE
#include "user_printer.h"
#else
#include "user_pcap.h"
#endif
#include "user_sniffer.h"
#include "user_network.h"
#include "user_config.h"

/**
 * Sniffing foundations from:
 *
 * https://github.com/n0w/esp8266-simple-sniffer
 * https://github.com/SmingHub/Sming
 * https://github.com/espressif/esp8266-rtos-sample-code/tree/master/03Wifi/Sniffer_DEMO
 */

// Features
const uint8_t cli_broadcast1[3] = {0x01, 0x00, 0x5e};
const uint8_t cli_broadcast2[6] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff};
const uint8_t cli_broadcast3[3] = {0x33, 0x33, 0x00};
static bool started = FALSE;
static uint32_t ts_channel = 0;
static uint32_t ts_routers = 0;
static struct channel_data chdata = {};
SLIST_HEAD(router_info_head, router_info) router_list;

// Definitions
void user_promiscuous_rx_cb(uint8_t *buf, uint16_t buf_len);
void user_station_scan_done_cb(void *arg, STATUS status);
void set_wifi_channel(uint8_t channel);
uint8_t pick_valid_channel(void);

/******************************************************************************
 * Parse beacon packet
 *******************************************************************************/
struct beacon_info ICACHE_FLASH_ATTR
parse_beacon_packet(uint8_t* buf, uint16_t buf_len)
{
    // Prepare beacon
    struct beacon_info beacon;
    beacon.ssid_len = 0;
    beacon.channel = 0;
    beacon.err = 0;
    int pos = 36;

    // Parse packet
    if(buf[pos] == 0x00)
    {
        while(pos < buf_len)
        {
            switch(buf[pos])
            {
                case 0x00:  //SSID
                    beacon.ssid_len = (int)buf[pos + 1];
                    if(beacon.ssid_len == 0)
                    {
                        os_memset(beacon.ssid, 0, MAX_SSID_LEN + 1);
                        break;
                    }

                    // Errors
                    if(beacon.ssid_len < 0)
                    {
                        beacon.err = -1;
                        break;
                    }
                    if(beacon.ssid_len > MAX_SSID_LEN)
                    {
                        beacon.err = -2;
                        break;
                    }

                    // Copy
                    os_memset(beacon.ssid, 0, MAX_SSID_LEN + 1);
                    os_memcpy(beacon.ssid, buf + pos + 2, beacon.ssid_len);
                    beacon.err = 0;
                    break;

                case 0x03: //Channel
                    beacon.channel = (int)buf[pos + 2];
                    pos = -1;
                    break;
                default:
                    break;
            }

            // Loop control
            if(pos < 0)
                break;
            pos += (int)buf[pos + 1] + 2;
        }
    }
    else
    {
        // Error
        beacon.err = -3;
    }

    beacon.capa[0] = buf[34];
    beacon.capa[1] = buf[35];
    os_memcpy(beacon.bssid, buf + 10, MAC_ADDR_LEN);

    return beacon;
}

/******************************************************************************
 * Parse client packet
 *******************************************************************************/
struct client_info ICACHE_FLASH_ATTR
parse_data_packet(uint8_t* buf, uint16_t buf_len, int rssi, uint8_t channel)
{
    // Prepare client
    struct client_info client;
	client.err = 0;
	client.channel = channel;
	client.rssi = rssi;

    // Parse packet
	uint8_t* bssid;
	uint8_t* station;
	uint8_t* ap;
	uint8_t ds = buf[1] & 3;
	switch(ds) {
	// p[1] - xxxx xx00 => NoDS   p[4]-DST p[10]-SRC p[16]-BSS
	case 0:
		bssid = buf + 16;
		station = buf + 10;
		ap = buf + 4;
		break;
	// p[1] - xxxx xx01 => ToDS   p[4]-BSS p[10]-SRC p[16]-DST
	case 1:
		bssid = buf + 4;
		station = buf + 10;
		ap = buf + 16;
		break;
	// p[1] - xxxx xx10 => FromDS p[4]-DST p[10]-BSS p[16]-SRC
	case 2:
		bssid = buf + 10;
		// hack - don't know why it works like this...
		if(os_memcmp(buf + 4, cli_broadcast1, 3) || os_memcmp(buf + 4, cli_broadcast2, 3) || os_memcmp(buf + 4, cli_broadcast3, 3)) {
			station = buf + 16;
			ap = buf + 4;
		} else {
			station = buf + 4;
			ap = buf + 16;
		}
		break;
	// p[1] - xxxx xx11 => WDS    p[4]-RCV p[10]-TRM p[16]-DST p[26]-SRC
	case 3:
	default:
		bssid = buf + 10;
		station = buf + 4;
		ap = buf + 4;
		break;
	}

	os_memcpy(client.station, station, MAC_ADDR_LEN);
	os_memcpy(client.bssid, bssid, MAC_ADDR_LEN);
	os_memcpy(client.ap, ap, MAC_ADDR_LEN);

	client.seq_n = (buf[23] * 0xFF) + (buf[22] & 0xF0);
    return client;
}

/******************************************************************************
 * Start sniffer loop
 *******************************************************************************/
void ICACHE_FLASH_ATTR
sniff(void)
{
    if(!started)
    {
        #ifdef PRINTER_MODE
        // Headers
        user_print_headers();
        #else
        // Initialize PCAP transmission
        user_pcap_init();
        #endif
    }

    // Pick valid channel
    pick_valid_channel();

    // Enable promiscuous mode
    wifi_promiscuous_enable(0);
    wifi_set_promiscuous_rx_cb(user_promiscuous_rx_cb);
    wifi_promiscuous_enable(1);

    // Post event
    if(!started)
        system_os_post(USER_TASK_PRIO_0, SIG_SNIFFER_UP, chdata.current);
    else
        system_os_post(USER_TASK_PRIO_0, SIG_CHANNEL, chdata.current);
}

/******************************************************************************
 * Pick valid channel
 *******************************************************************************/
uint8_t ICACHE_FLASH_ATTR
pick_valid_channel(void)
{
    uint8_t i;
    for (i = chdata.lookup; i < MAX_CHANNEL; i++)
    {
        // Matches detection result
        if ((chdata.bits & (1 << i)) != 0)
        {
            // Change channel
            chdata.lookup = i + 1;
            set_wifi_channel(i);
            os_printf("\n | \n | Channel Shift %d", i);
            break;
        }
    }
    return i;
}

/******************************************************************************
 * Start sniffer loop
 *******************************************************************************/
void ICACHE_FLASH_ATTR
scan_routers(void)
{
    // Turn off promiscuous mode
    wifi_promiscuous_enable(0);

    // Scan routers
    struct scan_config config = {};
    config.show_hidden = 1;
    wifi_station_scan(&config, user_station_scan_done_cb);
}

/******************************************************************************
 * Change current channel
 *******************************************************************************/
void ICACHE_FLASH_ATTR
set_wifi_channel(uint8_t channel)
{
    if ((channel != chdata.current) && (channel > 0) && (channel < MAX_CHANNEL + 1))
    {
        // Change channel
        chdata.current = channel;
        wifi_set_channel(chdata.current);

        // Post event
        system_os_post(USER_TASK_PRIO_0, SIG_CHANNEL, chdata.current);
    }
}

/******************************************************************************
 * Promiscuous callback
 *
 * SDK restrictions:
 *     Mangement packets 128 bytes
 *     Data packets 60 bytes
 *******************************************************************************/
void ICACHE_FLASH_ATTR
user_promiscuous_rx_cb(uint8_t *buf, uint16_t buf_len)
{
    // Generic
    const struct sniffer_pkt *pkt = (struct sniffer_pkt *)buf;

    // 802.11
    const struct ieee80211_pkt *iee_pkt = (struct ieee80211_pkt *)pkt->payload;
    const struct ieee80211_hdr *hdr = &iee_pkt->hdr;
    const struct frame_control_info *frame_ctrl = (struct frame_control_info *)&hdr->frame_control;

    #ifdef PRINTER_MODE
    // Print details
    user_print_packet(buf, buf_len, chdata.current);
    #else
    // Pcap record
    user_pcap_record(buf, buf_len);
    #endif

    if (frame_ctrl->type == PKT_MGMT && frame_ctrl->subtype == BEACON)
    {
        // Parse beacon only to print
        #ifdef PRINTER_MODE
        struct sniffer_mgmt_pkt *mgnt_pkt = (struct sniffer_mgmt_pkt *)buf;
        struct beacon_info beacon = parse_beacon_packet(mgnt_pkt->buf, 112);
        user_print_beacon(&beacon);
        #endif
    }
    else if (frame_ctrl->type == PKT_DATA)
    {
        // Parse client
        struct sniffer_data_pkt *data_pkt = (struct sniffer_data_pkt *)buf;
        struct client_info client = parse_data_packet(data_pkt->buf, 36, pkt->rx_ctrl.rssi, pkt->rx_ctrl.channel);

        // Attack

        #ifdef PRINTER_MODE
        user_print_client(&client);
        #endif
    }
}

/******************************************************************************
 * Station scan callback
 *******************************************************************************/
void ICACHE_FLASH_ATTR
user_station_scan_done_cb(void *arg, STATUS status)
{
    uint8_t ssid[MAX_SSID_LEN];
    struct router_info *info = NULL;

    // Reset state
    chdata.bits = 0;
    chdata.lookup = 0;
    chdata.current = 1;

    // Clear router list (free memory)
    while ((info = SLIST_FIRST(&router_list)) != NULL)
    {
        SLIST_REMOVE_HEAD(&router_list, next);
        os_free(info);
    }

    // Feed router list
    if (status == OK)
    {
        os_printf("\nStation Scan Success [status = %d]", status);
        uint8_t i;
        struct bss_info *bss = (struct bss_info *) arg;
        while (bss != NULL)
        {
            if (bss->channel != 0)
            {
                os_printf("\n Info >>> SSID[%s], Channel[%d], RSSI[%d], Authmode[%d]", bss->ssid, bss->channel, bss->rssi, bss->authmode);

                // Store channel as bitmask (sniffer works per channel)
                chdata.bits |= 1 << (bss->channel);

                // Save station info
                struct router_info *info = NULL;
                info = (struct router_info *) os_malloc(sizeof(struct router_info));
                info->authmode = bss->authmode;
                info->channel = bss->channel;
                os_memcpy(info->bssid, bss->bssid, 6);
                SLIST_INSERT_HEAD(&router_list, info, next);
            }

            // Next result entry
            bss = STAILQ_NEXT(bss, next);
        }

        // Start/Re-start sniffing
        sniff();
    }
    else
    {
        os_printf("Station Scan Failed [status = %d] \r\n\n", status);
    }
}

/******************************************************************************
 * Sniffer update
 *******************************************************************************/
void ICACHE_FLASH_ATTR
user_sniffer_update(const uint32_t millis)
{

    if((millis - ts_routers)  >= ROUTERS_UPDATE_DELAY)
    {
        // Track update time
        ts_routers = millis;
        scan_routers();
    }

    if((millis - ts_channel)  >= CHANNEL_CHANGE_DELAY)
    {
        // Track update time
        ts_channel = millis;

        // Update channel
        uint8_t picked = pick_valid_channel();

        // Reset when reaches last possible channel
        if (picked == MAX_CHANNEL) {
            chdata.lookup = 1;
            pick_valid_channel();
        }
    }
}

/******************************************************************************
 * Start sniffer
 *******************************************************************************/
void ICACHE_FLASH_ATTR
user_sniffer_init(void)
{
    #ifndef PRINTER_MODE
    // Turn off prints
    system_set_os_print(0);
    #endif

   // Scan routers
   SLIST_INIT(&router_list);
   scan_routers();
}