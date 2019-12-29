#include <c_types.h>
#include <mem.h>
#include <ets_sys.h>
#include <osapi.h>
#include <user_interface.h>

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
static os_timer_t timer;
SLIST_HEAD(router_info_head, router_info) router_list;
uint16_t channel_bits;
static const uint8_t broadcast1[3] = {0x01, 0x00, 0x5e};
static const uint8_t broadcast2[6] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff};
static const uint8_t broadcast3[3] = {0x33, 0x33, 0x00};

/******************************************************************************
 * Print headers
 *******************************************************************************/
void ICACHE_FLASH_ATTR
print_headers()
{
    os_printf("\n|       M1        |        M2         |        M3         | Ch |   Rs  | Prt | Type  |              Desc              | Ts| Fs| Mf| Rt| Pm| Mr| Wp| Sc| ");
}

/******************************************************************************
 * Print MAC
 *******************************************************************************/
char* ICACHE_FLASH_ATTR
print_mac(const uint8_t* mac)
{
  char *buf = "00:00:00:00:00:00\0";
  os_sprintf(buf, "%02x:%02x:%02x:%02x:%02x:%02x", mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
  return buf;
}

/******************************************************************************
 * Print packet type
 *******************************************************************************/
const char* ICACHE_FLASH_ATTR
print_packet_type(sniffer_pkt_t type, sniffer_mgmt_pkt_t subtype)
{
  switch(type)
  {
    case PKT_MGMT:
      switch(subtype)
      {
        case ASSOCIATION_REQ:
            return "Mgmt: Association request";
         case ASSOCIATION_RES:
            return "Mgmt: Association response";
         case REASSOCIATION_REQ:
            return "Mgmt: Reassociation request";
         case REASSOCIATION_RES:
             return "Mgmt: Reassociation response";
         case PROBE_REQ:
            return "Mgmt: Probe request";
         case PROBE_RES:
            return "Mgmt: Probe response";
         case BEACON:
            return "Mgmt: Beacon frame";
         case ATIM:
            return "Mgmt: ATIM";
         case DISASSOCIATION:
            return "Mgmt: Dissasociation";
         case AUTHENTICATION:
            return "Mgmt: Authentication";
         case DEAUTHENTICATION:
            return "Mgmt: Deauthentication";
         case ACTION:
            return "Mgmt: Action";
         case ACTION_NACK:
            return "Mgmt: Action no ack";
        default:
            return "Mgmt: Unsupported/Error";
      }

    case PKT_CTRL:
        return "Control";

    case PKT_DATA:
        return "Data";

    default:
      return "Unsupported/Error";
  }
}

#ifndef LEAN_MODE
/******************************************************************************
 * Parse beacon packet
 *******************************************************************************/
void ICACHE_FLASH_ATTR
parse_beacon_packet(struct beacon_info *beacon, uint8_t* buf, uint16_t buf_len)
{
    // Prepare beacon
    beacon->ssid_len = 0;
    beacon->channel = 0;
    beacon->err = 0;

    // Parse packet
    int pos = 36;
    if(buf[pos] == 0x00)
    {
        while(pos < buf_len)
        {
            switch(buf[pos])
            {
                case 0x00:  //SSID
                    beacon->ssid_len = (int)buf[pos + 1];
                    if(beacon->ssid_len == 0)
                    {
                        os_memset(beacon->ssid, 0, sizeof(beacon->ssid));
                        break;
                    }

                    // Errors
                    if(beacon->ssid_len < 0)
                    {
                        beacon->err = -1;
                        break;
                    }
                    if(beacon->ssid_len > 32)
                    {
                        beacon->err = -2;
                        break;
                    }

                    // Copy
                    os_memset(beacon->ssid, 0, sizeof(beacon->ssid));
                    os_memcpy(beacon->ssid, buf + pos + 2, beacon->ssid_len);
                    beacon->err = 0;
                    break;

                case 0x03: //Channel
                    beacon->channel = (int)buf[pos + 2];
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
        beacon->err = -3;
    }

    beacon->capa[0] = buf[34];
    beacon->capa[1] = buf[35];
    os_memcpy(beacon->bssid, buf + 10, MAC_ADDR_LEN);
}

/******************************************************************************
 * Parse client packet
 *******************************************************************************/
void ICACHE_FLASH_ATTR
parse_data_packet(struct client_info *client, uint8_t* buf, uint16_t buf_len, int rssi, uint8_t channel)
{
    // Prepare client
	client->err = 0;
	client->channel = channel;
	client->rssi = rssi;

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
		if(os_memcmp(buf + 4, broadcast1, 3) || os_memcmp(buf + 4, broadcast2, 3) || os_memcmp(buf + 4, broadcast3, 3)) {
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

	os_memcpy(client->station, station, MAC_ADDR_LEN);
	os_memcpy(client->bssid, bssid, MAC_ADDR_LEN);
	os_memcpy(client->ap, ap, MAC_ADDR_LEN);

	client->seq_n = (buf[23] * 0xFF) + (buf[22] & 0xF0);
}
#endif

/******************************************************************************
 * Channel change callback
 *
 * Callback not marked as ICACHE_FLASH_ATTR (loaded to iRam on boot)
 *******************************************************************************/
void ICACHE_FLASH_ATTR
user_channel_change_cb(void)
{
    uint8_t i;

    for (i = lookup_channel; i < 14; i++)
    {
        // Matches detection result
        if ((channel_bits & (1 << i)) != 0)
        {
            // Change channel
            lookup_channel = i + 1;
            user_set_wifi_channel(i);
            os_printf("\n\n Channel Shift %d", i);
            os_timer_arm(&timer, CHANNEL_CHANGE_DELAY, 0);
            break;
        }
    }

    // Reset when reaches last possible channel
    if (i == 14) {
        lookup_channel = 1;
        for(i = lookup_channel; i < 14; i++)
        {
            // Matches detection result
            if ((channel_bits & (1 << i)) != 0)
            {
                lookup_channel = i + 1;
                user_set_wifi_channel(i);
                os_printf("\n\n Channel Shift %d", i);
                os_timer_arm(&timer, CHANNEL_CHANGE_DELAY, 0);
                break;
            }
        }
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

    // Print metadata
    os_printf("\n%s | %s | %s | %u  |  %02d  |  %u  | %u(%-2u) |  %-28s  | %u | %u | %u | %u | %u | %u | %u | %u |",
        print_mac(hdr->addr1),
        print_mac(hdr->addr2),
        print_mac(hdr->addr3),
        current_channel,
        pkt->rx_ctrl.rssi,
        frame_ctrl->protocol,
        frame_ctrl->type,
        frame_ctrl->subtype,
        print_packet_type((sniffer_pkt_t)frame_ctrl->type, (sniffer_mgmt_pkt_t)frame_ctrl->subtype), // Desc
        frame_ctrl->to_ds,
        frame_ctrl->from_ds,
        frame_ctrl->more_frag,
        frame_ctrl->retry,
        frame_ctrl->pwr_mgmt,
        frame_ctrl->more_data,
        frame_ctrl->wep,
        frame_ctrl->strict
    );

    // Print details
    #ifndef LEAN_MODE
    if (frame_ctrl->type == PKT_MGMT && frame_ctrl->subtype == BEACON)
    {
        struct sniffer_mgmt_pkt *mgnt_pkt = (struct sniffer_mgmt_pkt *)buf;
        struct beacon_info *beacon_info = os_zalloc(sizeof(struct beacon_info));

        parse_beacon_packet(beacon_info, mgnt_pkt->buf, 112);
        os_printf("SSID [%d], BSSID [%s]",
            beacon_info->ssid,
            print_mac(beacon_info->bssid)
        );
    }
    else if (frame_ctrl->type == PKT_DATA)
    {
        struct sniffer_data_pkt *data_pkt = (struct sniffer_data_pkt *)buf;
        struct client_info *client_info = os_zalloc(sizeof(struct client_info));

        parse_data_packet(client_info, data_pkt->buf, 36, pkt->rx_ctrl.rssi, pkt->rx_ctrl.channel);
        os_printf("[BSSID] %s",
            print_mac(client_info->bssid)
        );
    }
    #endif

    // Serialize packet
    // user_serialize_packet(buf, buf_len);
}

/******************************************************************************
 * Serialize packet
 *******************************************************************************/
void ICACHE_FLASH_ATTR
user_serialize_packet(uint8_t *pkt, uint16_t pkt_len)
{
    // TODO: SD support
    uart0_tx_buffer(pkt, pkt_len);
}

/******************************************************************************
 * Start sniffer loop
 *******************************************************************************/
void ICACHE_FLASH_ATTR
user_sniff(void)
{
    // Enable promiscus mode
    wifi_set_channel(1);
    wifi_promiscuous_enable(0);
    wifi_set_promiscuous_rx_cb(user_promiscuous_rx_cb);
    wifi_promiscuous_enable(1);

    // Headers
    print_headers();

    // Configure channel change
    os_timer_disarm(&timer);
    os_timer_setfn(&timer, (os_timer_func_t *)user_channel_change_cb, NULL);
    os_timer_arm(&timer, CHANNEL_CHANGE_DELAY, 0);
}

/******************************************************************************
 * Station scan callback
 *******************************************************************************/
void ICACHE_FLASH_ATTR
user_station_scan_done_cb(void *arg, STATUS status)
{
    uint8_t ssid[33];
    struct router_info *info = NULL;

    // Reset state
    channel_bits = 0;
    current_channel = 1;

    // Clear router list
    while ((info = SLIST_FIRST(&router_list)) != NULL)
    {
        SLIST_REMOVE_HEAD(&router_list, next);
        os_free(info);
    }

    // Feed router list
    if (status == OK)
    {
        os_printf("Station Scan Success [status = %d] \r\n\n", status);
        uint8_t i;
        struct bss_info *bss = (struct bss_info *) arg;
        while (bss != NULL)
        {
            if (bss->channel != 0)
            {
                os_printf("SSID[%s], Channel[%d], Authmode[%d], RSSI[%d]\r\n\n", bss->ssid, bss->channel, bss->authmode, bss->rssi);

                // Store channel as bitmask (sniffer works per channel)
                channel_bits |= 1 << (bss->channel);

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

        // Sniff loop
        os_delay_us(60000);
        user_sniff();
    }
    else
    {
        os_printf("Station Scan Failed [status = %d] \r\n\n", status);
    }
}

/******************************************************************************
 * Start sniffer
 *******************************************************************************/
void ICACHE_FLASH_ATTR
user_sniffer_init(void)
{
    struct scan_config *config = NULL;

    // Init routers list
    SLIST_INIT(&router_list);
    // Scan routers
    wifi_station_scan(config, user_station_scan_done_cb);
}