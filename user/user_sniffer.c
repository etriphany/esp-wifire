#include <c_types.h>
#include <mem.h>
#include <ets_sys.h>
#include <osapi.h>
#include <user_interface.h>

#include "user_sniffer.h"
#include "user_network.h"
#include "user_config.h"

// Features
static os_timer_t timer;
SLIST_HEAD(router_info_head, router_info) router_list;
uint16_t channel_bits;

char* ICACHE_FLASH_ATTR
print_mac(const uint8_t* mac)
{
  char *buf = "00:00:00:00:00:00\0";
  os_sprintf(buf, "%02x:%02x:%02x:%02x:%02x:%02x", mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
  return buf;
}

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
            return "Mgmt: Unsupported/error";
      }

    case PKT_CTRL:
        return "Control";

    case PKT_DATA:
        return "Data";

    default:
      return "Unsupported/error";
  }
}

/******************************************************************************
 * Channel callback
 *
 * Callback not marked as ICACHE_FLASH_ATTR (loaded to iRam on boot)
 *******************************************************************************/
static void
user_channel_timer_cb(void)
{
    uint8_t i;

    for (i = lookup_channel; i < 14; i++)
    {
        if ((channel_bits & (1 << i)) != 0)
        {
            lookup_channel = i + 1;
            user_set_wifi_channel(i);
            os_printf("Current channel %d-----------------%d\n", i, system_get_time());
            os_timer_arm(&timer, 1000, 0);
            break;
        }
    }

    if (i == 14) {
        lookup_channel = 1;
        for(i = lookup_channel; i < 14; i++)
        {
            if ((channel_bits & (1 << i)) != 0)
            {
                lookup_channel = i + 1;
                user_set_wifi_channel(i);
                os_printf("Current channel %d-----------------%d\n", i, system_get_time());
                os_timer_arm(&timer, 1000, 0);
                break;
            }
        }
    }
}

/******************************************************************************
 * Promiscuous callback
 *
 * Callback not marked as ICACHE_FLASH_ATTR (loaded to iRam on boot)
 *******************************************************************************/
static void
user_promiscuous_rx_cb(uint8 *buf, uint16 buf_len)
{
    // Generic packet
    const struct sniffer_pkt *pkt = (struct sniffer_pkt *)buf;
    struct rx_control_pkt ctrl = (struct rx_control_pkt)pkt->rx_ctrl;

    // 802.11 packet
    const struct ieee80211_pkt *iee_pkt = (struct ieee80211_pkt *)pkt->payload;
    const struct ieee80211_hdr *hdr = &iee_pkt->hdr;
    const uint8_t *data = iee_pkt->payload;
    const struct frame_control_info *frame_ctrl = (struct frame_control_info *)&hdr->frame_control;

    // Ignore PKT_MISC
    if (frame_ctrl->type == PKT_MISC) return;
    // Packet too long
    if (ctrl.sig_len > SNAP_LEN) return;

    //if (frame_ctrl->type == PKT_MGMT && (pkt->payload[0] == 0xA0 || pkt->payload[0] == 0xC0 )) // deauths_counter++;

    // Packet length
    uint32_t packet_length = ctrl.sig_len;
    uint8_t i;
    for(i = 0; i < packet_length; ++i)
      os_printf("%c ", pkt->payload[i]);

    // Print
    // os_printf("\n%s | %s | %s | %u  | %02d |  %u  | %u(%-2u) |  %-28s  | %u | %u | %u | %u | %u | %u | %u | %u  ",
    //     print_mac(hdr->addr1),
    //     print_mac(hdr->addr2),
    //     print_mac(hdr->addr3),
    //     current_channel,
    //     pkt->rx_ctrl.rssi,
    //     frame_ctrl->protocol,
    //     frame_ctrl->type,
    //     frame_ctrl->subtype,
    //     print_packet_type((sniffer_pkt_t)frame_ctrl->type, (sniffer_mgmt_pkt_t)frame_ctrl->subtype), // Desc
    //     frame_ctrl->to_ds,
    //     frame_ctrl->from_ds,
    //     frame_ctrl->more_frag,
    //     frame_ctrl->retry,
    //     frame_ctrl->pwr_mgmt,
    //     frame_ctrl->more_data,
    //     frame_ctrl->wep,
    //     frame_ctrl->strict
    // );

    // Print payload
    if (frame_ctrl->type == PKT_MGMT && frame_ctrl->subtype == BEACON)
    {
        struct beacon_info *beacon_info = (struct beacon_info*) pkt->payload;
        char ssid[32];

        if (beacon_info->tag_length >= 32)
            strncpy(ssid, beacon_info->ssid, 31);
        else
            strncpy(ssid, beacon_info->ssid, beacon_info->tag_length);

       //os_printf("%02x", ssid);
    }
}

/******************************************************************************
 * Start sniffer loop
 *******************************************************************************/
void ICACHE_FLASH_ATTR
user_sniff()
{
    // Enable promiscus mode
    wifi_set_channel(1);
    wifi_promiscuous_enable(0);
    wifi_set_promiscuous_rx_cb(user_promiscuous_rx_cb);
    wifi_promiscuous_enable(1);
    os_printf("\n+---------------------------------------------------------------------------------------------------------------------------------------------------+");
    os_printf("\n|       M1        |        M2         |        M3         | Ch |  Rs | Prt | Type  |              Desc              | Ts| Fs| Mf| Rt| Pm| Mr| Wp| Sc|");
    os_printf("\n+---------------------------------------------------------------------------------------------------------------------------------------------------+");


    // Configure channel timer
    // os_timer_disarm(&timer);
    // os_timer_setfn(&timer, (os_timer_func_t *)user_channel_timer_cb, NULL);
    // os_timer_arm(&timer, 1000, 0);
}

/******************************************************************************
 * Station scan callback
 *
 * Callback not marked as ICACHE_FLASH_ATTR (loaded to iRam on boot)
 *******************************************************************************/
static void
user_station_scan_done_cb(void *arg, STATUS status)
{
    uint8_t ssid[33];
    channel_bits = 0;
    current_channel = 1;
    struct router_info *info = NULL;

    // Clear station list
    while ((info = SLIST_FIRST(&router_list)) != NULL)
    {
        SLIST_REMOVE_HEAD(&router_list, next);
        os_free(info);
    }

    // Feed station list
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

                // Save station info
                struct router_info *info = NULL;
                channel_bits |= 1 << (bss->channel);
                info = (struct router_info *) os_malloc(sizeof(struct router_info));
                info->authmode = bss->authmode;
                info->channel = bss->channel;
                os_memcpy(info->bssid, bss->bssid, 6);
                SLIST_INSERT_HEAD(&router_list, info, next);
            }

            // Next result entry
            bss = STAILQ_NEXT(bss, next);
        }

        os_delay_us(60000);

        // Sniff loop
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

    SLIST_INIT(&router_list);
    if(wifi_station_scan(config, user_station_scan_done_cb))
        os_printf("Station Scan Completed!\r\n");
}