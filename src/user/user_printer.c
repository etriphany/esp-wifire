#include <c_types.h>
#include <mem.h>
#include <ets_sys.h>
#include <osapi.h>
#include <user_interface.h>

#include "user_config.h"
#include "user_sniffer.h"
#include "user_network.h"

/******************************************************************************
 * Print MAC
 *******************************************************************************/
char* ICACHE_FLASH_ATTR
print_mac(const uint8_t* mac)
{
  char *buf = "00:00:00:00:00:00\0";
  MAC_STR(mac, buf);
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

/******************************************************************************
 * Print headers
 *******************************************************************************/
void ICACHE_FLASH_ATTR
user_print_headers(void)
{
    os_printf("\n ------------------------------------------------------------------------------------------------------------------------------------------------------- ");
    os_printf("\n|        M1         |        M2         |        M3         | Ch |   Rs  | Prt | Type  |              Desc              | Ts| Fs| Mf| Rt| Pm| Mr| Wp| Sc| ");
}

/******************************************************************************
 * Print packet
 *******************************************************************************/
void ICACHE_FLASH_ATTR
user_print_beacon(struct beacon_info *beacon)
{
    os_printf("\n \\ \n  | Info >>> SSID [%32s], BSSID [%s] \n /",
        beacon->ssid,
        print_mac(beacon->bssid)
    );
}

/******************************************************************************
 * Print packet
 *******************************************************************************/
void ICACHE_FLASH_ATTR
user_print_client(struct client_info *client)
{
    os_printf("\n \\ \n  | Info >>> BSSID [%s], Station [%s], Ap [%s] \n /",
        print_mac(client->bssid),
        print_mac(client->station),
        print_mac(client->ap)
    );
}

/******************************************************************************
 * Print packet
 *******************************************************************************/
void ICACHE_FLASH_ATTR
user_print_packet(uint8_t *buf, uint16_t buf_len, uint8_t channel)
{
    // Generic
    const struct sniffer_pkt *pkt = (struct sniffer_pkt *)buf;

    // 802.11
    const struct ieee80211_pkt *iee_pkt = (struct ieee80211_pkt *)pkt->payload;
    const struct ieee80211_hdr *hdr = &iee_pkt->hdr;
    const struct frame_control_info *frame_ctrl = (struct frame_control_info *)&hdr->frame_control;

    // Print metadata
    os_printf("\n| %s | %s | %s | %u  |  %02d  |  %u  | %u(%-2u) |  %-28s  | %u | %u | %u | %u | %u | %u | %u | %u |",
        print_mac(hdr->addr1),
        print_mac(hdr->addr2),
        print_mac(hdr->addr3),
        channel,
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

}