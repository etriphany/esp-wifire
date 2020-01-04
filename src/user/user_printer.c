#include <c_types.h>
#include <mem.h>
#include <ets_sys.h>
#include <osapi.h>
#include <user_interface.h>

#include "user_config.h"
#include "user_sniffer.h"
#include "user_network.h"

// Features
const uint8_t cli_broadcast1[3] = {0x01, 0x00, 0x5e};
const uint8_t cli_broadcast2[6] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff};
const uint8_t cli_broadcast3[3] = {0x33, 0x33, 0x00};

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

	os_memcpy(client->station, station, MAC_ADDR_LEN);
	os_memcpy(client->bssid, bssid, MAC_ADDR_LEN);
	os_memcpy(client->ap, ap, MAC_ADDR_LEN);

	client->seq_n = (buf[23] * 0xFF) + (buf[22] & 0xF0);
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
user_print_packet(uint8_t *buf, uint16_t buf_len)
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

    if (frame_ctrl->type == PKT_MGMT && frame_ctrl->subtype == BEACON)
    {
        struct sniffer_mgmt_pkt *mgnt_pkt = (struct sniffer_mgmt_pkt *)buf;
        struct beacon_info *beacon_info = os_zalloc(sizeof(struct beacon_info));

        parse_beacon_packet(beacon_info, mgnt_pkt->buf, 112);
        os_printf("\n \\ \n  | Info >>> SSID [%d], BSSID [%s] \n /",
            beacon_info->ssid,
            print_mac(beacon_info->bssid)
        );
    }
    else if (frame_ctrl->type == PKT_DATA)
    {
        struct sniffer_data_pkt *data_pkt = (struct sniffer_data_pkt *)buf;
        struct client_info *client_info = os_zalloc(sizeof(struct client_info));

        parse_data_packet(client_info, data_pkt->buf, 36, pkt->rx_ctrl.rssi, pkt->rx_ctrl.channel);
        os_printf("\n \\ \n  | Info >>> BSSID [%s], Station [%s], Ap [%s] \n /",
            print_mac(client_info->bssid),
            print_mac(client_info->station),
            print_mac(client_info->ap)
        );
    }
    else
        os_printf("\n \\ \n  |  \n /");
}