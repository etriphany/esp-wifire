#ifndef _USER_ATTACK_H
#define _USER_ATTACK_H

/**
 * Attack foundations from:
 *
 * https://github.com/spacehuhn/esp8266_deauther/tree/master/esp8266_deauther
 */

struct fake_router_info {
    SLIST_ENTRY(fake_router_info) next;
    uint8_t bssid[MAC_ADDR_LEN];
    uint8_t ssid[MAX_SSID_LEN + 1];
};

void user_attack_set_channel(uint8_t channel);
void user_attacks_init(uint8_t channel);

#endif