#ifndef _USER_NETWORK_H
#define _USER_NETWORK_H

/**
 * Network facilities from:
 *
 * https://github.com/spacehuhn/esp8266_deauther/tree/master/esp8266_deauther
 */

uint8_t lookup_channel;     // Used for lookup
uint8_t current_channel;    // Current channel

void user_set_wifi_channel(uint8_t channel);

bool user_is_mac_broadcast(uint8_t* mac);
bool user_is_mac_valid(uint8_t* mac);
bool user_is_mac_multicast(uint8_t* mac);

#endif