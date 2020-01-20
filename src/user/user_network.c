#include <c_types.h>
#include <osapi.h>
#include <user_interface.h>

#include "user_config.h"
#include "user_network.h"

/**
 * Some network facilities from:
 *
 * https://github.com/spacehuhn/esp8266_deauther/tree/master/esp8266_deauther
 */

// Features
static const uint8_t broadcast_mac[6] = { 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF };

bool ICACHE_FLASH_ATTR
user_is_mac_broadcast(uint8_t* mac)
{
    uint8_t i = 0;
    for (i = 0; i < MAC_ADDR_LEN; i++)
        if (mac[i] != broadcast_mac[i]) return FALSE;

    return TRUE;
}

void ICACHE_FLASH_ATTR
user_get_random_mac(uint8_t* mac)
{
    uint8_t i;
    for (i = 0; i < MAC_ADDR_LEN; i++)
         mac[i] = os_random() % 256;
}
