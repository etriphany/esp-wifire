#include <c_types.h>
#include <osapi.h>
#include <user_interface.h>

#include "user_network.h"

// Features
static const uint8_t broadcast_mac[6] = { 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF };

/******************************************************************************
 * Change wifi channel
 *******************************************************************************/
void ICACHE_FLASH_ATTR
user_set_wifi_channel(uint8_t channel)
{
    if ((channel != current_channel) && (channel > 0) && (channel < 15))
    {
        current_channel = channel;
        wifi_set_channel(current_channel);
    }
}

bool ICACHE_FLASH_ATTR
user_is_mac_broadcast(uint8_t* mac)
{
    uint8_t i = 0;
    for (i = 0; i < 6; i++)
        if (mac[i] != broadcast_mac[i]) return false;

    return true;
}

void user_get_random_mac(uint8_t* mac)
{
    uint8_t i;
    for (i = 0; i < 6; i++)
        mac[i] = random(256);
}

bool ICACHE_FLASH_ATTR
user_is_mac_valid(uint8_t* mac)
{
    uint8_t i = 0;
    for (i = 0; i < 6; i++)
        if (mac[i] != 0x00) return true;

    return false;
}

// see https://en.wikipedia.org/wiki/Multicast_address
bool ICACHE_FLASH_ATTR
user_is_mac_multicast(uint8_t* mac)
 {
    if ((mac[0] == 0x33) && (mac[1] == 0x33)) return true;

    if ((mac[0] == 0x01) && (mac[1] == 0x80) && (mac[2] == 0xC2)) return true;

    if ((mac[0] == 0x01) && (mac[1] == 0x00) && ((mac[2] == 0x5E) || (mac[2] == 0x0C))) return true;

    if ((mac[0] == 0x01) && (mac[1] == 0x0C) && (mac[2] == 0xCD) &&
        ((mac[3] == 0x01) || (mac[3] == 0x02) || (mac[3] == 0x04)) &&
        ((mac[4] == 0x00) || (mac[4] == 0x01))) return true;

    if ((mac[0] == 0x01) && (mac[1] == 0x00) && (mac[2] == 0x0C) && (mac[3] == 0xCC) && (mac[4] == 0xCC) &&
        ((mac[5] == 0xCC) || (mac[5] == 0xCD))) return true;

    if ((mac[0] == 0x01) && (mac[1] == 0x1B) && (mac[2] == 0x19) && (mac[3] == 0x00) && (mac[4] == 0x00) &&
        (mac[5] == 0x00)) return true;

    return false;
}