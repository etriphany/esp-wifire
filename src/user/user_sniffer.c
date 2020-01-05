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
static uint32_t last_update = 0;
static uint8_t lookup_channel;
static uint8_t current_channel;
static uint16_t channel_bits;
SLIST_HEAD(router_info_head, router_info) router_list;

void ICACHE_FLASH_ATTR user_sniff(void);
uint8_t ICACHE_FLASH_ATTR pick_valid_channel(void);

/******************************************************************************
 * Change current channel
 *******************************************************************************/
void ICACHE_FLASH_ATTR
set_wifi_channel(uint8_t channel)
{
    if ((channel != current_channel) && (channel > 0) && (channel < MAX_CHANNEL + 1))
    {
        // Change channel
        current_channel = channel;
        wifi_set_channel(current_channel);

        // Post event
        system_os_post(USER_TASK_PRIO_0, SIG_CHANNEL, current_channel);
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
    #ifdef PRINTER_MODE
    // Print details
    user_print_packet(buf, buf_len, current_channel);
    #else
    // Pcap record
    user_pcap_record(buf, buf_len);
    #endif
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
        os_printf("\nStation Scan Success [status = %d]", status);
        uint8_t i;
        struct bss_info *bss = (struct bss_info *) arg;
        while (bss != NULL)
        {
            if (bss->channel != 0)
            {
                os_printf("\n Info >>> SSID[%s], Channel[%d], RSSI[%d], Authmode[%d]", bss->ssid, bss->channel, bss->rssi, bss->authmode);

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

        // Start sniff
        user_sniff();
    }
    else
    {
        os_printf("Station Scan Failed [status = %d] \r\n\n", status);
    }
}

/******************************************************************************
 * Start sniffer loop
 *******************************************************************************/
void ICACHE_FLASH_ATTR
user_sniff(void)
{
    #ifdef PRINTER_MODE
    // Headers
    user_print_headers();
    #else
    // Initialize PCAP transmission
    user_pcap_init();
    #endif

    // Pick valid channel
    pick_valid_channel();

    // Enable promiscuous mode
    wifi_promiscuous_enable(0);
    wifi_set_promiscuous_rx_cb(user_promiscuous_rx_cb);
    wifi_promiscuous_enable(1);

    // Post event
    system_os_post(USER_TASK_PRIO_0, SIG_SNIFFER_UP, current_channel);
}

/******************************************************************************
 * Pick valid channel
 *******************************************************************************/
uint8_t ICACHE_FLASH_ATTR
pick_valid_channel(void)
{
    uint8_t i;
    for (i = lookup_channel; i < MAX_CHANNEL; i++)
    {
        // Matches detection result
        if ((channel_bits & (1 << i)) != 0)
        {
            // Change channel
            lookup_channel = i + 1;
            set_wifi_channel(i);
            os_printf("\n | \n | Channel Shift %d", i);
            break;
        }
    }
    return i;
}

/******************************************************************************
 * Sniffer update
 *******************************************************************************/
void ICACHE_FLASH_ATTR
user_sniffer_update(const uint32_t millis)
{
    // Check if action is required
    if((millis - last_update)  < CHANNEL_CHANGE_DELAY)
        return;

    // Track update time
    last_update = millis;

    // Update channel
    uint8_t picked = pick_valid_channel();

    // Reset when reaches last possible channel
    if (picked == MAX_CHANNEL) {
        lookup_channel = 1;
        pick_valid_channel();
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

    // Init routers list
    SLIST_INIT(&router_list);

    // Scan routers
    struct scan_config config = {};
    config.show_hidden = 1;
    wifi_station_scan(&config, user_station_scan_done_cb);
}