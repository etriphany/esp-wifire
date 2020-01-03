#include <c_types.h>
#include <mem.h>
#include <ets_sys.h>
#include <osapi.h>
#include <user_interface.h>

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
static os_timer_t timer;
SLIST_HEAD(router_info_head, router_info) router_list;
uint16_t channel_bits;

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
            os_printf("\n | \n | Channel Shift %d", i);
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
                os_printf("\n | \n | Channel Shift %d", i);
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
    #ifdef PRINTER_MODE
    // Print details
    user_print_packet(buf, buf_len);
    #else
    // Pcap record
    user_pcap_record(buf, buf_len);
    #endif
}

/******************************************************************************
 * Start sniffer loop
 *******************************************************************************/
void ICACHE_FLASH_ATTR
user_sniff(void)
{
    #ifdef PRINTER_MODE
    // Headers
    print_headers();
    #else
    // Initialize PCAP transmission
    user_pcap_init();
    #endif

    // Enable promiscuous mode
    wifi_set_channel(1);
    wifi_promiscuous_enable(0);
    wifi_set_promiscuous_rx_cb(user_promiscuous_rx_cb);
    wifi_promiscuous_enable(1);

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
        os_printf("\nStation Scan Success [status = %d]", status);
        uint8_t i;
        struct bss_info *bss = (struct bss_info *) arg;
        while (bss != NULL)
        {
            if (bss->channel != 0)
            {
                os_printf("\n Info >>> SSID[%s], RSSI[%d], Channel[%d], Authmode[%d]", bss->ssid, bss->channel, bss->authmode, bss->rssi);

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
    #ifndef PRINTER_MODE
    // Turn off prints
    system_set_os_print(0);
    #endif

    struct scan_config *config = NULL;
    // Init routers list
    SLIST_INIT(&router_list);
    // Scan routers
    wifi_station_scan(config, user_station_scan_done_cb);
}