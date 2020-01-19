#ifndef _USER_CONFIG_H
#define _USER_CONFIG_H

#define MAC_STR(mac, buf) os_sprintf(buf, "%02x:%02x:%02x:%02x:%02x:%02x", mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
#define ARRAY_SIZE(x) (sizeof((x)) / sizeof((x)[0]))

#define ESP01

// ESP01 (black 1MB) Flash Addresses
#ifdef ESP01
#define SPI_FLASH_SIZE_MAP                          2
#define SYSTEM_PARTITION_OTA_SIZE                   0x6A000     // ignored
#define SYSTEM_PARTITION_OTA_2_ADDR                 0x81000     // ignored
#define SYSTEM_PARTITION_RF_CAL_ADDR                0xfb000
#define SYSTEM_PARTITION_PHY_DATA_ADDR              0xfc000
#define SYSTEM_PARTITION_SYSTEM_PARAMETER_ADDR      0xfd000
#define SYSTEM_PARTITION_CUSTOMER_PRIV_PARAM_ADDR   0x7c000
#define SYSTEM_PARTITION_CUSTOMER_PRIV_PARAM        SYSTEM_PARTITION_CUSTOMER_BEGIN
#endif

// ESP12E (4MB) Flash Addresses
#ifdef ESP12
#define SPI_FLASH_SIZE_MAP                          4
#define SYSTEM_PARTITION_OTA_SIZE                   0x6A000     // ignored
#define SYSTEM_PARTITION_OTA_2_ADDR                 0x81000     // ignored
#define SYSTEM_PARTITION_RF_CAL_ADDR                0x3fb000
#define SYSTEM_PARTITION_PHY_DATA_ADDR              0x3fc000
#define SYSTEM_PARTITION_SYSTEM_PARAMETER_ADDR      0x3fd000
#define SYSTEM_PARTITION_CUSTOMER_PRIV_PARAM_ADDR   0x7c000
#define SYSTEM_PARTITION_CUSTOMER_PRIV_PARAM        SYSTEM_PARTITION_CUSTOMER_BEGIN
#endif

// Enable us timer
#define USE_US_TIMER

// Universal Wi-fi constants (don't touch)
#define MAX_CHANNEL                                 14
#define MAX_SSID_LEN                                32
#define MAC_ADDR_LEN                                6

// General
//#define PRINTER_MODE                                              // Uart works as text printer, instead PCAP pipe
#define MAX_FAKE_NETWORKS                           50              // Max fake networks (beacon spam)
#define MAX_TRACKED_ROUTERS                         15              // Max tracked unique routers (reseted per channel)
#define MAX_TRACKED_CLIENTS                         50              // Max tracked unique clients (reseted per channel)

// Time delays
#define ROUTERS_UPDATE_DELAY                        25 * 60 * 1000  // 25 min
#define CHANNEL_CHANGE_DELAY                        5 * 60 * 1000   // 5 min
#define BEACON_SPAM_US_DELAY                        100             // 100 us

// Tasks / Signals / Events
#define TASK_QUEUE_SIZE                             4
#define SIG_CLOCK_TICK                              0x10
#define SIG_SNIFFER_UP                              0x20
#define SIG_CHANNEL                                 0x30
#define SIG_TARGET                                  0x40


#endif