#ifndef _USER_CONFIG_H
#define _USER_CONFIG_H

// ESP12E Flash Addresses
#define SPI_FLASH_SIZE_MAP                          4
#define SYSTEM_PARTITION_OTA_SIZE                   0x6A000
#define SYSTEM_PARTITION_OTA_2_ADDR                 0x81000
#define SYSTEM_PARTITION_RF_CAL_ADDR                0x3fb000
#define SYSTEM_PARTITION_PHY_DATA_ADDR              0x3fc000
#define SYSTEM_PARTITION_SYSTEM_PARAMETER_ADDR      0x3fd000
#define SYSTEM_PARTITION_CUSTOMER_PRIV_PARAM_ADDR   0x7c000
#define SYSTEM_PARTITION_CUSTOMER_PRIV_PARAM        SYSTEM_PARTITION_CUSTOMER_BEGIN

// General
//#define PRINTER_MODE                                // Uart works as text printer, instead PCAP pipe

// Limits
#define MAX_CHANNEL                                 14
#define MAX_SSID_LEN                                32
#define MAC_ADDR_LEN                                6

// Delays
#define ROUTERS_UPDATE_DELAY                        25 * 60 * 1000  // 25 min
#define CHANNEL_CHANGE_DELAY                        5 * 60 * 1000   // 5 min
#define BEACON_SPAM_DELAY                           5               // 5 ms

// Tasks / Signals / Events
#define TASK_QUEUE_SIZE                             4
#define SIG_SNIFFER_UP                              0x10
#define SIG_CHANNEL                                 0x20
#define SIG_CLOCK_TICK                              0x30

#endif