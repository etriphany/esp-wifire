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
#define ETH_MAC_LEN                                 6
#define WHITELIST_LENGTH                            2

#endif