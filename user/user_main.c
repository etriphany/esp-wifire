#include <c_types.h>
#include <mem.h>
#include <ets_sys.h>
#include <osapi.h>
#include <user_interface.h>

#include "driver/uart.h"

#include "user_config.h"
#include "user_sniffer.h"

// Features
static const partition_item_t at_partition_table[] = {
    { SYSTEM_PARTITION_BOOTLOADER, 						0x0, 												0x1000},
    { SYSTEM_PARTITION_OTA_1,   						0x1000, 											SYSTEM_PARTITION_OTA_SIZE},
    { SYSTEM_PARTITION_OTA_2,   						SYSTEM_PARTITION_OTA_2_ADDR, 						SYSTEM_PARTITION_OTA_SIZE},
    { SYSTEM_PARTITION_RF_CAL,  						SYSTEM_PARTITION_RF_CAL_ADDR, 						0x1000},
    { SYSTEM_PARTITION_PHY_DATA, 						SYSTEM_PARTITION_PHY_DATA_ADDR, 					0x1000},
    { SYSTEM_PARTITION_SYSTEM_PARAMETER, 				SYSTEM_PARTITION_SYSTEM_PARAMETER_ADDR, 			0x3000},
    { SYSTEM_PARTITION_CUSTOMER_PRIV_PARAM,             SYSTEM_PARTITION_CUSTOMER_PRIV_PARAM_ADDR,          0x1000},
};

/******************************************************************************
 * System init done callback.
 *
 * Callback not marked as ICACHE_FLASH_ATTR (loaded to iRam on boot)
 *******************************************************************************/
static void
user_system_init_done_cb(void)
{
    // Setup hacks
    user_sniffer_init();
}


// ==========================================
// SDK required functions
// ==========================================

/******************************************************************************
 * The default method provided. Users can add functions like
 * firmware initialization, network parameters setting,
 * and timer initialization within user_init
 *******************************************************************************/
void ICACHE_FLASH_ATTR
user_init()
{
    // Configure flash partition
    partition_item_t partition_item;
    if (!system_partition_get_item(SYSTEM_PARTITION_CUSTOMER_PRIV_PARAM, &partition_item))
        os_printf("Init failed: Get partition information\n");

    // Init UART
    uart_init(BIT_RATE_115200, BIT_RATE_115200);

    // Promiscuous works only with station mode
    wifi_set_opmode(STATION_MODE);

    // Wait init done to proceed
    system_init_done_cb(user_system_init_done_cb);
}

/******************************************************************************
 * Need to be added to 'user_main.c' from ESP8266_NONOS_SDK_V3.0.0 onwards.
 *******************************************************************************/
void ICACHE_FLASH_ATTR
user_pre_init(void)
{
   uint32_t partition = sizeof(at_partition_table) / sizeof(at_partition_table[0]);
   if(!system_partition_table_regist(at_partition_table, partition, SPI_FLASH_SIZE_MAP))
   {
		os_printf("Init failed: Partition table registry\r\n");
		while(1);
   }
}

/******************************************************************************
 * From  ESP8266_NONOS_SDK_V2.1.0 onwards, when the DIO-to-QIO
 * flash is not used, users can add an empty function
 * 'void user_spi_flash_dio_to_qio_pre_init(void)' on
 * the application side to reduce iRAM usage.
 *******************************************************************************/
void ICACHE_FLASH_ATTR
user_spi_flash_dio_to_qio_pre_init(void)
{
}