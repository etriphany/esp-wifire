#include <c_types.h>
#include <mem.h>
#include <ets_sys.h>
#include <osapi.h>
#include <gpio.h>
#include <user_interface.h>

#include "driver/uart.h"

#include "user_config.h"
#include "user_attack.h"
#include "user_time.h"

// Features
static os_event_t *events[1];
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
 * Task callback / Priority 0 (lower).
 *******************************************************************************/
static void ICACHE_FLASH_ATTR
user_task0_cb(os_event_t *event)
{
    switch(event->sig)
    {
        case SIG_SNIFFER_UP:
            user_attacks_init(event->par);
            break;

        case SIG_CHANNEL:
            user_attack_set_channel(event->par);
            break;

        case SIG_CLOCK_TICK:
            user_sniffer_update(event->par);
            user_batch_attack(event->par);
            break;
    }
}

/******************************************************************************
 * System init done callback.
 *
 * Callback not marked as ICACHE_FLASH_ATTR (loaded to iRam on boot)
 *******************************************************************************/
void ICACHE_FLASH_ATTR
user_system_init_done_cb(void)
{
    // Register event handler
    events[0] = (os_event_t*) os_malloc(sizeof(os_event_t) * TASK_QUEUE_SIZE);
    system_os_task(user_task0_cb, USER_TASK_PRIO_0, events[0], TASK_QUEUE_SIZE);

    // Initialize features
    user_clock_init();
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

    // Promiscuous mode requires station mode
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