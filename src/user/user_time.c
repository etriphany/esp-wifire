#include <c_types.h>
#include <mem.h>
#include <ets_sys.h>
#include <osapi.h>
#include <user_interface.h>

#include "user_config.h"
#include "user_time.h"

/**
 * Time control from:
 *
 * https://github.com/mrwgx3/Arduino/blob/56e13f41729c97cc6cd1cf1279f44c0d505194ce/cores/esp8266/core_esp8266_wiring.c
 */

// Features
static os_timer_t timer;
static uint32_t micros_last_overflow_tick = 0;
static uint32_t micros_overflow_cnt = 0;

/******************************************************************************
 * Tick counter.
 *
 *******************************************************************************/
void ICACHE_FLASH_ATTR
user_micros_overflow_tick_cb(void)
{
   uint32_t m = system_get_time();
   if(m < micros_last_overflow_tick)
      ++micros_overflow_cnt;
   micros_last_overflow_tick = m;
}

/******************************************************************************
 * Clock tick timer.
 *
 *******************************************************************************/
void ICACHE_FLASH_ATTR
user_clock_init(void)
{
   os_timer_disarm(&timer);
   os_timer_setfn(&timer, (os_timer_func_t*) &user_micros_overflow_tick_cb, 0);
   os_timer_arm(&timer, 60000, 1);
}

/******************************************************************************
 * Time in millis (with overflow support).
 *
 *******************************************************************************/
uint32_t ICACHE_FLASH_ATTR
millis(void)
{
  uint32_t  a[2];  // Accumulator, little endian
  a[1] = 0;        // Zero high-acc

  // Get usec system time, usec overflow counter
  uint32_t  m = system_get_time();
  uint32_t  c = micros_overflow_cnt + ((m < micros_last_overflow_tick) ? 1 : 0);

  // (a) Init. low-acc with high-word of 1st product. The right-shift
  //     falls on a byte boundary, hence is relatively quick.
  ((uint64_t *)(&a[0]))[0]  =
     ( (uint64_t)( m * (uint64_t)MAGIC_1E3_wLO ) >> 32 );

  ((uint64_t *)(&a[0]))[0] +=              // (b) Offset sum, low-acc
     ( m * (uint64_t)MAGIC_1E3_wHI );

  ((uint64_t *)(&a[0]))[0] +=              // (c) Offset sum, low-acc
     ( c * (uint64_t)MAGIC_1E3_wLO );

  ((uint32_t *)(&a[1]))[0] +=              // (d) Truncated sum, low-acc
     (uint32_t)( c * (uint64_t)MAGIC_1E3_wHI );

  return ( a[1] );  // Extract result, high-acc
}

/******************************************************************************
 * Time in micros (with overflow support).
 *
 *******************************************************************************/
uint64_t ICACHE_FLASH_ATTR
micros_64()
{
    uint32_t low32_us = system_get_time();
    uint32_t high32_us = micros_overflow_cnt + ((low32_us < micros_last_overflow_tick) ? 1 : 0);
    uint64_t duration64_us = (uint64_t)high32_us << 32 | low32_us;
    return duration64_us;
}