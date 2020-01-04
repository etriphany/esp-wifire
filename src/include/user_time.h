#ifndef _USER_TIME_H
#define _USER_TIME_H

#define  MAGIC_1E3_wLO  0x4bc6a7f0    // LS part
#define  MAGIC_1E3_wHI  0x00418937    // MS part, magic multiplier

/**
 * Time control from:
 *
 * https://github.com/mrwgx3/Arduino/blob/56e13f41729c97cc6cd1cf1279f44c0d505194ce/cores/esp8266/core_esp8266_wiring.c
 */

void user_clock_init(void);
uint32_t millis(void);
uint64_t micros_64(void);

#endif