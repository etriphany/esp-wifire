#ifndef _USER_PRINTER_H
#define _USER_PRINTER_H

#include "user_sniffer.h"

void user_print_headers(void);
void user_print_beacon(struct beacon_info *beacon);
void user_print_client(struct client_info *client);
void user_print_packet(uint8_t *buf, uint16_t buf_len, uint8_t channel);

#endif