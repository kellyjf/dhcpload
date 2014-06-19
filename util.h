#ifndef DHCPLOADUITL_H
#define DHCPLOADUITL_H

unsigned short csum(unsigned short *ptr,int nbytes) ;
unsigned short checksum(unsigned short *ptr, int len);
unsigned short udp_sum_calc(unsigned short udp_len, unsigned short *src_addr,unsigned short *dest_addr, unsigned short *buff);



#endif

