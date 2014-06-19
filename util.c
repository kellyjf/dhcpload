#include <stdlib.h>
#include "util.h"

unsigned short csum(unsigned short *ptr,int nbytes) 
{
    register long sum;
    unsigned short oddbyte;
    register short answer;
 
    sum=0;
    while(nbytes>1) {
        sum+=*ptr++;
        nbytes-=2;
    }
    if(nbytes==1) {
        oddbyte=0;
        *((u_char*)&oddbyte)=*(u_char*)ptr;
        sum+=oddbyte;
    }
 
    sum = (sum>>16)+(sum & 0xffff);
    sum = sum + (sum>>16);
    answer=(short)~sum;
     
    return(answer);
}

unsigned short checksum(unsigned short *ptr, int len)
{
    int sum = 0;
    unsigned short answer = 0;
    unsigned short *w = ptr;
    int nleft = len;
 
    while(nleft > 1){
        sum += *w++;
        nleft -= 2;
    }
 
    sum = (sum >> 16) + (sum & 0xFFFF);
    sum += (sum >> 16);
    answer = ~sum;
    return(answer);
}

unsigned short udp_sum_calc(unsigned short udp_len, unsigned short *src_addr,unsigned short *dest_addr, unsigned short *buff)
{
    unsigned char prot_udp=17;
    unsigned long sum;
    int nleft;
    unsigned short *w;
 
    sum = 0;
    nleft = udp_len;
    w=buff;
 
    while(nleft > 1)
    {
        sum += *w++;
        nleft -= 2;
    }
 
    /* if nleft is 1 there ist still on byte left. We add a padding byte (0xFF) to build a 16bit word */
    if(nleft>0)
    {
    	/* sum += *w&0xFF; */
             sum += *w&ntohs(0xFF00);   /* Thanks to Dalton */
    }
 
    /* add the pseudo header */
    sum += src_addr[0];
    sum += src_addr[1];
    sum += dest_addr[0];
    sum += dest_addr[1];
    sum += htons(udp_len);
    sum += htons(prot_udp);
 
    // keep only the last 16 bits of the 32 bit calculated sum and add the carries
    sum = (sum >> 16) + (sum & 0xFFFF);
    sum += (sum >> 16);
 
    // Take the one's complement of sum
    sum = ~sum;
 
    return ((unsigned short) sum);
}

