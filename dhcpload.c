#include <stdio.h>
#include <fcntl.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>

#include <getopt.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netpacket/packet.h>
#include <net/ethernet.h> /* the L2 protocols */
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <sys/ioctl.h>
#include <net/if.h>




void usage(char *progname) {
	printf("Usage:  %s [options]\n", progname);
	printf("\t-h\t--help\tHelp (this message\n");
}


unsigned char  snd_buf[512];
unsigned char  psh_buf[512];
unsigned char  rcv_buf[2048];

typedef struct sockaddr_ll sll_t;
typedef struct sockaddr    sa_t;
typedef unsigned short us_t;

struct dhcp_body {
	unsigned char   bootreq, hwtype, alen, hops;
	unsigned int    id;
	unsigned short  elapsed;
	unsigned short  flags;
	unsigned int    ip_client, ip_your, ip_next, ip_relay;
	unsigned char   addr[16]; 
	unsigned char   server[64]; 
	unsigned char   bootfile[128]; 
	unsigned int    cookie;
	unsigned char   options[];
} __attribute__ ((__packed__));

struct dhcp_packet {
	struct ether_header  eth;
	struct iphdr         ip;
	struct udphdr        udp;
	struct dhcp_body     dhcp;
} __attribute__ ((__packed__));


int bind_interface(int sock, char *name) {
	struct ifreq ifr;
	int          rc;
	sll_t        sll, *phw;
	
	memset(&ifr, 0, sizeof(ifr));
	memset(&sll, 0, sizeof(sll));

	strncpy(ifr.ifr_name, name, IFNAMSIZ);

	if((rc=ioctl(sock, SIOCGIFINDEX, &ifr))<0) {
		perror("SIOCGIFINDEX:");
		return -1;
	}

	printf("Index is %d\n", ifr.ifr_ifindex);
	sll.sll_family = AF_PACKET;	
	sll.sll_protocol = htons(ETHERTYPE_IP);
	sll.sll_ifindex  = ifr.ifr_ifindex;
	sll.sll_halen = ETH_ALEN;
	phw = (sll_t *)&ifr.ifr_hwaddr;
	memcpy(&sll.sll_addr, &(phw->sll_addr), ETH_ALEN); 

	if((rc = bind(sock, (sa_t *)&sll, sizeof(sll)))<0) {
		perror("bind");
		return -1;
	}

	return ifr.ifr_ifindex;
}
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

void dump_packet(unsigned char *buf, ssize_t cnt) {

	ssize_t              ndx;
	struct dhcp_packet  *p;

	p = (struct dhcp_packet *)buf;

	printf ("CLIENT MAC: %02x:%02x:%02x:%02x:%02x:%02x\n",
		p->dhcp.addr[0],
		p->dhcp.addr[1],
		p->dhcp.addr[2],
		p->dhcp.addr[3],
		p->dhcp.addr[4],
		p->dhcp.addr[5]);
	printf ("DST MAC: %02x:%02x:%02x:%02x:%02x:%02x\n",
		p->eth.ether_dhost[0],
		p->eth.ether_dhost[1],
		p->eth.ether_dhost[2],
		p->eth.ether_dhost[3],
		p->eth.ether_dhost[4],
		p->eth.ether_dhost[5]);
	printf ("SRC MAC: %02x:%02x:%02x:%02x:%02x:%02x\n",
		p->eth.ether_shost[0],
		p->eth.ether_shost[1],
		p->eth.ether_shost[2],
		p->eth.ether_shost[3],
		p->eth.ether_shost[4],
		p->eth.ether_shost[5]);
	printf("ETH TYPE %04x\n", htons(p->eth.ether_type));
	for(ndx=0; ndx<cnt; ndx++) {
		if(ndx && ndx%4==0) printf(" ");
		if(ndx && ndx%8==0) printf(" ");
		if(ndx && ndx%16==0) printf("\n");
		printf("%02x", buf[ndx]);
	}
	printf("\n");

}


int send_packet(int sock, int type) {
	struct dhcp_packet     *p;
	struct dhcp_packet     *r;
	static unsigned short  idnum = 0x66;
	ssize_t                len;
	ssize_t                ndx;
	
	memset(snd_buf, 0, sizeof(snd_buf));
	p = (struct dhcp_packet  *) snd_buf;
	r = (struct dhcp_packet  *) rcv_buf;

	memset(&p->eth.ether_dhost, 0xff, ETH_ALEN);
	p->eth.ether_shost[0] = 0xCC;
	p->eth.ether_shost[1] = 0xCC;
	p->eth.ether_shost[2] = 0xCC;
	p->eth.ether_shost[3] = 0x04;
	p->eth.ether_shost[4] = 0x05;
	p->eth.ether_shost[5] = 0x06;
	p->eth.ether_type = htons(ETHERTYPE_IP);

	p->ip.version = 4;
	p->ip.ihl = 5;
	p->ip.id = htons(idnum++); 
	p->ip.ttl = 64; 
	p->ip.protocol = 17; 
	p->ip.daddr = 0xFFFFFFFF;
	
	p->udp.source = htons(68);
	p->udp.dest = htons(67);
	p->udp.len = htons(sizeof(*p));

	p->dhcp.bootreq = 1;
	p->dhcp.hwtype = 1;
	p->dhcp.alen = ETH_ALEN;
	p->dhcp.id = 0xCAFE;
	p->dhcp.flags = 0x0080;
	memcpy(p->dhcp.addr, p->eth.ether_shost, ETH_ALEN);
	p->dhcp.cookie = htonl(0x63825363);

	ndx=0;
	p->dhcp.options[ndx++] = 0x35;
	p->dhcp.options[ndx++] = 0x01;
	p->dhcp.options[ndx++] = type;
	switch(type) {
	case 1:
		p->dhcp.options[ndx++] = 0x37;
		p->dhcp.options[ndx++] = 0x04;
		p->dhcp.options[ndx++] = 0x01;
		p->dhcp.options[ndx++] = 0x03;
		p->dhcp.options[ndx++] = 0x06;
		p->dhcp.options[ndx++] = 0x1c;
		break;
	case 3:
		p->dhcp.options[ndx++] = 0x3d;
		p->dhcp.options[ndx++] = 0x07;
		p->dhcp.options[ndx++] = 0x01;
		memcpy(&p->dhcp.options[ndx], p->eth.ether_dhost, ETH_ALEN);
		ndx += ETH_ALEN;

		p->dhcp.options[ndx++] = 0x32;
		p->dhcp.options[ndx++] = 0x04;
		memcpy(&p->dhcp.options[ndx], &r->dhcp.ip_your, 4);
		ndx += 4;

		p->dhcp.options[ndx++] = 0x3c;
		p->dhcp.options[ndx++] = 12;
		sprintf(&p->dhcp.options[ndx], "dchpload-%03x", p->eth.ether_shost[5]);
		ndx += 12;
		
		break;
	default:
		break;
	}
	p->dhcp.options[ndx++] = 0xFF;
	len = sizeof(*p)+ndx;

	p->ip.tot_len = htons(len - sizeof(p->eth));
	p->udp.len = htons(len - sizeof(p->eth) - sizeof(p->ip));

	p->ip.check = (checksum((unsigned short *)&p->ip, p->ip.ihl*4));
	p->udp.check = (udp_sum_calc(htons(p->udp.len), (us_t *)&p->ip.saddr, (us_t *)&p->ip.daddr, (us_t *)&p->udp));

	return write(sock, p, len);
}

int main(int argc, char **argv) {


	int         packet_socket;
	int         rc, ch, cnt;
	sll_t       sll;         
	ssize_t     rcnt;
	socklen_t   slen;

	/* options descriptor */
	static struct option longopts[] = {
		{ "help",       no_argument,            NULL,           'h' },
		{ "fluoride",   required_argument,      NULL,           'f' },
		{ NULL,         0,                      NULL,           0 }
	};

	while ((ch = getopt_long(argc, argv, "h", longopts, NULL)) != -1)
		switch (ch) {
		case 'h':
			usage(argv[0]);
			exit(0);
			break;
		default:
		     usage(argv[0]);
	}
	argc -= optind;
	argv += optind;
	
	packet_socket = socket(AF_PACKET, SOCK_RAW, htons(ETHERTYPE_IP));

	if(packet_socket<0) {
		perror("SOCK_RAW requires root permissions");
		exit(1);
	}

	if((rc = bind_interface(packet_socket, "eth0"))<0) {
		return -1;
	}

	rc = send_packet(packet_socket, 1);
	{
		struct dhcp_packet *r = rcv_buf;
		struct dhcp_packet *s = snd_buf;
		
		cnt = 0;
			
		while(cnt++<1500 &&memcmp((void*)r->dhcp.addr, (void*)s->eth.ether_shost, ETH_ALEN)) {
			memset(&sll, 0, sizeof(sll));  slen=sizeof(sll);
			memset(rcv_buf, 0, sizeof(rcv_buf)); 
			
			if((rcnt=recvfrom(packet_socket, rcv_buf, sizeof(rcv_buf), 0,
				(sa_t*)&sll, &slen))>0) {
				
					printf("%02x %d; ",r->eth.ether_dhost[5], r->ip.protocol);
					fflush(stdout);
					if(r->eth.ether_dhost[5]==0xff && r->ip.protocol==17) dump_packet(rcv_buf, rcnt);
			} else {
				perror("recvfrom");
			}	
		}
		printf("Found it!: %d\n", rcnt);
	}

	rc = send_packet(packet_socket, 3);
	{
		struct dhcp_packet *r = rcv_buf;
		struct dhcp_packet *s = snd_buf;
		
		cnt = 0;
		while(cnt++<15 &&memcmp(r->dhcp.addr, s->eth.ether_shost, ETH_ALEN)) {
		if((rcnt=recvfrom(packet_socket, rcv_buf, sizeof(rcv_buf), 0,
			(sa_t*)&sll, &slen))>0) {
			
				printf("Got another: %d\n", rcnt);
				dump_packet(rcv_buf, rcnt);
			}
		}	
		printf("Found it!: %d\n", rcnt);
	}
	close(packet_socket);

	return(0);
}

