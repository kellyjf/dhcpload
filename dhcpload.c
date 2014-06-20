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

#include "util.h"


void usage(char *progname) {
	printf("Usage:  %s [options]\n", progname);
	printf("\t-i|--interface        Interface (eth0)\n");
	printf("\t-t|--total            Total requests to generate (1)\n");
	printf("\t-w|--wait             Seconds of delay between requests (1)\n");
	printf("\t-j|--concurrent       Number of concurrent sessions (3)\n");
	printf("\t-d|--debug            Turn on debugging\n");
	printf("\t-h\t--help\tHelp (this message\n");
}

 
typedef enum {
	SESS_START, SESS_DISCOVER, SESS_REQUEST, SESS_DONE
} session_state_t;

typedef struct {
	unsigned char   index;
	session_state_t state;
	unsigned char   server_mac_addr[ETH_ALEN];
	unsigned char   client_mac_addr[ETH_ALEN];
	unsigned char   client_ip_addr[4];
	struct timeval  tv_discover, tv_offer, tv_request, tv_ack;
} session_t;
	
typedef struct sockaddr_ll sll_t;
typedef struct sockaddr    sa_t;
typedef unsigned short     us_t;

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
typedef struct dhcp_packet dhcp_t;


unsigned char  snd_buf[512];
unsigned char  rcv_buf[2048];
session_t     *session;
unsigned int   opt_max = 1;
unsigned int   opt_wait = 1;
unsigned int   opt_debug = 0;
unsigned int   opt_concurrent = 5;

unsigned int   sessions_available;
unsigned int   sessions_pending;
unsigned int   sessions_remaining;

void dump_packet(unsigned char *buf, ssize_t cnt) {

	ssize_t              ndx;
	dhcp_t              *p;

	p = (dhcp_t *)buf;

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

	if(opt_debug) printf("Interface %s Index is %d\n", name, ifr.ifr_ifindex);
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

int send_packet(int sock, session_t *sess, int type) {
	dhcp_t                 *p;
	dhcp_t                 *r;
	static unsigned short  idnum = 0x66;
	ssize_t                len;
	ssize_t                ndx;
	socklen_t              slen;
	
	memset(snd_buf, 0, sizeof(snd_buf));
	p = (dhcp_t  *) snd_buf;
	r = (dhcp_t  *) rcv_buf;

	memset(&p->eth.ether_dhost, 0xff, ETH_ALEN);
	memcpy(p->eth.ether_shost, sess->client_mac_addr, ETH_ALEN);
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
	p->dhcp.id = 0xFECA + (sess->index<<16) + (type<<24);
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

#define TRACE if(opt_debug) printf("%s %d (%d,%d,%d)\n", __func__, __LINE__, sessions_remaining, sessions_pending, sessions_available)
#define DETAIL if(opt_debug) printf("Found %d/%d: %s %d (%d,%d,%d)\n",found, session[found].state, __func__, __LINE__, sessions_remaining, sessions_pending, sessions_available)
int main(int argc, char **argv) {


	int         packet_socket;
	int         rc, ch, cnt, ndx;
	sll_t       sll;         
	ssize_t     rcnt;
	socklen_t   slen;
	char       *opt_ifname = "eth0";

	/* options descriptor */
	static struct option longopts[] = {
		{ "help",       no_argument,            NULL,           'h' },
		{ "debug",      no_argument,            NULL,           'h' },
		{ "wait",       required_argument,      NULL,           'w' },
		{ "total",      required_argument,      NULL,           't' },
		{ "concurrent", required_argument,      NULL,           'j' },
		{ "interface",  required_argument,      NULL,           'i' },
		{ NULL,         0,                      NULL,           0 }
	};

	while ((ch = getopt_long(argc, argv, "hdi:j:t:w:", longopts, NULL)) != -1)
		switch (ch) {
		case 'd':
			opt_debug=1;
			break;
		case 'j':
			opt_concurrent = strtoul(optarg, NULL, 10);
			break;
		case 't':
			opt_max = strtoul(optarg, NULL, 10);
			break;
		case 'w':
			opt_wait = strtoul(optarg, NULL, 10);
			break;
		case 'i':
			opt_ifname = optarg;
			break;
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

	if((rc = bind_interface(packet_socket, opt_ifname))<0) {
		return -1;
	}

	session = calloc(opt_max, sizeof(session_t));
	for(ndx=0; ndx<opt_max; ndx++) {
		session[ndx].index = ndx;
		session[ndx].state = SESS_START;
		memset(session[ndx].client_mac_addr, '\xCC', ETH_ALEN);
		session[ndx].client_mac_addr[5] = ndx;
	}

	sessions_available = opt_concurrent;
	sessions_pending   = opt_max;
	sessions_remaining = opt_max;
	ndx = 0;

	while(sessions_pending) {
		dhcp_t        *r = (dhcp_t *)rcv_buf;
		unsigned char *bcast = "\xff\xff\xff\xff\xff\xff";
		unsigned char *oui =   "\xcc\xcc\xcc";


		while(sessions_available && sessions_remaining) {
			if(session[ndx].state == SESS_START) {
				rc = send_packet(packet_socket, session+ndx, 1);
				session[ndx].state = SESS_DISCOVER;
				ndx++;  ndx %= opt_max;
				sessions_remaining--;
				sessions_available--;
				sleep(opt_wait);
			}
TRACE;
		}
		while(sessions_available==0 || (sessions_pending && sessions_remaining==0)) {
TRACE;
			memset(rcv_buf, 0, sizeof(rcv_buf)); 
			while(memcmp((void*)r->dhcp.addr, oui, 3)) {
TRACE;
				memset(&sll, 0, sizeof(sll));  slen=sizeof(sll);
				memset(rcv_buf, 0, sizeof(rcv_buf)); 
				
				if((rcnt=recvfrom(packet_socket, rcv_buf, sizeof(rcv_buf), 0,
					(sa_t*)&sll, &slen))>0) {
					
TRACE;
#if 0
						printf("%x\n", memcmp(r->eth.ether_dhost, bcast, ETH_ALEN)==0);
						printf("%x\n", (r->dhcp.id & 0xffff)==0xfeca);
						printf("%x\n", (r->ip.protocol==17));
						printf("%x\n", memcmp(r->dhcp.addr, oui, 3)==0);
#endif
						if( (memcmp(r->eth.ether_dhost, bcast, ETH_ALEN)==0) 
							&& (r->ip.protocol==17 )
							&& ((r->dhcp.id & 0xffff ) == 0xfeca)
							&& (memcmp(r->dhcp.addr, oui,3)==0)) {
							unsigned char found = r->dhcp.addr[5];
DETAIL;
	
							switch(session[found].state) {
							case SESS_DISCOVER:
								rc = send_packet(packet_socket, session+found, 3);
		
								session[found].state = SESS_REQUEST;
								break;
							case SESS_REQUEST:
								session[found].state = SESS_DONE;
								sessions_pending--;
								sessions_available++;
								break;
							}
DETAIL;
						}
					//	dump_packet(rcv_buf, rcnt);
				} else {
					perror("recvfrom");
				}	
			}
		}
	}

	close(packet_socket);

	return(0);
}

