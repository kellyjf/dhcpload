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

#include "queue.h"
#include "pool.h"

unsigned int   opt_max        = 1;
unsigned int   opt_timeout    = 10;
unsigned int   opt_wait       = 1;
unsigned int   opt_debug      = 0;
unsigned int   opt_quiet      = 0;
unsigned int   opt_concurrent = 5;
char          *opt_ifname     = "eth0";

void usage(char *progname) {
	printf("Usage:  %s [options]\n", progname);
	printf("\t-i|--interface name     Interface                         (using: %s)\n", opt_ifname);
	printf("\t-m|--max #reqs          Total requests to generate        (using: %d)\n", opt_max);
	printf("\t-t|--timeout #sec       Restart discovery interval        (using: %d)\n", opt_timeout);
	printf("\t-w|--wait  #sec/req     Rate limit # request per interval (using: %d)\n", opt_wait);
	printf("\t-j|--concurrent num     Number of concurrent requests     (using: %d)\n", opt_concurrent);
	printf("\t-d|--debug              Turn on debugging\n");
	printf("\t-q|--quiet              Suppress status reporting\n");
	printf("\t-h|--help               Help (this message)\n");
}


typedef unsigned char[ETH_ALEN] hw_addr_t;
 
typedef enum {
	SESS_START, SESS_DISCOVER, SESS_REQUEST, SESS_DONE
} session_state_t;

enum {
	DHCP_OPTION_SUBNET_MASK = 0x01,
	DHCP_OPTION_ROUTER = 0x03,
	DHCP_OPTION_DNS = 0x06,
	DHCP_OPTION_HOSTNAME = 0x0c,
	DHCP_OPTION_REQUESTED_IP = 0x32,
	DHCP_OPTION_LEASE = 0x33,
	DHCP_OPTION_MESSAGE_TYPE = 0x35,
	DHCP_OPTION_SERVER = 0x36,
	DHCP_OPTION_PARAM_LIST = 0x37,
	DHCP_OPTION_RENEWAL = 0x3a,
	DHCP_OPTION_CLIENT_ID = 0x3d,
	DHCP_OPTION_END = 0xff,
};
	
	
typedef struct sockaddr_ll sll_t;
typedef struct sockaddr    sa_t;
typedef unsigned short     us_t;

s
typedef struct {
	session_state_t   state;
	struct list_head  list;
	msg_queue_t      *thread_queue;
	msg_queue_t      *mgr_queue;
	hw_addr_t         client_mac;	
	hw_addr_t         server_mac;	
	unsigned int      client_ip;
	unsigned int      server_ip;
	sll_t             sll;
	socklen_t         slen;
	union {
		unsigned char snd_buf[384];
		dhcp_t        dhcp;
	}                 buf;
} session_t;


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
	p->dhcp.options[ndx++] = DHCP_OPTION_MESSAGE_TYPE;
	p->dhcp.options[ndx++] = 0x01;
	p->dhcp.options[ndx++] = type;
	switch(type) {
	case 1:
		p->dhcp.options[ndx++] = DHCP_OPTION_PARAM_LIST;
		p->dhcp.options[ndx++] = 0x04;
		p->dhcp.options[ndx++] = 0x01;
		p->dhcp.options[ndx++] = 0x03;
		p->dhcp.options[ndx++] = 0x06;
		p->dhcp.options[ndx++] = 0x1c;
		break;
	case 3:
		p->dhcp.options[ndx++] = DHCP_OPTION_CLIENT_ID;
		p->dhcp.options[ndx++] = 0x07;
		p->dhcp.options[ndx++] = 0x01;
		memcpy(&p->dhcp.options[ndx], p->eth.ether_dhost, ETH_ALEN);
		ndx += ETH_ALEN;

		p->dhcp.options[ndx++] = DHCP_OPTION_REQUESTED_IP;
		p->dhcp.options[ndx++] = 0x04;
		memcpy(&p->dhcp.options[ndx], &r->dhcp.ip_your, 4);
		ndx += 4;

		p->dhcp.options[ndx++] = DHCP_OPTION_HOSTNAME;
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

	if(opt_debug) printf("Sending client %d type %d\n", sess->index, type);
	return write(sock, p, len);
}


void *dhcp_client_thread(void *user) {
	

}

void *dhcp_recv_thread(void *user) {
	session_t       *session   = user;
	unsigned char   *rcv_buf;
	int              packet_socket;

	rcv_buf = pool_alloc(session->pool);

	packet_socket = socket(AF_PACKET, SOCK_RAW, htons(ETHERTYPE_IP));

	if(packet_socket<0) {
		perror("SOCK_RAW requires root permissions");
		exit(1);
	}

	if((rc = bind_interface(packet_socket, opt_ifname))<0) {
		return -1;
	}

	
	memset(rcv_buf, 0, pool_slabsize(session->pool) ); 
	memset(&pool->sll, 0, sizeof(sll));  session->slen=sizeof(sll);

	if((rcnt=recvfrom(packet_socket, rcv_buf, pool_slabsize(session->pool), 0,
		(sa_t*)&session->sll, &session->slen))>0) {
		
		dhcp_t  *r = (shcp_t *)rcv_buf;	
		
		if( (memcmp(r->eth.ether_dhost, bcast, ETH_ALEN)==0) 
			&& (r->ip.protocol==17 )
			&& ((r->dhcp.id & 0xffff ) == 0xfeca)
			&& (memcmp(r->dhcp.addr, oui,3)==0)) {
			unsigned char found = r->dhcp.addr[5];

			switch(session[found].state) {
			case SESS_DISCOVER:
				gettimeofday(&session[found].tv_offer, NULL);
				if((rc = send_packet(packet_socket, session+found, 3))>0) {
					gettimeofday(&session[found].tv_request, NULL);
					memcpy(&session[found].client_ip_addr, &r->dhcp.ip_your, 4);
					memcpy(&session[found].server_ip_addr, &r->ip.saddr, 4);
					memcpy(session[found].client_mac_addr, r->dhcp.addr, ETH_ALEN);
					memcpy(session[found].server_mac_addr, r->eth.ether_shost, ETH_ALEN);
					report_state(session+found);	
					session[found].state = SESS_REQUEST;
				} else {
					printf("Error sending REQUEST to client %d\n", found);
					sessions_pending--;
					sessions_available++;
					session[found].state = SESS_DONE;
				}
		
				break;
			case SESS_REQUEST:
				sessions_pending--;
				sessions_available++;
				gettimeofday(&session[found].tv_ack, NULL);
				report_state(session+found);	
				session[found].state = SESS_DONE;
				break;
			}
		}
		//	dump_packet(rcv_buf, rcnt);
	} else {
		perror("recvfrom");
	}	

	close(packet_socket);


}

int main(int argc, char **argv) {

	int            rc, ch, ndx;
	ssize_t        rcnt;
	struct timeval tv_now, tv_gate = {0,0};  	

	/* options descriptor */
	static struct option longopts[] = {
		{ "help",       no_argument,            NULL,           'h' },
		{ "debug",      no_argument,            NULL,           'h' },
		{ "quiet",      no_argument,            NULL,           'q' },
		{ "wait",       required_argument,      NULL,           'w' },
		{ "max",        required_argument,      NULL,           'm' },
		{ "timeout",    required_argument,      NULL,           't' },
		{ "concurrent", required_argument,      NULL,           'j' },
		{ "interface",  required_argument,      NULL,           'i' },
		{ NULL,         0,                      NULL,           0 }
	};

	while ((ch = getopt_long(argc, argv, "hdqi:j:m:t:w:", longopts, NULL)) != -1)
		switch (ch) {
		case 'q':
			opt_quiet=1;
			break;
		case 'd':
			opt_debug=1;
			break;
		case 'j':
			opt_concurrent = strtoul(optarg, NULL, 10);
			break;
		case 't':
			opt_timeout = strtoul(optarg, NULL, 10);
			break;
		case 'm':
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
	

	return 0;
}


