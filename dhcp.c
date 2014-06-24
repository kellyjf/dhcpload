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
#include <assert.h>

#include "queue.h"
#include "pool.h"
#include "util.h"
#include "log.h"

unsigned int   opt_max        = 1;
unsigned int   opt_timeout    = 10;
unsigned int   opt_wait       = 1;
unsigned int   opt_debug      = 0;
unsigned int   opt_quiet      = 0;
unsigned int   opt_concurrent = 5;
char          *opt_ifname     = "eth0";

unsigned char    bcast [ ETH_ALEN ];
unsigned char    oui [ ETH_ALEN ];

LIST_HEAD(session_list);
pthread_mutex_t  session_mutex  =  PTHREAD_MUTEX_INITIALIZER;

int              raw_socket;
pthread_mutex_t  socket_mutex   =  PTHREAD_MUTEX_INITIALIZER;

msg_queue_t     *manager_queue;
pool_t          *rcv_pool;

void usage(char *progname) {
	printf("Usage:  %s [options]\n", progname);
	printf("\t-i|--interface name     Interface                         (using: %s)\n", opt_ifname);
	printf("\t-m|--max #reqs          Total requests to generate        (using: %d)\n", opt_max);
	printf("\t-t|--timeout #          Num timeouts before quit          (using: %d)\n", opt_timeout);
	printf("\t-w|--wait  #sec/req     Rate limit # request per interval (using: %d)\n", opt_wait);
	printf("\t-j|--concurrent num     Number of concurrent requests     (using: %d)\n", opt_concurrent);
	printf("\t-d|--debug              Turn on debugging\n");
	printf("\t-q|--quiet              Suppress status reporting\n");
	printf("\t-h|--help               Help (this message)\n");
}


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

typedef struct {
	pthread_t         thread;
	session_state_t   state;
	struct list_head  list;
	msg_queue_t      *thread_queue;
	msg_queue_t      *manager_queue;
	unsigned char     client_mac[ETH_ALEN];	
	unsigned char     server_mac[ETH_ALEN];	
	unsigned int      client_ip;
	unsigned int      server_ip;
	union {
		unsigned char snd_buf[384];
		dhcp_t        dhcp;
	}                 buf;
} session_t;


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

	if(opt_debug) log_printf("Interface %s Index is %d\n", name, ifr.ifr_ifindex);
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

ssize_t send_packet(session_t *sess, int type) {
	dhcp_t                 *p;
	dhcp_t                 *r;
	static unsigned short  idnum = 0x66;
	ssize_t                len;
	ssize_t                ndx;
	ssize_t                ret;
		
	p = (dhcp_t  *) &sess->buf.dhcp;
	memset(p, 0, sizeof(sess->buf));

	memset(&p->eth.ether_dhost, 0xff, ETH_ALEN);
	memcpy(p->eth.ether_shost, sess->client_mac, ETH_ALEN);
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
	p->dhcp.id = 0xFECA + (sess->client_mac[5]<<16) + (type<<24);
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

	pthread_mutex_lock(&socket_mutex);
	ret = write(raw_socket, p, len);
	pthread_mutex_unlock(&socket_mutex);

	return ret;
}

void report_state(session_t *sess) {

	unsigned         epoch = 0 , svc;
	char            *sessname = "UNK";
	struct timeval   tv;
	
	if(opt_quiet) return;
	gettimeofday(&tv, NULL);

	switch(sess->state) { 
	case SESS_DISCOVER: 
		sessname="DISCOVER"; 
		break;
	case SESS_REQUEST:
		sessname="REQUEST";
		break;
	default:
		log_printf("STATE IS %d Index %p\n", sess->state, sess);
		break;
	}
	
	epoch = tv.tv_sec;
	log_printf("%06d %2d %10.10s %5d %02X:%02X:%02X:%02X:%02X:%02X %d.%d.%d.%d\n", 
		epoch%1000000,
		sess->client_mac[5],
		sessname,
		0, //svc,
		sess->client_mac[0],
		sess->client_mac[1],
		sess->client_mac[2],
		sess->client_mac[3],
		sess->client_mac[4],
		sess->client_mac[5],
		(sess->client_ip & 0xff),
		(sess->client_ip>>8 & 0xff),
		(sess->client_ip>>16 & 0xff),
		(sess->client_ip>>24 & 0xff)
	);
}	

void *dhcp_client_thread(void *user) {
	session_t       *session   = user;
	msg_t           *msg;
	dhcp_t          *r;
	struct timeval   delay = { 1, 0 };
	int              tcnt = 0;

	log_printf("%s started session  %2d @ %p\n", __func__, session->client_mac[5],session);

	while(session->state != SESS_DONE) {
		msg = msg_queue_get(session->thread_queue, &delay);

		if(opt_debug) {
			log_printf("msg from %p for %2d: %p\n",
				session->thread_queue, session->client_mac[5], msg);
		}
		
		if(msg==NULL) {
			session->state = SESS_START;
			if(delay.tv_sec < 16) delay.tv_sec *= 2;
			if(opt_debug) 
				log_printf("timeout %2d on %d @ %p\n",  
					tcnt, session->client_mac[5],session);
			if(tcnt++ > opt_timeout) {
				session->state = SESS_DONE;
			}
			continue;
		} 

		switch(session->state) {
		case SESS_START:
			session->state = SESS_DISCOVER;
			send_packet(session, 1);
			report_state(session);
			break;
		case SESS_DISCOVER:
			assert(msg);
			r = (dhcp_t *)msg->data;
			memcpy(&session->client_ip, &r->dhcp.ip_your, 4);
			memcpy(&session->server_ip, &r->ip.saddr, 4);
			memcpy(session->client_mac, r->dhcp.addr, ETH_ALEN);
			memcpy(session->server_mac, r->eth.ether_shost, ETH_ALEN);
			send_packet(session, 3);
			session->state = SESS_REQUEST;
			report_state(session);
			break;
		case SESS_REQUEST:
			session->state =  SESS_DONE;
			report_state(session);
			break;
		}
		if(msg) {
			pool_free(rcv_pool, msg->data);
			msg_queue_put(session->thread_queue, msg);
		}
	}	


	msg_queue_send(session->manager_queue, session);
	return session;
}


session_t *dhcp_session_for_packet(dhcp_t *packet) {

	session_t  *sess = NULL;

	pthread_mutex_lock(&session_mutex);
	list_for_each_entry(sess, &session_list, list) {
		if(memcmp(sess->client_mac, packet->dhcp.addr, ETH_ALEN)==0) {
			break;
		}
	}	
	pthread_mutex_unlock(&session_mutex);
	return sess;
}

void *dhcp_recv_thread(void *user) {
	session_t       *session   = user;
	dhcp_t          *r;
	ssize_t          rcnt;
	sll_t            sll;
	socklen_t        slen;

	log_printf("%s started\n", __func__);

	r = (dhcp_t *)pool_alloc(rcv_pool);
	
	memset(r, 0, pool_slabsize(rcv_pool) ); 
	memset(&sll, 0, sizeof(sll_t));  slen=sizeof(sll_t);

	if((rcnt=recvfrom(raw_socket, r, pool_slabsize(rcv_pool), 0,
		(sa_t*)&sll, &slen))>0) {
		
		
		if( (memcmp(r->eth.ether_dhost, bcast, ETH_ALEN)==0) 
			&& (r->ip.protocol==17 )
			&& ((r->dhcp.id & 0xffff ) == 0xfeca)
			&& (memcmp(r->dhcp.addr, oui,3)==0)) {

			session_t  *sess;

			if(sess = dhcp_session_for_packet(r)) {
				msg_queue_send(sess->thread_queue, r);
				r = (dhcp_t *)pool_alloc(rcv_pool);
			}
		}
		//	dump_packet(rcv_buf, rcnt);
	} else {
		perror("recvfrom");
	}	



}

void start_thread(int i) {
		session_t  *sess;

		sess = calloc(1, sizeof(*sess));
		memcpy(sess->client_mac, oui, sizeof(oui));
		sess->client_mac[5] = i;
		sess->state = SESS_START;
		sess->thread_queue = msg_queue_new();
		sess->manager_queue = manager_queue;
		pthread_create(&sess->thread, NULL, dhcp_client_thread, sess);

}

#ifndef TEST
int main(int argc, char **argv) {

	int            rc, ch, ndx, cnt;
	ssize_t        rcnt;
	struct timeval tv_now, tv_gate = {0,0};  	
	pthread_t       rcv_thread;

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

	memset(bcast, 0xff, sizeof(bcast) ); 
	memset(oui,   0xcc, sizeof(oui) ); 

	log_init();
	rcv_pool = pool_new(8, 2048);	
	manager_queue  = msg_queue_new();

	raw_socket = socket(AF_PACKET, SOCK_RAW, htons(ETHERTYPE_IP));

	if(raw_socket<0) {
		perror("SOCK_RAW requires root permissions");
		exit(1);
	}

	if((rc = bind_interface(raw_socket, opt_ifname))<0) {
		return -1;
	}



	pthread_create(&rcv_thread, NULL, dhcp_recv_thread, NULL);

	for(cnt=0, ndx=0; ndx<opt_max; ) {
		if(cnt<opt_concurrent) {	
			start_thread(ndx);
			sleep(opt_wait);
			cnt++;
			ndx++;
		} else  {
			msg_t     *msg   = msg_queue_get(manager_queue, NULL);
			session_t *t     = msg->data;
			void      *status;
			cnt--;
			pthread_join(t->thread, &status);
			log_printf("join %2d @ %p/%p\n", t->client_mac[5], t, (session_t*)status);
			assert((session_t *)status==t);
		}
	}
	while(cnt>0) {
		msg_t     *msg   = msg_queue_get(manager_queue, NULL);
		session_t *t     = msg->data;
		void      *status;
		pthread_join(t->thread, &status);
		assert(status==t);
		cnt--;
		log_printf("join %2d @ %p/%p\n", t->client_mac[5], t, status);
	}
	close(raw_socket);
	return 0;
}

#endif
