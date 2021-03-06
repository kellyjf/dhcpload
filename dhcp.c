#include <stdio.h>
#include <fcntl.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <signal.h>

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


struct {
	unsigned int   opt_start;
	unsigned int   opt_max;
	unsigned int   opt_timeout;
	unsigned int   opt_wait;
	unsigned int   opt_debug;
	unsigned int   opt_quiet;
	unsigned int   opt_renew;
	unsigned int   opt_renewtime;
	unsigned int   opt_concurrent;
	char          *opt_ifname;
	char          *opt_cachefile;

	unsigned char    bcast [ ETH_ALEN ];
	unsigned char    oui [ ETH_ALEN ];
	unsigned int     ipcache[256];

	pthread_mutex_t  session_mutex;

	int              raw_socket;
	pthread_mutex_t  socket_mutex;

	msg_queue_t     *manager_queue;
	pool_t          *rcv_pool;
} module = {
	.opt_start      = 0,
	.opt_max        = 1,
	.opt_timeout    = 10,
	.opt_wait       = 1,
	.opt_debug      = 0,
	.opt_quiet      = 0,
	.opt_renew      = 0,
	.opt_renewtime  = 30,
	.opt_concurrent = 5,
	.opt_ifname     = "eth0",
	.session_mutex  =  PTHREAD_MUTEX_INITIALIZER,
	.socket_mutex   =  PTHREAD_MUTEX_INITIALIZER,
};
LIST_HEAD(session_list);

void usage(char *progname) {
	printf("Usage:  %s [options]\n", progname);
	printf("\t-i|--interface name     Interface                         (using: %s)\n", module.opt_ifname);
	printf("\t-s|--start #val         Starting req number               (using: %d)\n", module.opt_start);
	printf("\t-m|--max #reqs          Total requests to generate        (using: %d)\n", module.opt_max);
	printf("\t-t|--timeout #          Num timeouts before quit          (using: %d)\n", module.opt_timeout);
	printf("\t-w|--wait  #sec/req     Rate limit # request per interval (using: %d)\n", module.opt_wait);
	printf("\t-j|--concurrent num     Number of concurrent requests     (using: %d)\n", module.opt_concurrent);
	printf("\t-c|--cachefile file     Name of reuse file\n");
	printf("\t-r|--renew cnt          Number of times to renew          (using: %d)\n", module.opt_renew);
	printf("\t-R|--renewtime sec      Seconds between renewals          (using: %d)\n", module.opt_renewtime);
	printf("\t-d|--debug              Turn on debugging\n");
	printf("\t-q|--quiet              Suppress status reporting\n");
	printf("\t-h|--help               Help (this message)\n");
}

typedef struct sockaddr_ll sll_t;
typedef struct sockaddr    sa_t;
typedef unsigned short     us_t;

typedef enum {
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
} dhcp_option_t;

typedef enum {
	DHCP_TYPE_DISCOVER = 1,	
	DHCP_TYPE_REQUEST  = 3,	
} dhcp_type_t;
	

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

typedef enum {
	SESS_START, 
	SESS_DISCOVER, 
	SESS_REQUEST, 
	SESS_DONE
} session_state_t;

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
	unsigned char     name[16];	
	int               cnt_renew;
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

	if(module.opt_debug) log_printf("Interface %s Index is %d\n", name, ifr.ifr_ifindex);
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

ssize_t send_packet(session_t *sess, dhcp_type_t type) {
	dhcp_t                 *p;
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
	p->dhcp.id = 0xFECA + (sess->client_mac[5]<<16) + (type<<24) + ((sess->cnt_renew%16)<<28);
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
		memcpy(&p->dhcp.options[ndx], sess->client_mac, ETH_ALEN);
		ndx += ETH_ALEN;

		p->dhcp.options[ndx++] = DHCP_OPTION_REQUESTED_IP;
		p->dhcp.options[ndx++] = 0x04;
		memcpy(&p->dhcp.options[ndx], &sess->client_ip, 4);
		ndx += 4;

		p->dhcp.options[ndx++] = DHCP_OPTION_HOSTNAME;
		p->dhcp.options[ndx++] = strlen(sess->name);
		memcpy(&p->dhcp.options[ndx], sess->name, strlen(sess->name));
		ndx += strlen(sess->name);
		
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

	pthread_mutex_lock(&module.socket_mutex);
	if(module.opt_debug) log_printf("Writing %d bytes to socket %d\n", len, module.raw_socket);
	ret = write(module.raw_socket, p, len);
	pthread_mutex_unlock(&module.socket_mutex);

	return ret;
}

void report_state(session_t *sess) {

	unsigned         epoch = 0 , svc;
	char            *statename = "UNKNOWN";
	char            *sessname = "";
	struct timeval   tv;
	
	if(module.opt_quiet) return;
	gettimeofday(&tv, NULL);

	switch(sess->state) { 
	case SESS_DISCOVER: 
		statename="DISCOVER"; 
		break;
	case SESS_REQUEST:
		statename="OFFREQ";
		sessname = sess->name;
		break;
	case SESS_DONE:
		statename="ACK";
		sessname = sess->name;
		break;
	default:
		log_printf("STATE IS %d Index %p\n", sess->state, sess);
		break;
	}
	
	epoch = tv.tv_sec;
	log_printf("%06d.%06d  %02X:%02X:%02X:%02X:%02X:%02X   %-10.10s  %03d.%03d.%03d.%03d  %-12.12s\n", 
		epoch%1000000, tv.tv_usec,
		sess->client_mac[0],
		sess->client_mac[1],
		sess->client_mac[2],
		sess->client_mac[3],
		sess->client_mac[4],
		sess->client_mac[5],
		statename,
		(sess->client_ip & 0xff),
		(sess->client_ip>>8 & 0xff),
		(sess->client_ip>>16 & 0xff),
		(sess->client_ip>>24 & 0xff),
		sessname
	);
}	

void *dhcp_client_thread(void *user) {
	session_t       *session   = user;
	msg_t           *msg;
	dhcp_t          *r;
	struct timeval   delay = { 1, 0 };
	int              tcnt = 0;

	if(module.opt_debug) log_printf("%s started session  %2d @ %p\n", __func__, session->client_mac[5],session);

	while(session->state != SESS_DONE) {
		if(module.opt_debug) log_printf("Looping state %d\n", session->state);
		switch(session->state) {
		case SESS_START:
			session->client_ip = module.ipcache[session->client_mac[5]];
			if(session->client_ip) {
	if(module.opt_debug) log_printf("%s cache value for  %2d is  %08x\n", __func__, session->client_mac[5],module.ipcache[session->client_mac[5]]);
				send_packet(session, DHCP_TYPE_REQUEST);
				session->state = SESS_REQUEST;
			} else {
				send_packet(session, DHCP_TYPE_DISCOVER);
				session->state = SESS_DISCOVER;
			}
			report_state(session);
			break;
		default:
			break;
		}
		msg = msg_queue_get(session->thread_queue, &delay);

		if(module.opt_debug) {
			log_printf("msg from %p for %2d: %p\n",
				session->thread_queue, session->client_mac[5], msg);
		}
		
		if(msg==NULL) {
			session->state = SESS_START;
			if(delay.tv_sec < 16) delay.tv_sec *= 2;
			if(module.opt_debug) 
				log_printf("timeout %2d on %d @ %p\n",  
					tcnt, session->client_mac[5],session);
			if(++tcnt > module.opt_timeout) {
				session->state = SESS_DONE;
			}
			continue;
		} 

		switch(session->state) {
		case SESS_START:
			session->state = SESS_DISCOVER;
			send_packet(session, DHCP_TYPE_DISCOVER);
			report_state(session);
			break;
		case SESS_DISCOVER:
			assert(msg);
			r = (dhcp_t *)msg->data;
			memcpy(&session->client_ip, &r->dhcp.ip_your, sizeof(session->client_ip));
			memcpy(&session->server_ip, &r->ip.saddr, sizeof(session->server_ip));
			memcpy(session->client_mac, r->dhcp.addr, ETH_ALEN);
			memcpy(session->server_mac, r->eth.ether_shost, ETH_ALEN);
			send_packet(session, DHCP_TYPE_REQUEST);
			session->state = SESS_REQUEST;
			module.ipcache[session->client_mac[5]] = session->server_ip;
			report_state(session);
			break;
		case SESS_REQUEST:
			if(session->cnt_renew-- > 0 ) {
				session->state =  SESS_DONE;
				report_state(session);
				sleep(module.opt_renewtime);
				session->state =  SESS_REQUEST;
				send_packet(session, DHCP_TYPE_REQUEST);
			} else {
				session->state =  SESS_DONE;
			}
			report_state(session);
			break;
		}
		if(msg) {
			pool_free(module.rcv_pool, msg->data);
			msg_queue_put(session->thread_queue, msg);
		}
	}	


	msg_queue_send(session->manager_queue, session);
	return session;
}


session_t *dhcp_session_for_packet(dhcp_t *packet) {

	session_t  *sess = NULL;

	pthread_mutex_lock(&module.session_mutex);
	list_for_each_entry(sess, &session_list, list) {
		if(module.opt_debug) log_printf("%s %08x %08x\n", __func__, sess->client_mac, packet->dhcp.addr) ;
		if(memcmp(sess->client_mac, packet->dhcp.addr, ETH_ALEN)==0) {
			break;
		}
	}	
	pthread_mutex_unlock(&module.session_mutex);
	return sess;
}

void *dhcp_recv_thread(void *user) {
	session_t       *session   = user;
	dhcp_t          *r;
	ssize_t          rcnt = 0;
	sll_t            sll;
	socklen_t        slen;

	if(module.opt_debug) log_printf("%s started\n", __func__);

	r = (dhcp_t *)pool_alloc(module.rcv_pool);
	
	while(rcnt>=0) {
		memset(r, 0, pool_slabsize(module.rcv_pool) ); 
		memset(&sll, 0, sizeof(sll_t));  slen=sizeof(sll_t);

		if((rcnt=recvfrom(module.raw_socket, r, pool_slabsize(module.rcv_pool), 0,
			(sa_t*)&sll, &slen))>0) {
			
			if(module.opt_debug) log_printf("packet %d recieved\n", rcnt);
			 
			if( 
				/* If dst mac is broadcast or unicast to one of our ilk */
				((memcmp(r->eth.ether_dhost, module.bcast, ETH_ALEN)==0) ||
				(memcmp(r->eth.ether_dhost, module.oui, 3)==0))

				/* And UDP */
				&& (r->ip.protocol==17 )

				/* And has one of our IDs */
				&& ((r->dhcp.id & 0xffff ) == 0xfeca)

				/* And has our OUI internally */
				&& (memcmp(r->dhcp.addr, module.oui,3)==0)) {


				/* Then we will act on it */
				session_t  *sess;

				if(sess = dhcp_session_for_packet(r)) {
					if(module.opt_debug) log_printf("Sending packet to %d\n", sess->client_mac[5]);
					msg_queue_send(sess->thread_queue, r);
					r = (dhcp_t *)pool_alloc(module.rcv_pool);
				}
				if(module.opt_debug) log_printf("packet is %p\n", sess);
			}
		} else {
			perror("recvfrom");
		}	
	}	
	return NULL;
}

void start_thread(int i) {
		session_t  *sess;

		sess = calloc(1, sizeof(*sess));
		memcpy(sess->client_mac, module.oui, sizeof(module.oui));
		sess->client_mac[5] = i;
		sess->state = SESS_START;
		sess->thread_queue = msg_queue_new();
		sess->manager_queue = module.manager_queue;
		sess->cnt_renew = module.opt_renew;
		snprintf(sess->name, sizeof(sess->name), "dhcpload-%03d", i);
		pthread_create(&sess->thread, NULL, dhcp_client_thread, sess);
		pthread_mutex_lock(&module.session_mutex);
		list_add(&sess->list, &session_list);
		pthread_mutex_unlock(&module.session_mutex);

}

void end_thread(session_t *t) {
	void      *status;
	msg_t     *msg;

	pthread_join(t->thread, &status);
	pthread_mutex_lock(&module.session_mutex);
	list_del(&t->list);
	pthread_mutex_unlock(&module.session_mutex);
	while(!list_empty(&t->thread_queue->list)) {
		msg = msg_queue_get(t->thread_queue, NULL);
		pool_free(module.rcv_pool, msg->data);
		msg_queue_put(t->thread_queue, msg);
	}
	msg_queue_free(t->thread_queue);
	assert(status==t);
	if(module.opt_debug) log_printf("join %2d @ %p/%p\n", t->client_mac[5], t, status);
}

void parsecache(char *cachefile) {
	unsigned char buffer[256];
	FILE *fp = fopen(cachefile, "r");

	if(fp==NULL) return;
	if(module.opt_debug) log_printf("%s parsing cache file %s\n", __func__, cachefile);

	while(fgets(buffer, sizeof(buffer), fp)) {
		int           rc;
		unsigned long tsec, tusec;
		unsigned char octet[2], type[32], ipname[32];
		unsigned int  ipaddr;

		if(5==(rc=sscanf(buffer, "%lu.%lu CC:CC:CC:CC:CC:%2s %s %s", &tsec, &tusec, octet, type, ipname))) {
			if(strncmp(type, "ACK", 3)==0) {
				unsigned char lastoct;
				unsigned char *cip;
				lastoct = strtoul(octet, NULL, 16);
				cip = (unsigned char *)&ipaddr;
				sscanf(ipname, "%hhu.%hhu.%hhu.%hhu", cip, cip+1, cip+2, cip+3); 
				module.ipcache[lastoct] = ipaddr;
	if(module.opt_debug) log_printf("%s cache entry %d -> %08x\n", __func__, lastoct, ipaddr);

			}

		}
	}
	fclose(fp);
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
		{ "debug",      no_argument,            NULL,           'd' },
		{ "quiet",      no_argument,            NULL,           'q' },
		{ "wait",       required_argument,      NULL,           'w' },
		{ "max",        required_argument,      NULL,           'm' },
		{ "start",      required_argument,      NULL,           's' },
		{ "timeout",    required_argument,      NULL,           't' },
		{ "concurrent", required_argument,      NULL,           'j' },
		{ "cachefile",  required_argument,      NULL,           'c' },
		{ "renew",      required_argument,      NULL,           'r' },
		{ "renewtime",  required_argument,      NULL,           'R' },
		{ "interface",  required_argument,      NULL,           'i' },
		{ NULL,         0,                      NULL,           0 }
	};

	while ((ch = getopt_long(argc, argv, "hdqi:j:s:m:t:w:c:r:R:", longopts, NULL)) != -1)
		switch (ch) {
		case 'q':
			module.opt_quiet=1;
			break;
		case 'd':
			module.opt_debug=1;
			break;
		case 'j':
			module.opt_concurrent = strtoul(optarg, NULL, 10);
			break;
		case 't':
			module.opt_timeout = strtoul(optarg, NULL, 10);
			break;
		case 'm':
			module.opt_max = strtoul(optarg, NULL, 10);
			break;
		case 's':
			module.opt_start = strtoul(optarg, NULL, 10);
			break;
		case 'w':
			module.opt_wait = strtoul(optarg, NULL, 10);
			break;
		case 'c':
			module.opt_cachefile = optarg;
			break;
		case 'i':
			module.opt_ifname = optarg;
			break;
		case 'r':
			module.opt_renew = strtoul(optarg, NULL, 10);
			break;
		case 'R':
			module.opt_renewtime = strtoul(optarg, NULL, 10);
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

	memset(module.bcast, 0xff, sizeof(module.bcast) ); 
	memset(module.oui,   0xcc, sizeof(module.oui) ); 

	log_init();
	module.rcv_pool = pool_new(8, 2048);	
	module.manager_queue  = msg_queue_new();

	if(module.opt_cachefile) parsecache(module.opt_cachefile);

	module.raw_socket = socket(AF_PACKET, SOCK_RAW, htons(ETHERTYPE_IP));

	if(module.raw_socket<0) {
		perror("SOCK_RAW requires root permissions");
		exit(1);
	}

	if((rc = bind_interface(module.raw_socket, module.opt_ifname))<0) {
		return -1;
	}



	pthread_create(&rcv_thread, NULL, dhcp_recv_thread, NULL);

	for(cnt=0, ndx=module.opt_start; ndx<module.opt_start+module.opt_max; ) {
		if(cnt<module.opt_concurrent) {	
			start_thread(ndx);
			if(module.opt_wait) sleep(module.opt_wait);
			ndx++;
			cnt++;
		} else  {
			msg_t     *msg   = msg_queue_get(module.manager_queue, NULL);
			session_t *t     = msg->data;
			end_thread(t);
			cnt--;
		}
	}
	while(cnt>0) {
		msg_t     *msg   = msg_queue_get(module.manager_queue, NULL);
		session_t *t     = msg->data;
		end_thread(t);
		cnt--;
	}
	pthread_kill(rcv_thread, 19);
	close(module.raw_socket);
	return 0;
}

#endif
