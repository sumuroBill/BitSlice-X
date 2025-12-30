#include <stdio.h>
#include <time.h>
#include <openssl/evp.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <inttypes.h>
#include <sys/types.h>
#include <sys/queue.h>
#include <netinet/in.h> 
#include <setjmp.h>
#include <stdarg.h>
#include <ctype.h>
#include <errno.h>
#include <getopt.h>
#include <signal.h>
#include <stdbool.h> 
#include <openssl/crypto.h>

#include <rte_common.h>
#include <rte_log.h>
#include <rte_malloc.h>
#include <rte_memory.h>
#include <rte_memcpy.h>
#include <rte_memzone.h> 
#include <rte_eal.h>
#include <rte_launch.h>
#include <rte_atomic.h> 
#include <rte_cycles.h>
#include <rte_prefetch.h>
#include <rte_lcore.h>
#include <rte_per_lcore.h>
#include <rte_branch_prediction.h>
#include <rte_interrupts.h>
#include <rte_pci.h> 
#include <rte_random.h>
#include <rte_debug.h>
#include <rte_ether.h>
#include <rte_ethdev.h>
#include <rte_mempool.h>
#include <rte_mbuf.h>
#include <chrono>  
#include <rte_ip.h>  
#include <netinet/in.h>  
#include <arpa/inet.h>  

#include <openssl/engine.h>

/******************************Custom packages and variables*****************************/
#include "process.h" 

#include <pthread.h>

using namespace chrono;  


bool packetloss_flag = false;
bool retrans_flag = false;
int packetloss_router = 0;
int pick = 0;
uint64_t min_time;

unsigned long long tick_sample1;
unsigned long long tick_sample2;
double time_sample = 0;

unsigned long long tick;
unsigned long long tick0;
unsigned long long tick2;
double time_throughput = 0;
unsigned long long tick_init1;
unsigned long long tick_init2;
double time_init = 0;
unsigned long long tick_con1;
unsigned long long tick_con2;
double time_con = 0;
unsigned long long tick_ve1;
unsigned long long tick_ve2;
double time_ve = 0;

unsigned long long tick00;
unsigned long long tick01;
double time_throughput0 = 0;

unsigned long long tick40;
unsigned long long tick41;
double time_throughput4 = 0;

unsigned long long tick80;
unsigned long long tick81;
double time_throughput8 = 0;

unsigned long long tick120;
unsigned long long tick121;
double time_throughput12 = 0;

uint8_t pktseq = 0;
uint64_t global_groupID = 0; 
int packetCount = 0; 
/******************************Custom packages and variables*****************************/

static volatile bool force_quit;

/* MAC updating enabled by default */
static int mac_updating = 1;

/* sth definition about append to the mbuf*/
#define APPEND_ERROR -1  //new
#define APPEND_SUCCESS 1  //new
#define FAIL_STORE -5  //new
#define SUCCESS_STORE 5  //new

#define RTE_LOGTYPE_L2FWD RTE_LOGTYPE_USER1

#define NB_MBUF   65536 //new
#define MAX_PKT_BURST 32
#define BURST_TX_DRAIN_US 100 /* TX drain every ~100us */
#define MEMPOOL_CACHE_SIZE 256 //512

#define DATA_SIZE (100 * 1024 * 1024) // 10MB

/*new*/
struct timespec t1={0,0};
struct timespec t2={0,0};
double temp_time;
bool ifstart = false;

struct timespec t10={0,0};
struct timespec t20={0,0};
double temp_time0;
bool ifstart0 = false;

struct timespec t14={0,0};
struct timespec t24={0,0};
double temp_time4;
bool ifstart4 = false;

struct timespec t18={0,0};
struct timespec t28={0,0};
double temp_time8;
bool ifstart8 = false;

struct timespec t112={0,0};
struct timespec t212={0,0};
double temp_time12;
bool ifstart12 = false;
/*new*/

/*
 * Configurable number of RX/TX ring descriptors
 */
#define RTE_TEST_RX_DESC_DEFAULT 256 
#define RTE_TEST_TX_DESC_DEFAULT 512 
static uint16_t nb_rxd = RTE_TEST_RX_DESC_DEFAULT;
static uint16_t nb_txd = RTE_TEST_TX_DESC_DEFAULT;

int packet_number[RTE_MAX_ETHPORTS] = {0}; //new 

/* ethernet addresses of ports */
static struct ether_addr l2fwd_ports_eth_addr[RTE_MAX_ETHPORTS];

/* mask of enabled ports */
static uint32_t l2fwd_enabled_port_mask = 0;
uint8_t nb_enabled_port = 0; //new

static uint32_t l2fwd_dst_ports[RTE_MAX_ETHPORTS];

Signer* signers[RTE_MAX_ETHPORTS]; //new
static unsigned int l2fwd_rx_queue_per_lcore = 1;

#define MAX_RX_QUEUE_PER_LCORE 16
#define MAX_TX_QUEUE_PER_PORT 16
struct lcore_queue_conf {
	unsigned n_rx_port;
	unsigned rx_port_list[MAX_RX_QUEUE_PER_LCORE];
} __rte_cache_aligned;
struct lcore_queue_conf lcore_queue_conf[RTE_MAX_LCORE];

static struct rte_eth_dev_tx_buffer *tx_buffer[RTE_MAX_ETHPORTS];


/*
 * RX and TX Prefetch, Host, and Write-back threshold values should be
 * carefully set for optimal performance. Consult the network
 * controller's datasheet and supporting DPDK documentation for guidance
 * on how these parameters should be set.
 */
/*new*/
#define RX_PTHRESH 			8 /**< Default values of RX prefetch threshold reg. */
#define RX_HTHRESH 			8 /**< Default values of RX host threshold reg. */
#define RX_WTHRESH 			4 /**< Default values of RX write-back threshold reg. */

/*
 * These default values are optimized for use with the Intel(R) 82599 10 GbE
 * Controller and the DPDK ixgbe PMD. Consider using other values for other
 * network controllers and/or network drivers.
 */
/*new*/
#define TX_PTHRESH 			36 /**< Default values of TX prefetch threshold reg. */
#define TX_HTHRESH			0  /**< Default values of TX host threshold reg. */
#define TX_WTHRESH			0  /**< Default values of TX write-back threshold reg. */


/*A static rte_eth_conf struct is defined to configure the behavior of Ethernet device (network card) ports in the DPDK*/ 
static const struct rte_eth_conf port_conf = {
	.link_speeds = ETH_LINK_SPEED_FIXED, // Fixed link speed
	.rxmode = {
		.mq_mode = ETH_MQ_RX_NONE,  
		.max_rx_pkt_len = 0,  
		.split_hdr_size = 0,  
	},
	.txmode = {
		.mq_mode = ETH_MQ_TX_NONE,   
	},
};


/*rx configure This code defines two structs, rte_eth_rxconf and rte_eth_txconf, which are used to configure the behavior of the receive (RX) and send (TX) queues, respectively */
static const struct rte_eth_rxconf rx_conf = {
	.rx_thresh = {
		.pthresh = 		RX_PTHRESH, /* RX prefetch threshold reg */
		.hthresh = 		RX_HTHRESH, /* RX host threshold reg */
		.wthresh = 		RX_WTHRESH, /* RX write-back threshold reg */
	},
	.rx_free_thresh = 	    32,
};
/* tx configure */
static const struct rte_eth_txconf tx_conf = {
	.tx_thresh = {
		.pthresh = 		TX_PTHRESH, /* TX prefetch threshold reg */
		.hthresh = 		TX_HTHRESH, /* TX host threshold reg */
		.wthresh = 		TX_WTHRESH, /* TX write-back threshold reg */
	},
	.tx_rs_thresh = 		0, /* Use PMD default values */
};

struct rte_mempool * l2fwd_pktmbuf_pool = NULL;

/* Per-port statistics struct */
struct l2fwd_port_statistics {
	uint64_t tx;
	uint64_t rx;
	uint64_t dropped;
} __rte_cache_aligned;
struct l2fwd_port_statistics port_statistics[RTE_MAX_ETHPORTS];

uint32_t s_portid, d_portid; //new


#define MAX_TIMER_PERIOD 86400 /* 1 day max */
/* A tsc-based timer responsible for triggering statistics printout */
static uint64_t timer_period = 10; /* default period is 10 seconds */


/*Appends an array of uint64_t, uint32_t, uint8_t, and uint8_t types to the tail of a rte_mbuf packet and returns the result of the operation*/
static int append_data(struct rte_mbuf *m, const void *data, size_t len) {
    int remain_room = rte_pktmbuf_tailroom(m); // Check if the remaining tail space is sufficient
    if (remain_room < (int)len) {
        return APPEND_ERROR;
    }
    void *tail = rte_pktmbuf_append(m, len); // append data
    if (!tail) {
        return APPEND_ERROR;
    }
    rte_memcpy(tail, data, len);// copy data to mbuf tail
    return APPEND_SUCCESS;
}
static int append_uint8(struct rte_mbuf *m, uint8_t value) {
    return append_data(m, &value, sizeof(uint8_t));
}
static int append_uint32(struct rte_mbuf *m, uint32_t value) {
    return append_data(m, &value, sizeof(uint32_t));
}
static int append_uint64(struct rte_mbuf *m, uint64_t value) {
    return append_data(m, &value, sizeof(uint64_t));
}
static int append_array(struct rte_mbuf *m, const uint8_t *array, size_t len) {
    return append_data(m, array, len);
}
/*Append a byte to the tail of a rte_mbuf packet and return the result of the operation*/
static int append_byte(struct rte_mbuf* m,char b)
{
    int remain_room = rte_pktmbuf_tailroom(m);
    if(remain_room <= 0){
        return APPEND_ERROR;
    }
    char* tail = rte_pktmbuf_append(m,1);
    tail[0] = b & 0xFF;
    return APPEND_SUCCESS;
}
/*Append multiple bytes to the tail of a rte_mbuf packet and return the result of the operation*/
static int append_bytes(struct rte_mbuf* m, unsigned char* b, int size)
{
    
    int remain_room = rte_pktmbuf_tailroom(m);
    if(remain_room <= size ){
        printf("Not enough space for this mbuf to insert %d bytes!\n\n\n\n\n\n",size);
		return APPEND_ERROR;
    }
    unsigned char* tail = (unsigned char*)rte_pktmbuf_append(m,size);
    int i = 0;
    for(i = 0; i < size; i++){
        tail[i] = b[i];
    }
    return size;
}

/*Packages and stores data in the DataPackage structure into the DPDK's rte_mbuf data structure*/

static int Store_DataPackage(struct rte_mbuf* m, DataPackage * datapackage)
{
	int ret = 0;
	ret = append_uint8(m, datapackage -> PVhd.hd_length);
	ret = append_uint64(m, datapackage -> PVhd.group_ID);
	// printf("store pktID group_ID = %d\n", (datapackage -> PVhd.group_ID));
	ret = append_uint8(m, datapackage -> PVhd.group_size);
	ret = append_uint8(m, datapackage -> PVhd.pkt_seq);
	// printf("store pktID pkt_seq = %d\n", (datapackage -> PVhd.pkt_seq));
	ret = append_uint8(m, datapackage -> PVhd.pot_length);
	ret = append_uint32(m, datapackage -> PVhd.timestamp);
	ret = append_bytes(m, datapackage -> PVhd.pkt_ID, 16);
	ret = append_uint8(m, datapackage -> PVhd.flag);

	// printf("pktID group_ID = %d\n", (in -> PVhd.group_ID));
    // printf("pktID pkt_seq = %d\n", (in -> PVhd.pkt_seq));
    // printf("pktID uint32_t tmp_TS: %u\n", (in -> PVhd.timestamp)); 

	for(int i = 0; i<N; i++){
		ret = append_uint32(m, datapackage -> PVhd.POT[i]);
		// printf("store in -> PVhd.POT[ %d ]: ", i);
        // print_binary_32(datapackage -> PVhd.POT[i]);
	}

	if(ret == APPEND_ERROR){
		return FAIL_STORE;
	}
	return SUCCESS_STORE;
}
/*Add a function to process a packet*/
static int package_process(struct rte_mbuf* m, int portid)
{
retransmission:		
		/* 1 initialize */
		DataPackage * src_datapackage;
		//src_datapackage = Initial_DataPackage(m);
		src_datapackage = new DataPackage();
		packet_number[portid]++;

		/* 2 sign */
		//signers[portid]->Sign(src_datapackage);
		// tick_init1 = rdtsc(); //
		// signers[portid] -> generateInit(src_datapackage,src_addr,dst_addr);
		// tick_init2 = rdtsc(); //
		// if(packet_number[portid] != 1) 		
		// time_init += (double)(tick_init2 - tick_init1) / 7; //
		
		// tick_con1 = rdtsc();
		// cout << "port" << portid << " flag" << packetloss_flag << endl;
		// tick_con1 = rdtsc();
		signers[portid] -> generateConstruction(src_datapackage);
		// tick_con2 = rdtsc();
		// if(packet_number[portid] != 1) 		
		// time_con += (double)(tick_con2 - tick_con1) / 2.7; //
		// if(packet_number[portid] == 100){
		// 	printf("average generateConstruction time = %f ns\n", time_con / packet_number[portid]);
		// }
		// tick_con2 = rdtsc();
		// if(packet_number[portid] != 1) 		
		// time_con += (double)(tick_con2 - tick_con1) / 2.7; //

		// singe core
		// if(packet_number[portid] == 100000){
		// 	// tick2 =  rdtsc();
		// 	// time_throughput = (double)(tick2 - tick0) / 2.7 - time_init;
		// 	// printf("packetnumber = %d\ntime = %f ns\npacket size = %d\nthroughput = %f\n\n", packet_number[portid], time_throughput , (datalength * G + 19 * G + 16 * N + 52), packet_number[portid] * (datalength * G + 19 * G + 16 * N + 52) * 8 / time_throughput);
		// 	// printf("average construction time = %f ns\n", time_con / packet_number[portid] / G);
		// 	packet_number[portid] = 0;
		// 	time_con = 0;
		// }

		/* 3 store */
		Store_DataPackage(m,src_datapackage);

		return 0;
	// }
}

/*You need to replace the source IP and destination IP with the actual IP address*/
static void
l2fwd_mac_updating(struct rte_mbuf *m, unsigned dest_portid)
{
	struct ether_hdr *eth;

	struct ipv4_hdr *ipv4_hdr; //new
	uint16_t ether_type; //new

	eth = rte_pktmbuf_mtod(m, struct ether_hdr *);
	ether_type = rte_be_to_cpu_16(eth->ether_type); //new
	ipv4_hdr = rte_pktmbuf_mtod_offset(m, struct ipv4_hdr *,sizeof(struct ether_hdr)); //new
    uint32_t new_src_ip = rte_cpu_to_be_32(0xAC113C9B);  // 172.17.60.155 new node5 eth1 0xAC113C9B
	uint32_t new_dst_ip = rte_cpu_to_be_32(0xAC113C9D);  // 172.17.60.157 new node6 eth1 0xAC113C9D
	
	
	ipv4_hdr->src_addr = new_src_ip; //new
	ipv4_hdr->dst_addr = new_dst_ip; //new

	/* Recalculate the IP checksum */
	ipv4_hdr->hdr_checksum = 0; //new
	ipv4_hdr->hdr_checksum = rte_ipv4_cksum(ipv4_hdr); //new

	/* src addr */
	ether_addr_copy(&l2fwd_ports_eth_addr[dest_portid], &eth->s_addr);
}

static void
l2fwd_simple_forward(struct rte_mbuf *m, unsigned portid)//m is the data to be sent, and portid is the src id
{

	// if(portid == d_portid && packet_number[portid] >= 94) printf("already %d packets in simple fwd\n", packet_number[portid]);	
	unsigned dst_port;
	int sent;
	struct rte_eth_dev_tx_buffer *buffer;

	dst_port = l2fwd_dst_ports[portid];

	if (mac_updating)
		// l2fwd_mac_updating(m, portid, dst_port);
		l2fwd_mac_updating(m, dst_port);

	/* lock */
	buffer = tx_buffer[dst_port];

	sent = rte_eth_tx_buffer(dst_port, 0, buffer, m); 

	if (sent){
		port_statistics[dst_port].tx += sent;
	}
}

static void
l2fwd_main_loop(void)
{
	struct rte_mbuf *pkts_burst[MAX_PKT_BURST];
	struct rte_mbuf *m;
	int sent;
	unsigned lcore_id;
	uint64_t prev_tsc, diff_tsc, cur_tsc, timer_tsc;
	unsigned i, j, portid, nb_rx;
	struct lcore_queue_conf *qconf;
	const uint64_t drain_tsc = (rte_get_tsc_hz() + US_PER_S - 1) / US_PER_S *
			BURST_TX_DRAIN_US;
	struct rte_eth_dev_tx_buffer *buffer;
	// struct l2fwd_dst_ports * dst_ports;
	prev_tsc = 0;
	timer_tsc = 0;

	lcore_id = rte_lcore_id();
	qconf = &lcore_queue_conf[lcore_id];

	if (qconf->n_rx_port == 0) {
		RTE_LOG(INFO, L2FWD, "lcore %u has nothing to do\n", lcore_id);
		return;
	}

	RTE_LOG(INFO, L2FWD, "entering main loop on lcore %u\n", lcore_id);

	for (i = 0; i < qconf->n_rx_port; i++) { //A logical core can map multiple receive queues

		portid = qconf->rx_port_list[i];
		RTE_LOG(INFO, L2FWD, " -- lcoreid=%u portid=%u\n", lcore_id,
			portid);

	}

	int cnt_96 = 0;
	while (!force_quit) {

		cur_tsc = rte_rdtsc();// Get a timestamp from boot to the current day

		/*
		 * TX burst queue drain
		 */
		diff_tsc = cur_tsc - prev_tsc;
		if (unlikely(diff_tsc > drain_tsc)) { 
			for (i = 0; i < qconf->n_rx_port; i++) {
			
				portid = l2fwd_dst_ports[qconf->rx_port_list[i]];  //The portid here is dst_portid

				buffer = tx_buffer[portid];
				sent = rte_eth_tx_buffer_flush(portid, 0, buffer);

				if (sent){
						port_statistics[portid].tx += sent;
				}
			}

			/* if timer is enabled */
			if (timer_period > 0) {
				/* advance the timer */
				timer_tsc += diff_tsc;

				/* if timer has reached its timeout */
				if (unlikely(timer_tsc >= timer_period)) {

					/* do this only on master core */
					if (lcore_id == rte_get_master_lcore()) {
						// print_stats(timer_tsc);
						/* reset the timer */
						timer_tsc = 0;
					}
				}
			}

			prev_tsc = cur_tsc;
		}

		/*
		 * Read packet from RX queues 
		 */
		for (i = 0; i < qconf->n_rx_port; i++) {

			portid = qconf->rx_port_list[i];
			nb_rx = rte_eth_rx_burst((uint8_t) portid, 0,
						 pkts_burst, MAX_PKT_BURST);// pkts_burst rx queue

			port_statistics[portid].rx += nb_rx;	
            /*Traverse the received data packets.*/
			
			for (j = 0; j < nb_rx; j++) {
				tick_con1 = rdtsc();
				m = pkts_burst[j]; //pkts_burst[j] 
				rte_prefetch0(rte_pktmbuf_mtod(m, void *)); //rte_pktmbuf_mtod(m, void *) 
				
				
				struct ether_hdr *eth_hdr;
				struct ipv4_hdr *ipv4_hdr;
				struct ether_addr *src_mac;
				char src_ip_str[INET_ADDRSTRLEN];
				eth_hdr = rte_pktmbuf_mtod(m, struct ether_hdr *);
				src_mac = &eth_hdr->s_addr;
				ipv4_hdr = rte_pktmbuf_mtod_offset(m, struct ipv4_hdr *, sizeof(struct ether_hdr));

				uint32_t new_src_ip = rte_cpu_to_be_32(0xAC113c93); // 172.17.60.147 node1 eth1
				
				if(ipv4_hdr->src_addr == new_src_ip){
					if(!ifstart && portid == 0){
						ifstart = true;
						// printf("tick0\n");
						// tick0 = rdtsc();
					}
					
					int ret = package_process(m,portid);
							
					if(ret == FALSE_PACKAGE){
						// printf("drop a false package!\n");
						continue;
					}

					l2fwd_simple_forward(m, portid);
				
				}		
				// tick_con2 = rdtsc();
				// time_con += (double)(tick_con2 - tick_con1) / 2.7;
				// if(packet_number[portid] == 500){
				// 	 printf("generateConstruction time = %f ns\n", time_con);
				// }

			}
		}
	}
}


static int
l2fwd_launch_one_lcore(__attribute__((unused)) void *dummy)
{
	l2fwd_main_loop();
	return 0;
}
/* display usage*/
static void
l2fwd_usage(const char *prgname)
{
	printf("%s [EAL options] -- -p PORTMASK [-q NQ]\n"
	       "  -p PORTMASK: hexadecimal bitmask of ports to configure\n"
	       "  -q NQ: number of queue (=ports) per lcore (default is 1)\n"
		   "  -T PERIOD: statistics will be refreshed each PERIOD seconds (0 to disable, 10 default, 86400 maximum)\n"
		   "  --[no-]mac-updating: Enable or disable MAC addresses updating (enabled by default)\n"
		   "      When enabled:\n"
		   "       - The source MAC address is replaced by the TX port MAC address\n"
		   "       - The destination MAC address is replaced by 02:00:00:00:00:TX_PORT_ID\n",
	       prgname);
}

static int
l2fwd_parse_portmask(const char *portmask)
{
	char *end = NULL;
	unsigned long pm;

	/* parse hexadecimal string */
	pm = strtoul(portmask, &end, 16);
	if ((portmask[0] == '\0') || (end == NULL) || (*end != '\0'))
		return -1;

	if (pm == 0)
		return -1;

	return pm;
}

static unsigned int
l2fwd_parse_nqueue(const char *q_arg)
{
	char *end = NULL;
	unsigned long n;

	/* parse hexadecimal string */
	n = strtoul(q_arg, &end, 10);
	if ((q_arg[0] == '\0') || (end == NULL) || (*end != '\0'))
		return 0;
	if (n == 0)
		return 0;
	if (n >= MAX_RX_QUEUE_PER_LCORE)
		return 0;

	return n;
}

static int
l2fwd_parse_timer_period(const char *q_arg)
{
	char *end = NULL;
	int n;

	/* parse number string */
	n = strtol(q_arg, &end, 10);
	if ((q_arg[0] == '\0') || (end == NULL) || (*end != '\0'))
		return -1;
	if (n >= MAX_TIMER_PERIOD)
		return -1;

	return n;
}

static const char short_options[] =
	"p:"  /* portmask */
	"q:"  /* number of queues */
	"T:"  /* timer period */
	;

#define CMD_LINE_OPT_MAC_UPDATING "mac-updating"
#define CMD_LINE_OPT_NO_MAC_UPDATING "no-mac-updating"

enum {
	/* long options mapped to a short option */

	/* first long only option value must be >= 256, so that we won't
	 * conflict with short options */
	CMD_LINE_OPT_MIN_NUM = 256,
};

static const struct option lgopts[] = {
	{ CMD_LINE_OPT_MAC_UPDATING, no_argument, &mac_updating, 1},
	{ CMD_LINE_OPT_NO_MAC_UPDATING, no_argument, &mac_updating, 0},
	{NULL, 0, 0, 0}
};
/* Parse the argument given in the command line of the application */
static int
l2fwd_parse_args(int argc, char **argv)
{
	int opt, ret, timer_secs;
	char **argvopt;
	int option_index;
	char *prgname = argv[0];

	argvopt = argv;

	while ((opt = getopt_long(argc, argvopt, short_options,
				  lgopts, &option_index)) != EOF) {

		switch (opt) {
		/* portmask */
		case 'p':
			l2fwd_enabled_port_mask = l2fwd_parse_portmask(optarg);
			if (l2fwd_enabled_port_mask == 0) {
				printf("invalid portmask\n");
				l2fwd_usage(prgname);
				return -1;
			}
			break;

		/* nqueue */
		case 'q':
			l2fwd_rx_queue_per_lcore = l2fwd_parse_nqueue(optarg);
			if (l2fwd_rx_queue_per_lcore == 0) {
				printf("invalid queue number\n");
				l2fwd_usage(prgname);
				return -1;
			}
			break;

		/* timer period */
		case 'T':
			timer_secs = l2fwd_parse_timer_period(optarg);
			if (timer_secs < 0) {
				printf("invalid timer period\n");
				l2fwd_usage(prgname);
				return -1;
			}
			timer_period = timer_secs;
			break;

		/* long options */
		case 0:
			break;

		default:
			l2fwd_usage(prgname);
			return -1;
		}
	}

	if (optind >= 0)
		argv[optind-1] = prgname;

	ret = optind-1;
	optind = 1; /* reset getopt lib */
	return ret;
}
/* Check the link status of all ports in up to 9s, and print them finally */
static void
check_all_ports_link_status(uint8_t port_num, uint32_t port_mask)
{
#define CHECK_INTERVAL 100 /* 100ms */
#define MAX_CHECK_TIME 90 /* 9s (90 * 100ms) in total */
	uint8_t portid, count, all_ports_up, print_flag = 0;
	struct rte_eth_link link;

	printf("\nChecking link status");
	fflush(stdout);
	for (count = 0; count <= MAX_CHECK_TIME; count++) {
		if (force_quit)
			return;
		all_ports_up = 1;
		for (portid = 0; portid < port_num; portid++) {
			if (force_quit)
				return;
			if ((port_mask & (1 << portid)) == 0)
				continue;
			memset(&link, 0, sizeof(link));
			rte_eth_link_get_nowait(portid, &link);
			/* print link status if flag set */
			if (print_flag == 1) {
				if (link.link_status)
					printf("Port %d Link Up - speed %u "
						"Mbps - %s\n", (uint8_t)portid,
						(unsigned)link.link_speed,
				(link.link_duplex == ETH_LINK_FULL_DUPLEX) ?
					("full-duplex") : ("half-duplex\n"));
				else
					printf("Port %d Link Down\n",
						(uint8_t)portid);
				continue;
			}
			/* clear all_ports_up flag if any link down */
			if (link.link_status == ETH_LINK_DOWN) {
				all_ports_up = 0;
				break;
			}
		}
		/* after finally printing all link status, get out */
		if (print_flag == 1)
			break;

		if (all_ports_up == 0) {
			printf(".");
			fflush(stdout);
			rte_delay_ms(CHECK_INTERVAL);
		}

		/* set the print_flag if all ports up or timeout */
		if (all_ports_up == 1 || count == (MAX_CHECK_TIME - 1)) {
			print_flag = 1;
			printf("done\n");
		}
	}
}

static void
signal_handler(int signum)
{
	if (signum == SIGINT || signum == SIGTERM) {
		printf("\n\nSignal %d received, preparing to exit...\n",
				signum);
		force_quit = true;
	}
}

int
main(int argc, char **argv)
{
	
	// pair P;
	// P.current_global_ID = 0;
	// P.current_global_ID_status = 0;
	struct lcore_queue_conf *qconf;
	struct rte_eth_dev_info dev_info; //new
	int ret;
	uint8_t nb_ports;
	uint8_t nb_ports_available;
	uint8_t portid, last_port;
	unsigned lcore_id, rx_lcore_id;
	unsigned nb_ports_in_mask = 0;


	/* -- no change -- init EAL */
	ret = rte_eal_init(argc, argv);
	printf("\n argc %d \n", argc);
	printf("\n %s \n", argv[0]);
	if (ret < 0)
		rte_exit(EXIT_FAILURE, "Invalid EAL arguments\n");
	argc -= ret;
	argv += ret;

	force_quit = false;
	signal(SIGINT, signal_handler);
	signal(SIGTERM, signal_handler);

	/* -- no change -- parse application arguments (after the EAL ones) */
	ret = l2fwd_parse_args(argc, argv);
	if (ret < 0)
		rte_exit(EXIT_FAILURE, "Invalid L2FWD arguments\n");

	printf("MAC updating %s\n", mac_updating ? "enabled" : "disabled");

	/* -- no change -- convert to number of cycles */
	timer_period *= rte_get_timer_hz();

	nb_ports = rte_eth_dev_count_avail();
	if (nb_ports == 0)
		rte_exit(EXIT_FAILURE, "No Ethernet ports - bye\n");

	printf("\n Found %d ports\n", nb_ports);

	/*create the mbuf pool */
	l2fwd_pktmbuf_pool = rte_pktmbuf_pool_create("mbuf_pool", NB_MBUF,
		MEMPOOL_CACHE_SIZE, 0, RTE_MBUF_DEFAULT_BUF_SIZE,
		rte_socket_id());
	if (l2fwd_pktmbuf_pool == NULL)
		rte_exit(EXIT_FAILURE, "Cannot init mbuf pool\n");

	/*reset l2fwd_dst_ports */
	memset(l2fwd_dst_ports,0,sizeof(l2fwd_dst_ports));

	// Initial(); 
	for (portid = 0; portid < nb_ports; portid++) {
		if ((l2fwd_enabled_port_mask & (1 << portid)) != 0){
			nb_enabled_port++;
			signers[portid]=new Signer(portid);
		}
	}

	// if(nb_enabled_port<2)
	// 	rte_exit(EXIT_FAILURE, "At least 3 enabled ports, %d found\n" , nb_enabled_port );

	/*
	 * Each logical core is assigned a dedicated TX queue on each port.
	 */
	/* set s_portid, d_portid, l2fwd_dst_ports */
	uint8_t tmp_cnt=0, tmp_idx=0;
	for (portid = 0; portid < nb_ports; portid++) {
		/* skip ports that are not enabled */
		if ((l2fwd_enabled_port_mask & (1 << portid)) == 0)
			continue;
		if (tmp_cnt % N == 0) { // sourceN
			s_portid = portid;
			// printf("!!!!!!!!!!!!!!!!!!!!!!!source id %d\n", portid);
		}else if((tmp_cnt + 1) % N == 0){ // end 
			d_portid = portid;
			l2fwd_dst_ports[tmp_idx] = portid;
			l2fwd_dst_ports[portid] = (portid + 1 - N);
			// printf("!!!!!!!!!!!!!!!!!!!!!!!dst id %d\n", portid);
		}else{ // middle
			l2fwd_dst_ports[tmp_idx] = portid;
		}
		tmp_idx = portid;
		tmp_cnt++;

		rte_eth_dev_info_get(portid, &dev_info);

	}


	rx_lcore_id = 0;
	qconf = NULL;

	/* Initialize the port/queue configuration of each logical core  -- no change -- */
	for (portid = 0; portid < nb_ports; portid++) {
		/* skip ports that are not enabled */
		if ((l2fwd_enabled_port_mask & (1 << portid)) == 0)
			continue;
		/* get the lcore_id for this port */
		while (rte_lcore_is_enabled(rx_lcore_id) == 0 ||
		       lcore_queue_conf[rx_lcore_id].n_rx_port ==
		       l2fwd_rx_queue_per_lcore) {
			rx_lcore_id++;
			if (rx_lcore_id >= RTE_MAX_LCORE)
				rte_exit(EXIT_FAILURE, "Not enough cores\n");
		}

		if (qconf != &lcore_queue_conf[rx_lcore_id])
			/* Assigned a new logical core in the loop above. */
			qconf = &lcore_queue_conf[rx_lcore_id];

		qconf->rx_port_list[qconf->n_rx_port] = portid;
		qconf->n_rx_port++;
		printf("Lcore %u: RX port %u\n", rx_lcore_id, (unsigned) portid);
	}

	nb_ports_available = nb_ports;

	/* Initialize each port */
	for (portid = 0; portid < nb_ports; portid++) {
		/* skip ports that are not enabled */
		if ((l2fwd_enabled_port_mask & (1 << portid)) == 0) {
			printf("Skipping disabled port %u\n", (unsigned) portid);
			nb_ports_available--;
			continue;
		}
		/* init port */
		printf("Initializing port %u... ", (unsigned) portid);
		fflush(stdout);
		// printf("\nlsc: %d\n", port_conf.intr_conf.lsc);
		ret = rte_eth_dev_configure(portid, 1, 1, &port_conf);
		if (ret < 0)
			rte_exit(EXIT_FAILURE, "Cannot configure device: err=%d, port=%u\n",
				  ret, (unsigned) portid);

		ret = rte_eth_dev_adjust_nb_rx_tx_desc(portid, &nb_rxd, 
						       &nb_txd);
		if (ret < 0)
			rte_exit(EXIT_FAILURE,
				 "Cannot adjust number of descriptors: err=%d, port=%u\n",
				 ret, (unsigned) portid);

		rte_eth_macaddr_get(portid, &l2fwd_ports_eth_addr[portid]);

		/* init one RX queue */
		fflush(stdout);

		ret = rte_eth_rx_queue_setup(portid, 0, nb_rxd,
					     rte_eth_dev_socket_id(portid),
					     NULL,
					     l2fwd_pktmbuf_pool);
		if (ret < 0)
			rte_exit(EXIT_FAILURE, "rte_eth_rx_queue_setup:err=%d, port=%u\n",
				  ret, (unsigned) portid);

		/* init one TX queue on each port*/
		fflush(stdout);
		ret = rte_eth_tx_queue_setup(portid, 0, nb_txd,
				rte_eth_dev_socket_id(portid),
				&tx_conf);
		if (ret < 0)
			rte_exit(EXIT_FAILURE, "rte_eth_tx_queue_setup:err=%d, port=%u\n",
				ret, (unsigned) portid);

		/* Initialize TX buffers */
		tx_buffer[portid] = (rte_eth_dev_tx_buffer*)rte_zmalloc_socket("tx_buffer",
				RTE_ETH_TX_BUFFER_SIZE(MAX_PKT_BURST), 0,
				rte_eth_dev_socket_id(portid));
		if (tx_buffer[portid] == NULL)
			rte_exit(EXIT_FAILURE, "Cannot allocate buffer for tx on port %u\n",
					(unsigned) portid);

		rte_eth_tx_buffer_init(tx_buffer[portid], MAX_PKT_BURST);

		ret = rte_eth_tx_buffer_set_err_callback(tx_buffer[portid],
				rte_eth_tx_buffer_count_callback,
				&port_statistics[portid].dropped);
		if (ret < 0)
				rte_exit(EXIT_FAILURE, "Cannot set error callback for "
						"tx buffer on port %u\n", (unsigned) portid);

		/* Start device */
		ret = rte_eth_dev_start(portid);
		if (ret < 0)
			rte_exit(EXIT_FAILURE, "rte_eth_dev_start:err=%d, port=%u\n",
				  ret, (unsigned) portid);

		printf("done: \n");

		// rte_eth_promiscuous_enable(portid);

		printf("Port %u, MAC address: %02X:%02X:%02X:%02X:%02X:%02X\n\n",
				(unsigned) portid,
				l2fwd_ports_eth_addr[portid].addr_bytes[0],
				l2fwd_ports_eth_addr[portid].addr_bytes[1],
				l2fwd_ports_eth_addr[portid].addr_bytes[2],
				l2fwd_ports_eth_addr[portid].addr_bytes[3],
				l2fwd_ports_eth_addr[portid].addr_bytes[4],
				l2fwd_ports_eth_addr[portid].addr_bytes[5]);

		/* initialize port stats */
		memset(&port_statistics, 0, sizeof(port_statistics));
	}
	

	if (!nb_ports_available) {
		rte_exit(EXIT_FAILURE,
			"All available ports are disabled. Please set portmask.\n");
	}
	check_all_ports_link_status(nb_ports, l2fwd_enabled_port_mask);

	ret = 0;
	/* launch per-lcore init on every lcore */
	printf("launch one core start\n");

	rte_eal_mp_remote_launch(l2fwd_launch_one_lcore, NULL, CALL_MASTER);

	RTE_LCORE_FOREACH_SLAVE(lcore_id) {
		if (rte_eal_wait_lcore(lcore_id) < 0) {
			ret = -1;
			break;
		}
	}

	for (portid = 0; portid < nb_ports; portid++) {
		if ((l2fwd_enabled_port_mask & (1 << portid)) == 0)
			continue;
		printf("Closing port %d...", portid);
		rte_eth_dev_stop(portid);
		rte_eth_dev_close(portid);
		printf(" Done\n");
	}
	printf("Bye...\n");

	return ret;
}





// int main() {
// 	unsigned char *plaintext = (unsigned char *)malloc(DATA_SIZE);
//     unsigned char *ciphertext = (unsigned char *)malloc(DATA_SIZE + AES_BLOCK_SIZE);

//     unsigned char key[16] = {0}; // 16-byte key for AES-128
//     unsigned char iv[16] = {0};  // 16-byte IV


//     // unsigned char key[16] = {0};
//     // unsigned char iv[16] = {0};
//     // unsigned char plaintext[1048576]; // 设置明文为 1KB
//     // unsigned char ciphertext[1048576];
// 	memset(plaintext, 'D', DATA_SIZE);

//     EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
//     if (!ctx) {
//         fprintf(stderr, "Failed to create EVP_CIPHER_CTX\n");
//         return 1;
//     }

//     if (EVP_EncryptInit_ex(ctx, EVP_aes_128_cbc(), NULL, key, iv) != 1) {
//         fprintf(stderr, "EVP_EncryptInit_ex failed\n");
//         return 1;
//     }
//     unsigned long long tag_3 = rdtsc();
//     int len;

// 	struct timespec start, end;
//     clock_gettime(CLOCK_MONOTONIC, &start);


// 	EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, DATA_SIZE);

// 	unsigned long long tag_4 = rdtsc();
// 	double tag_con_10 = (double)(tag_4 - tag_3) / 2.7;

// 	printf("tag_con_10 = %f ns\n", tag_con_10);

// 	clock_gettime(CLOCK_MONOTONIC, &end);
//     double time_taken = (end.tv_sec - start.tv_sec) + (end.tv_nsec - start.tv_nsec) / 1e9;

//     printf("Encryption time: %f seconds\n", time_taken);

//     if (EVP_EncryptFinal_ex(ctx, ciphertext + len, &len) != 1) {
//         fprintf(stderr, "EVP_EncryptFinal_ex failed\n");
//         return 1;
//     }

//     EVP_CIPHER_CTX_free(ctx);
// 	free(plaintext);
//     free(ciphertext);

    
//     return 0;
// }
