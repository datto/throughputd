/*
    Copyright (C) 2015 Datto Inc.

    This file is part of throughputd.

    This program is free software; you can redistribute it and/or modify it 
    under the terms of the GNU General Public License version 2 as published
    by the Free Software Foundation.
*/

#define _GNU_SOURCE

#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <ifaddrs.h>
#include <sqlite3.h>
#include <signal.h>
#include <time.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <pthread.h>
#include <arpa/inet.h>
#include <netinet/if_ether.h>

#include "debug.h"
#include "hashtable.h"

/******************************* Macro Definitions ********************************/

#define HASHTABLE_ARRAY_SIZE 100
#define PACKET_BUF_LEN 200
#define PCAP_TIMEOUT_MS 5000

#define SQL_SCHEMA_CREATE_STMT						\
"CREATE TABLE IF NOT EXISTS %s (					\
	id INTEGER PRIMARY KEY AUTOINCREMENT,			\
	ip TEXT NOT NULL,								\
	timestamp INTEGER NOT NULL,						\
	send_total INTEGER NOT NULL,					\
	recv_total INTEGER NOT NULL						\
);"

#define SQL_INSERT_RECORD_STMT "INSERT INTO %s(ip, timestamp, send_total, recv_total) VALUES(?, ?, ?, ?);"

#define SQL_CREATE_INDEX_STMT "CREATE INDEX IF NOT EXISTS nt_timestamp ON %s(timestamp);"

#define DEFAULT_DBFILE_NAME "throughputd.db"
#define DEFAULT_TABLE_NAME "network_traffic"

#define USAGE \
"Usage: %s [options...] [<interfaces>]\n"										\
"Valid options are:\n"															\
"  -t integer        Interval between writes in seconds (default: 5)\n"			\
"  -f path           Path to sqlite database (default: throughputd.db)\n"		\
"  -p path           Path to PID file (default: none)\n"						\
"  -a table          Name of database table (default: network_traffic)\n"		\
"  -d                Daemonize after starting (only if debugging disabled)\n"

/******************************* Struct Definitions ********************************/

struct ethernet_header{
	uint8_t dest[ETHER_ADDR_LEN];
	uint8_t host[ETHER_ADDR_LEN];
	uint16_t type;
};
#define SIZE_ETHERNET 14

struct ipv4_header{
	uint8_t version_length;
	uint8_t tos;
	uint16_t len;
	uint16_t id;
	uint16_t frag_off;
	uint8_t ttl;
	uint8_t protocol;
	uint16_t chksum;
	struct in_addr src;
	struct in_addr dest;
};
#define IP_HEADER_LENGTH(ip) ((((ip)->version_length) & 0x0f) * 4)
#define IP_VERSION(ip) (((ip)->version_length) >> 4)

struct ipv6_header{
	uint32_t version_tc_flowlabel;
	uint16_t len;
	uint8_t  next_header;
	uint8_t  hop_limit;
	struct in6_addr src;
	struct in6_addr dest;
};

struct throughputd_record{
	char lan_ip[INET6_ADDRSTRLEN];
	uint64_t recv_total;
	uint64_t send_total;
	struct hashtable_link link;
};

struct throughputd_context{
	struct hashtable records;
	struct ifaddrs *ifaddr;
	char should_stop;
	pthread_mutex_t lock;
	pthread_t thread;
	pcap_t *pcap_fd;
};

/******************************* Global Variables ********************************/

static struct throughputd_context *throughputd_contexts = NULL;
static int context_count = 0;
static struct ifaddrs *ifaddrs = NULL;
static unsigned int record_interval = 5;
static pthread_t recording_pthread;
static volatile sig_atomic_t should_stop_recording = 0;
static sqlite3 *db = NULL;
static char *insert_stmt = NULL;
static char *pid_file = NULL;

static void signal_handler(int sig);

static struct sigaction signal_action = {
	.sa_handler = signal_handler,
};

/*************************** Recording Logic ****************************/

static int record_entry(struct hashtable *records, struct hashtable_link *hl, void *data){
	int ret;
	sqlite3_stmt *stmt = NULL;
	time_t *cur_time = (time_t *)data;
	struct throughputd_record *record = container_of(hl, struct throughputd_record, link);
	
	ret = sqlite3_prepare_v2(db, insert_stmt, strlen(insert_stmt), &stmt, NULL);
	if(ret != SQLITE_OK){
		PRINT_ERROR(ret, "error preparing insert statement: %s", sqlite3_errmsg(db));
		goto error;
	}
		
	sqlite3_bind_text(stmt, 1, record->lan_ip, strlen(record->lan_ip), NULL);
	sqlite3_bind_int64(stmt, 2, *cur_time);
	sqlite3_bind_int64(stmt, 3, record->send_total);
	sqlite3_bind_int64(stmt, 4, record->recv_total);
	
	ret = sqlite3_step(stmt);
	if(ret != SQLITE_DONE) {
		PRINT_ERROR(ret, "error executing insert statement");
		goto error;
	}
	
	sqlite3_finalize(stmt);
	
	hashtable_delete(records, hl->key);
	free(record);
	
	return 0;
	
error:
	PRINT_ERROR(ret, "error recording entry");
	if(stmt) sqlite3_finalize(stmt);
	return ret;
}

static void *recording_thread(void *unused){
	int ret, i;
	char transaction_exists = 0;
	time_t cur_time;
	struct throughputd_context *ctx;
	
	pthread_setcanceltype(PTHREAD_CANCEL_ASYNCHRONOUS, NULL);
	
	while(!should_stop_recording){
		sleep(record_interval);
		
		pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, NULL);
		
		PRINT_DEBUG("interval elapsed, recording current state");
		cur_time = time(NULL);
		
		ret = sqlite3_exec(db, "BEGIN;", NULL, NULL, NULL);
		if(ret != SQLITE_OK){
			PRINT_ERROR(ret, "error beginning transaction");
			goto error;
		}
		transaction_exists = 1;
		
		for(i = 0; i < context_count; i++){
			ctx = &throughputd_contexts[i];
			
			pthread_mutex_lock(&ctx->lock);
			
			PRINT_DEBUG("recording current state for %s", ctx->ifaddr->ifa_name);
			ret = hashtable_for_each_key(&ctx->records, record_entry, &cur_time);
			if(ret) goto error;
			
			pthread_mutex_unlock(&ctx->lock);
		}
		
		PRINT_DEBUG("committing transaction");
		ret = sqlite3_exec(db, "COMMIT;", NULL, NULL, NULL);
		if(ret != SQLITE_OK){
			PRINT_ERROR(ret, "error committing transaction");
			goto error;
		}
		transaction_exists = 0;
		
		pthread_setcancelstate(PTHREAD_CANCEL_ENABLE, NULL);
	}
	
	return NULL;
	
error:
	PRINT_ERROR(ret, "error during the recording thread, exiting");
	if(transaction_exists) sqlite3_exec(db, "ROLLBACK;", NULL, NULL, NULL);
	return NULL;
}

/************************** Internal State Management ***************************/

static int throughputd_record_alloc(char *ip, struct throughputd_record **record_out){
	int ret;
	struct throughputd_record *record;
	
	PRINT_DEBUG("allocating new record");
	record = malloc(sizeof(struct throughputd_record));
	if(!record){
		ret = ENOMEM;
		PRINT_ERROR(ret, "error allocating new record");
		
		*record_out = NULL;
		return ret;
	}
	
	record->recv_total = 0; 
	record->send_total = 0;
	strncpy(record->lan_ip, ip, INET6_ADDRSTRLEN);

	*record_out = record;
	return 0;
}

static int update_record(struct throughputd_context *ctx, char *ip, uint64_t datalen, int is_recv){
	int ret;
	struct throughputd_record *record;
	struct hashtable_link *hl;
	
	pthread_mutex_lock(&ctx->lock);
	
	hl = hashtable_find(&ctx->records, ip);
	if(!hl){
		PRINT_DEBUG("existing record not found, adding new record");
		ret = throughputd_record_alloc(ip, &record);
		if(ret) goto error;
		
		ret = hashtable_insert(&ctx->records, record->lan_ip, &record->link);
		if(ret){
			PRINT_ERROR(ret, "error inserting new record into hashtable: This shouldn't happen");
			goto error;
		}
	}else record = container_of(hl, struct throughputd_record, link);
	
	if(is_recv) record->recv_total += datalen;
	else record->send_total += datalen;
	
	pthread_mutex_unlock(&ctx->lock);
	
	return 0;
	
error:
	PRINT_ERROR(ret, "error updating record for packet");
	pthread_mutex_unlock(&ctx->lock);
	return ret;
}

/*************************** Packet Specific Handlers ****************************/

static int ip_matches_nic(uint32_t *ip, uint32_t *if_addr, uint32_t *netmask, int bits){
	int i;
	
	for(i = 0; i < bits / 8 / sizeof(uint32_t); i++){
		if((if_addr[i] & netmask[i]) != (ip[i] & netmask[i])) return 0;
	}

	return 1;
}

static void handle_ipv4_packet(struct throughputd_context *ctx, const u_char *packet, time_t timestamp, uint32_t len){
	char src_ip[INET_ADDRSTRLEN];
	char dest_ip[INET_ADDRSTRLEN];
	struct ipv4_header *header = (struct ipv4_header *)packet;
	uint32_t *if_addr = &(((struct sockaddr_in *)ctx->ifaddr->ifa_addr)->sin_addr.s_addr);
	uint32_t *if_mask = &(((struct sockaddr_in *)ctx->ifaddr->ifa_netmask)->sin_addr.s_addr);
	uint32_t *src_addr = ((uint32_t *)&header->src.s_addr);
	uint32_t *dest_addr = ((uint32_t *)&header->dest.s_addr);

	inet_ntop(AF_INET, &header->src, src_ip, INET_ADDRSTRLEN);
	inet_ntop(AF_INET, &header->dest, dest_ip, INET_ADDRSTRLEN);

	PRINT_DEBUG("IPv4 src = %s, dest = %s", src_ip, dest_ip);
	
	if(ip_matches_nic(src_addr, if_addr, if_mask, 32)){
		PRINT_DEBUG("Packet is outgoing");
		update_record(ctx, src_ip, len, 0);
	}
	
	if(ip_matches_nic(dest_addr, if_addr, if_mask, 32)){
		PRINT_DEBUG("Packet is incoming");
		update_record(ctx, dest_ip, len, 1);
	}
}

static void handle_ipv6_packet(struct throughputd_context *ctx, const u_char *packet, time_t timestamp, uint32_t len){
	char src_ip[INET6_ADDRSTRLEN];
	char dest_ip[INET6_ADDRSTRLEN];
	struct ipv6_header *header = (struct ipv6_header *)packet;
	uint32_t *if_addr = (uint32_t *)(((struct sockaddr_in6 *)ctx->ifaddr->ifa_addr)->sin6_addr.s6_addr);
	uint32_t *if_mask = (uint32_t *)(((struct sockaddr_in6 *)ctx->ifaddr->ifa_netmask)->sin6_addr.s6_addr);
	uint32_t *src_addr = ((uint32_t *)&header->src.s6_addr);
	uint32_t *dest_addr = ((uint32_t *)&header->dest.s6_addr);
	
	inet_ntop(AF_INET6, &header->src, src_ip, INET6_ADDRSTRLEN);
	inet_ntop(AF_INET6, &header->dest, dest_ip, INET6_ADDRSTRLEN);

	PRINT_DEBUG("IPv6 src = %s, dest = %s", src_ip, dest_ip);
	
	if(ip_matches_nic(src_addr, if_addr, if_mask, 128)){
		PRINT_DEBUG("Packet is outgoing");
		update_record(ctx, src_ip, len, 0);
	}
	
	if(ip_matches_nic(dest_addr, if_addr, if_mask, 128)){
		PRINT_DEBUG("Packet is incoming");
		update_record(ctx, dest_ip, len, 1);
	}
}

/*************************** Main processing Logic ****************************/

static void on_packet_received(u_char *data, const struct pcap_pkthdr *pkt_header, const u_char *packet){
	char should_stop;
	struct throughputd_context *ctx = (struct throughputd_context *)data; 
	struct ethernet_header *eth_header = (struct ethernet_header *)packet;
	int tag_offset = 0;
	uint8_t *eth_type_ptr;
	uint16_t eth_type;
	
	pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, NULL);
	
reevaluate_type:
	eth_type_ptr = ((uint8_t*)&eth_header->type) + tag_offset;
	eth_type = ntohs(*((uint16_t*)eth_type_ptr));

	switch(eth_type){
	case ETHERTYPE_VLAN:
		PRINT_DEBUG("VLAN tag found, reevaluating packet type");
		tag_offset += 2 * sizeof(uint16_t);
		goto reevaluate_type;
	case ETHERTYPE_IP:
		handle_ipv4_packet(ctx, packet + SIZE_ETHERNET + tag_offset, pkt_header->ts.tv_sec, pkt_header->len);
		break;
	case ETHERTYPE_IPV6:
		handle_ipv6_packet(ctx, packet + SIZE_ETHERNET + tag_offset, pkt_header->ts.tv_sec, pkt_header->len);
		break;
	case ETHERTYPE_ARP:
		PRINT_DEBUG("ARP packet");
		break;
	default:
		PRINT_DEBUG("unrecognized packet recieved (0x%x)", eth_type);
		break;
	}
	
	pthread_mutex_lock(&ctx->lock);
	should_stop = ctx->should_stop;
	pthread_mutex_unlock(&ctx->lock);
	
	if(should_stop){
		PRINT_DEBUG("stopping thread due to flag");
		pcap_breakloop(ctx->pcap_fd);
		return;
	}
	
	pthread_setcancelstate(PTHREAD_CANCEL_ENABLE, NULL);
}

static void *interface_listening_thread(void *data){
	int ret;
	struct throughputd_context *ctx = (struct throughputd_context *)data;
	
	pthread_setcanceltype(PTHREAD_CANCEL_ASYNCHRONOUS, NULL);

	PRINT_DEBUG("beginning processing loop");
	ret = pcap_loop(ctx->pcap_fd, -1, on_packet_received, data);
	if(ret){
		PRINT_ERROR(ret, "error running pcap loop");
		return NULL;
	}
	
	PRINT_DEBUG("exiting processing loop");

	return NULL;
}

static int initialize_thread_context(struct throughputd_context *ctx, struct ifaddrs *interface){
	int ret;
	char hashtable_initialized = 0, mutex_intialized = 0;
	char errbuf[PCAP_ERRBUF_SIZE];
	
	ctx->ifaddr = interface;
	ctx->should_stop = 0;
	
	PRINT_DEBUG("initializing hashtable");
	ret = hashtable_init(&ctx->records, HASHTABLE_ARRAY_SIZE);
	if(ret) goto error;
	hashtable_initialized = 1;
	
	PRINT_DEBUG("initializing mutex");
	ret = pthread_mutex_init(&ctx->lock, NULL);
	if(ret){
		PRINT_ERROR(ret, "error initializing mutex");
		goto error;
	}
	mutex_intialized = 1;
	
	PRINT_DEBUG("opening device %s for listening", interface->ifa_name);
	ctx->pcap_fd = pcap_open_live(interface->ifa_name, PACKET_BUF_LEN, 0, PCAP_TIMEOUT_MS, errbuf);
	if(!ctx->pcap_fd){
		ret = EFAULT;
		PRINT_ERROR(ret, "error opening pcap device %s", errbuf);
		goto error;
	}
	
	PRINT_DEBUG("creating thread");
	ret = pthread_create(&ctx->thread, NULL, interface_listening_thread, ctx);
	if(ret){
		PRINT_ERROR(ret, "error starting trafic monitoring thread");
		goto error;
	}
	
	return 0;

error:
	PRINT_ERROR(ret, "error initializing thread context");
	if(hashtable_initialized) hashtable_destroy(&ctx->records);
	if(mutex_intialized) pthread_mutex_destroy(&ctx->lock);
	return ret;
}

static void signal_handler(int sig){
	PRINT_DEBUG("----------------------- SIGTERM / SIGINT caught ---------------------------");
	should_stop_recording = 1;
	pthread_cancel(recording_pthread);
}

static int free_record(struct hashtable *records, struct hashtable_link *hl, void *data){
	free(container_of(hl, struct throughputd_record, link));
	return 0;
}

static int string_is_present(int argc, char **argv, char *str){
	int i;
	
	for(i = 0; i < argc; i++){
		if(!strcmp(str, argv[i])) return 1;
	}
	
	return 0;
}

static int context_already_exists(char *ifname){
	int i;
	
	for(i = 0; i < context_count; i++){
		if(!strcmp(throughputd_contexts[i].ifaddr->ifa_name, ifname)) return 1;
	}
	
	return 0;
}

static int interface_exists(char *ifname){
	struct ifaddrs *interface;
	
	for(interface = ifaddrs; interface; interface = interface->ifa_next){
		if(interface->ifa_addr->sa_family != AF_INET && interface->ifa_addr->sa_family != AF_INET6) continue;
		if(!strcmp(interface->ifa_name, ifname)) return 1;
	}
	
	return 0;
}

static void throughputd_cleanup(void){
	int i;
	struct throughputd_context *ctx;
	
	PRINT_DEBUG("cleaning up all allocations");
	
	for(i = 0; i < context_count; i++){
		ctx = &throughputd_contexts[i];
		
		PRINT_DEBUG("setting should stop for thread %s", ctx->ifaddr->ifa_name);
		pthread_mutex_lock(&ctx->lock);
		ctx->should_stop = 1;
		pthread_mutex_unlock(&ctx->lock);
		
		PRINT_DEBUG("sending signal to thread");
		pthread_cancel(ctx->thread);
		
		PRINT_DEBUG("waiting for thread to stop");
		pthread_join(ctx->thread, NULL);
		
		PRINT_DEBUG("freeing hashtable entries");
		hashtable_for_each_key(&ctx->records, free_record, NULL);
		
		PRINT_DEBUG("freeing hashtable");
		hashtable_destroy(&ctx->records);

		PRINT_DEBUG("destroying context lock");
		pthread_mutex_destroy(&ctx->lock);
		
		PRINT_DEBUG("destroying context interface descriptor");
		pcap_close(ctx->pcap_fd);
	}
	
	PRINT_DEBUG("destroying global variables");
	if(ifaddrs) freeifaddrs(ifaddrs);
	if(throughputd_contexts) free(throughputd_contexts);
	if(db) sqlite3_close(db);
	if(insert_stmt) free(insert_stmt);
	if(pid_file && access(pid_file, W_OK) != -1) unlink(pid_file);
}

int main(int argc, char **argv){
	int ret, c, i, if_count = 0;
	FILE *pid_fd = NULL;
	char addr_str[INET6_ADDRSTRLEN];
	struct sockaddr_in *sock_addr;
	struct sockaddr_in6 *sock_addr6;
	struct ifaddrs *interface;
	char *create_stmt = NULL;
	char *index_stmt = NULL;
	char *dbname = DEFAULT_DBFILE_NAME;
	char *db_table_name = DEFAULT_TABLE_NAME;
	char **interface_names = NULL;
#ifndef DEBUG_ENABLED
	int daemonize = 0;
#endif
	
	while((c = getopt(argc, argv, "df:t:a:p:")) != -1){
		switch(c){
#ifndef DEBUG_ENABLED
		case 'd':
			PRINT_DEBUG("process will daemonize");
			daemonize = 1;
			break;
#endif
		case 'f':
			dbname = optarg;
			PRINT_DEBUG("database file set to %s", dbname);
			break;
		case 't':
			record_interval = atoi(optarg);
			PRINT_DEBUG("recording interval set to %u seconds", record_interval);
			break;
		case 'a':
			db_table_name = optarg;
			PRINT_DEBUG("database table set to %s", db_table_name);
			break;
		case 'p':
			pid_file = optarg;
			PRINT_DEBUG("pid file set to %s", pid_file);
			break;
		default:
			ret = EINVAL;
			PRINT_ERROR(ret, "unrecognized option provided");
			goto error;
		}
	}
	
#ifndef DEBUG_ENABLED
	if(daemonize){
		PRINT_DEBUG("daemonizing process");
		ret = daemon(0, 0);
		if(ret){
			ret = errno;
			PRINT_ERROR(ret, "error daemonizing process");
			goto error;
		}
	}
#endif

	if(pid_file){
		PRINT_DEBUG("opening PID file for writing");
		pid_fd = fopen(pid_file, "w");
		if(!pid_fd) {
			ret = errno;
			PRINT_ERROR(ret, "error opening pid file for writing");
			goto error;
		}
		
		PRINT_DEBUG("writing PID to file");
		ret = fprintf(pid_fd, "%d\n", getpid());
		if(ret < 0){
			ret = errno;
			PRINT_ERROR(ret, "error writing pid to pid file");
			goto error;
		}
		
		PRINT_DEBUG("closing PID file");
		fclose(pid_fd);
	}
	
	interface_names = &argv[optind];
	if(argv[optind] && strlen(argv[optind]) == 0 && argc - optind == 1){
		if_count = 0;
		interface_names = NULL;
	}
	else{
		if_count = argc - optind;
	}
	
	PRINT_DEBUG("registering signal handlers %d", signal_action.sa_flags);
	ret = sigaction(SIGTERM, &signal_action, NULL);
	if(ret){
		PRINT_ERROR(ret, "error registering SIGTERM signal handler");
		goto error;
	}
	
	ret = sigaction(SIGINT, &signal_action, NULL);
	if(ret){
		PRINT_ERROR(ret, "error registering SIGINT signal handler");
		goto error;
	}
	
	PRINT_DEBUG("opening sqlite database file %s", dbname);
	ret = sqlite3_open(dbname, &db);
	if(ret){
		PRINT_ERROR(ret, "error opening sqlite database");
		goto error;
	}
	
	PRINT_DEBUG("composing create table statement");
	ret = asprintf(&create_stmt, SQL_SCHEMA_CREATE_STMT, db_table_name);
	if(ret < 0){
		create_stmt = NULL;
		ret = EFAULT;
		PRINT_ERROR(ret, "error composing create table statement");
		goto error;
	}
	
	PRINT_DEBUG("creating table (if it doesnt exist already)");
	ret = sqlite3_exec(db, create_stmt, NULL, NULL, NULL);
	if(ret != SQLITE_OK){
		PRINT_ERROR(ret, "error creating sqlite table for records");
		goto error;
	}
	free(create_stmt);
	create_stmt = NULL;
	
	PRINT_DEBUG("composing create index statement");
	ret = asprintf(&index_stmt, SQL_CREATE_INDEX_STMT, db_table_name);
	if(ret < 0){
		index_stmt = NULL;
		ret = EFAULT;
		PRINT_ERROR(ret, "error composing create index statement");
		goto error;
	}
	
	PRINT_DEBUG("creating timestamp index");
	ret = sqlite3_exec(db, index_stmt, NULL, NULL, NULL);
	if(ret != SQLITE_OK){
		PRINT_ERROR(ret, "error creating timestamp index");
		goto error;
	}
	free(index_stmt);
	index_stmt = NULL;
	
	PRINT_DEBUG("composing insert statement");
	ret = asprintf(&insert_stmt, SQL_INSERT_RECORD_STMT, db_table_name);
	if(ret < 0){
		insert_stmt = NULL;
		ret = EFAULT;
		PRINT_ERROR(ret, "error composing insert statement");
		goto error;
	}
	
	PRINT_DEBUG("fetching list of all network interfaces");
	ret = getifaddrs(&ifaddrs);
	if(ret){
		PRINT_ERROR(ret, "error fetching list of network interfaces");
		goto error;
	}
	
	if(if_count == 0){
		PRINT_DEBUG("no interfaces specified, discovering all network interfaces");
		for(interface = ifaddrs; interface; interface = interface->ifa_next){
			switch(interface->ifa_addr->sa_family){
			case AF_INET:
				sock_addr = (struct sockaddr_in *) interface->ifa_addr;
				inet_ntop(AF_INET, &sock_addr->sin_addr, addr_str, INET_ADDRSTRLEN);
				PRINT_DEBUG("found ipv4 interface %s", interface->ifa_name);
				break;
			case AF_INET6:
				sock_addr6 = (struct sockaddr_in6 *) interface->ifa_addr;
				inet_ntop(AF_INET6, &sock_addr6->sin6_addr, addr_str, INET6_ADDRSTRLEN);
				PRINT_DEBUG("found ipv6 interface %s", interface->ifa_name);
				break;
			default:
				continue;
			}
			
			if_count++;
		}
	}else{
		PRINT_DEBUG("%d interfaces specified, checking that they all exist", if_count);
		for(i = 0; i < if_count; i++){
			if(interface_exists(interface_names[i])) PRINT_DEBUG("found interface %s", interface_names[i]);
			else{
				ret = EINVAL;
				PRINT_ERROR(ret, "could not find interface %s", interface_names[i]);
				goto error;
			}
		}
	}
		
	PRINT_DEBUG("allocating context array");
	throughputd_contexts = malloc(if_count * sizeof(struct throughputd_context));
	if(!throughputd_contexts){
		ret = ENOMEM;
		PRINT_ERROR(ret, "error allocating context array");
		goto error;
	}
	
	PRINT_DEBUG("initializing context array");
	for(interface = ifaddrs; interface; interface = interface->ifa_next){
		if(interface->ifa_addr->sa_family != AF_INET && interface->ifa_addr->sa_family != AF_INET6) continue;
		
		if(interface_names && *interface_names){
			if(!string_is_present(if_count, interface_names, interface->ifa_name)) continue;
			if(context_already_exists(interface->ifa_name)) continue;
		}
		
		PRINT_DEBUG("initialing interface %s", interface->ifa_name);
		ret = initialize_thread_context(&throughputd_contexts[context_count], interface);
		if(ret) goto error;
		
		context_count++;
	}
	
	PRINT_DEBUG("creating recording thread");
	ret = pthread_create(&recording_pthread, NULL, recording_thread, NULL);
	if(ret){
		PRINT_ERROR(ret, "error starting trafic monitoring thread");
		goto error;
	}

	PRINT_DEBUG("joining main thread with recording thread");
	ret = pthread_join(recording_pthread, NULL);
	if(ret){
		PRINT_ERROR(ret, "error joining main thread with recording thread");
		goto error;
	}
	
	throughputd_cleanup();
	return 0;
	
error:
	PRINT_ERROR(ret, "error during main function");
	if(ret == EINVAL) printf(USAGE, argv[0]);
	
	if(create_stmt) free(create_stmt);
	if(index_stmt) free(index_stmt);
	throughputd_cleanup();
	return ret;
}
