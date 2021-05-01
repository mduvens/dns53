#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <netdb.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <time.h>
#include <sys/time.h>
#include <inttypes.h>


struct timeval start, end;

typedef struct hosts_st {
	char *hostname;
	unsigned int addr_len;
	in_addr_t address;
	time_t expires_on;
	struct hosts_st *prev;
	struct hosts_st *next;
} hosts_t;

typedef struct dns_header_st {
    uint16_t xid;
    uint16_t flags; 
    uint16_t qdcount;
    uint16_t ancount;
    uint16_t nscount; 
    uint16_t arcount; 
} dns_header_t;

typedef struct dns_question_st {
    uint16_t dnstype;
    uint16_t dnsclass;
} dns_question_t;

typedef struct dns_answer_st{
    uint16_t compression;
    uint16_t type;
    uint16_t class;
    uint32_t ttl;
    uint16_t length;
    struct in_addr addr;
} __attribute__((packed)) dns_answer_t;

int decode_hostname(char *dns_payload, char *hostname) {
	char *it = dns_payload + sizeof(dns_header_t);
	int dot = 0;
	int i = 0;
	while (it[i] != '\0') {
		if (i == dot) {
			hostname[i-1] = '.';
			dot += it[dot] + 1;
		} else {
			hostname[i-1] = it[i];	
		}
		i++;
		if (i > 250) {	// Some stupid high value to exit
			return 0;
		}
	}
	hostname[i] = 0;
	return i+1;
}

/* Should be 53, but when developping I do not want to change my dns server */
#define PORT 15353	

#define MAX_LENGTH 1024

/*
 * error - wrapper for perror
 */
void error(char *msg) {
	perror(msg);
	exit(1);
}

ssize_t read_hosts(char *hostfile, hosts_t** hosts_queue) {
	FILE *fh = fopen(hostfile, "rt");
	if (fh == NULL)
        error("Cannot open hosts file");

	char * line = NULL;
	size_t len = 0;
	ssize_t read;

	hosts_t *record;
	ssize_t records = 0;
	char ip[20];
	char hostname[128];
 	while ((read = getline(&line, &len, fh)) != -1) {
 		if ((read > 3) && (line[0] != '#')) {
        	sscanf(line, "%s %s", ip, hostname);
        	record = (hosts_t*)calloc(1, sizeof(hosts_t));
        	record->next = NULL;
        	record->next = *hosts_queue;	// Insert at head
        	if (record->next)
        		record->next->prev = record;	// Next point back to me
        	*hosts_queue = record;
        	record->hostname = strdup(hostname);
        	record->address = inet_addr(ip);
        	record->addr_len = 4;
        	record->expires_on = 0;
        	records++;
        }
    }
    fclose(fh);
    if(line){
		free(line);
	}
    	
	return records;
}

ssize_t dns_query(char *dns_server, int port, char *payload, unsigned int payload_len) {
	//Forwarding request to 1.1.1.1

	// Create udp socket
	int sock_fd = socket(AF_INET, SOCK_DGRAM, 0);

	struct sockaddr_in address;
    address.sin_addr.s_addr = inet_addr(dns_server);    // Convert IPv4 address string to binary representation
	address.sin_family = AF_INET;
    address.sin_port = htons(port);

    sendto(sock_fd, payload, payload_len, 0, (struct sockaddr*) &address, sizeof(struct sockaddr_in));	// Should check return
    socklen_t src_addr_len = 0;
    memset(payload, 0, MAX_LENGTH);        // Set payload to 0
    ssize_t len = recvfrom(sock_fd, payload, MAX_LENGTH, 0, (struct sockaddr *) &address, (socklen_t*) &src_addr_len);

    // for (int i = 0; i < len; i++) {
    //     if ((i % 8) == 0) printf("\t");
    //     if ((i % 16) == 0) printf("\n");
    //     printf(" %02X", (unsigned char)payload[i]);
    // }
	// printf("\n\n");
	fflush(stdout);

    return len;
}

int compare(char *a, char *b) {
	if ((a == NULL) || (b == NULL))
		return 0;
	int i = 0;
	while (a[i] != '\0') {
		if (a[i] != b[i])
			return 0;
		i++;
	}
	return (a[i] == b[i]);
}

hosts_t *find_in_queue(hosts_t *queue, char *hostname) {
	time_t now = time(NULL);
	hosts_t *it = queue;
	while (it != NULL) {
		//printf("%s - %u\n", it->hostname, it->expires_on);
		if (compare(hostname, it->hostname) == 1) {
			return it;
		}
		if ((it->expires_on > 0) && (it->expires_on < now)) {
			// remove stale elements
			hosts_t *tmp = it;
			if (it->prev)
				it->prev->next = it->next;
			if (it->next)
				it->next->prev = it->prev;
			free(tmp->hostname);
			free(tmp);
			it = it->next;
		} else
			it = it->next;
	}
	return NULL;
}

int add_to_queue(hosts_t **queue, char *hostname, in_addr_t *address, unsigned int addr_len, unsigned int ttl) {
	hosts_t *record = (hosts_t*)calloc(1, sizeof(hosts_t));
	if (record == NULL)
		return 0;
	record->prev = NULL;
	record->next = *queue;	// Insert at head
	if (record->next)
		record->next->prev = record;	// Next point back to me
	*queue = record;
	record->hostname = strdup(hostname);
	memcpy(&record->address, address, addr_len);
	record->addr_len = addr_len;
	record->expires_on = time(NULL) + ttl;
	return 1;
}		
int createDNSresponse(char *udp_payload, hosts_t *record, int hostname_len){
	dns_header_t *dns_header = (dns_header_t *)udp_payload;
	dns_header->flags = htons(ntohs(dns_header->flags)|(1<<15)|(1<<7));	// Answer
	dns_header->ancount = htons(1);
	// dns_question_t *dns_question = (dns_question_t*)(udp_payload + sizeof(dns_header_t));
	dns_answer_t *dns_answer = (dns_answer_t *)(udp_payload + sizeof(dns_header_t) + sizeof(dns_question_t) + hostname_len);
	dns_answer->compression = htons((3<<14) | sizeof(dns_header_t));
	dns_answer->type = htons(1);
	dns_answer->class = htons(1);
	dns_answer->ttl = htonl(3600);
	dns_answer->length = htons(record->addr_len);
	memcpy(&dns_answer->addr, &record->address, record->addr_len);
	return sizeof(dns_header_t) + sizeof(dns_answer_t) + sizeof(dns_question_t) + hostname_len;
}
int main(int argc, char *argv[]) {
	int sockfd;						/* socket */
	struct sockaddr_in serveraddr;	/* server's addr */
	struct sockaddr_in clientaddr;	/* client addr */
	int optval;						/* flag value for setsockopt */
	int len;						/* message byte size */

	hosts_t *host_records = NULL;
	hosts_t *cache_records = NULL;

	read_hosts(argv[1], &host_records);

	// Data sections
	char udp_payload[MAX_LENGTH]; 	/* UDP Payload */
	unsigned char control[CMSG_SPACE(sizeof(struct in_pktinfo))];	/* Control messages */


	// Related to getting destination IP from received packets
	struct msghdr msg;
	struct cmsghdr *cmsg;
	struct iovec iov[1];

	struct in_pktinfo *pktinfo;		/* To set the source IP address in a response */

	unsigned int interface_idx;		// Interface index of the received packet
	struct in_addr recv_dest_addr;	// Destination address of the received packet

	/* 
	 * socket: create the parent socket 
	 */
	sockfd = socket(AF_INET, SOCK_DGRAM, 0);
	if (sockfd < 0)
		error("ERROR opening socket");

	/* setsockopt: Handy debugging trick that lets 
	 * us rerun the server immediately after we kill it; 
	 * otherwise we have to wait about 20 secs. 
	 * Eliminates "ERROR on binding: Address already in use" error. 
	 */
	optval = 1;
	if (setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, (const void *)&optval, sizeof(int))  == -1)
		error("setsockopt - reuse address");
	
	/* Allow us to retrieve the received packets' destination address */
	if (setsockopt(sockfd, IPPROTO_IP, IP_PKTINFO, (const void *)&optval, sizeof(int))  == -1)
		error("setsockopt - ip packet info");

	/*
	 * build the server's Internet address
	 * We listen to all addresses and send the response from the received packets
	 * destination address, so it should always be accepted.
	 */
	memset(&serveraddr, 0, sizeof serveraddr);
	serveraddr.sin_family = AF_INET;
	serveraddr.sin_addr.s_addr = htonl(INADDR_ANY);
	serveraddr.sin_port = htons(PORT);

	/* 
	 * bind: associate the parent socket with a port 
	 */
	if (bind(sockfd, (struct sockaddr *)&serveraddr, sizeof(struct sockaddr_in )) == -1)
		error("ERROR on binding");

	iov[0].iov_base = udp_payload;
	iov[0].iov_len = MAX_LENGTH;		// On receive set to max buffer length

	/* Tricky header stuff for more control */
	memset(&msg, 0, sizeof(struct msghdr));
	msg.msg_name = &clientaddr;
	msg.msg_namelen = sizeof(struct sockaddr_in);
	msg.msg_iov = iov;
	msg.msg_iovlen = 1;
	msg.msg_control = &control;
	msg.msg_controllen = sizeof(control);


	/* 
	 * main loop: wait for a datagram, then echo it
	 */
	while (1) {
		/*
		 * recvfrom: receive a UDP datagram from a client
		 */
		memset(udp_payload, 0, MAX_LENGTH);
		interface_idx = (unsigned int) -1;	// So we can check for the correct one

		len = recvmsg(sockfd, &msg, 0);
		if (len < 0)
			error("ERROR in recvfrom");

		gettimeofday(&start,0);
		// save current time in usecs
		for (cmsg = CMSG_FIRSTHDR(&msg); cmsg != NULL; cmsg = CMSG_NXTHDR(&msg, cmsg)) {
			if ((cmsg->cmsg_level == IPPROTO_IP) && (cmsg->cmsg_type == IP_PKTINFO)) {
				pktinfo = (struct in_pktinfo *)(CMSG_DATA(cmsg));
				interface_idx = pktinfo->ipi_ifindex;
				recv_dest_addr = pktinfo->ipi_addr;
			}
		}

		/*
		 * NOTE: A lot of times these helper functions, like inet_ntoa,
		 * use a static buffer. This means any call to inet_ntoa will
		 * change the static buffer, so you can only use it once in 
		 * every printf!
		 */
		// printf("Received payload (%ld bytes) from %s:%hu",
		// 	(long)len,
		// 	inet_ntoa(clientaddr.sin_addr), 
		// 	ntohs(clientaddr.sin_port));
		// printf(" to %s via interface %u:\n", 
		// 	inet_ntoa(recv_dest_addr),
		// 	interface_idx);

	    // for (int i = 0; i < len; i++) {
	    //     if ((i % 8) == 0) printf("\t");
	    //     if ((i % 16) == 0) printf("\n");
	    //     printf(" %02X", (unsigned char)udp_payload[i]);
	    // }
	    // printf("\n\n");

	    char hostname[128] = {0}; // "long" enough
	    int hostname_len = decode_hostname(udp_payload, hostname);

	    fflush(stdout);

	    // Let's find an IP for <hostname>
	    hosts_t *record = find_in_queue(host_records, hostname);
	    if (record == NULL) {
	    	// Not in hosts file
		    record = find_in_queue(cache_records, hostname);
		}			
	    if (record == NULL) {
	    	// Not in cache
	    } 
	    if (record == NULL) { 
	    	// Not found, make an external query
		    iov[0].iov_len = dns_query("1.1.1.1", 53, udp_payload, len);
		    dns_answer_t *dns_answer = (dns_answer_t *)(udp_payload + sizeof(dns_header_t) + sizeof(dns_question_t) + hostname_len);
	    	if (ntohs(dns_answer->type) == 1)
				add_to_queue(&cache_records, hostname, (in_addr_t*)&dns_answer->addr, ntohs(dns_answer->length), ntohl(dns_answer->ttl));
	    } else {
	    	// Create a response by hand	
	    	iov[0].iov_len = createDNSresponse(udp_payload,record,hostname_len);
	    }
 		fflush(stdout);
		/* 
		 * sendto: echo the input back to the client 
		 */

		// Set the correct source address
	    cmsg = CMSG_FIRSTHDR(&msg);
		cmsg->cmsg_level = IPPROTO_IP;
		cmsg->cmsg_type = IP_PKTINFO;
		cmsg->cmsg_len = CMSG_LEN(sizeof(struct in_pktinfo));
		pktinfo = (struct in_pktinfo*) CMSG_DATA(cmsg);
		pktinfo->ipi_ifindex = interface_idx;
		pktinfo->ipi_spec_dst = recv_dest_addr;
		len = sendmsg(sockfd, &msg, 0);
		if (len < 0)
			error("ERROR in sendmsg");
	
		// Print usecs for call
		gettimeofday(&end, 0);
		long seconds = end.tv_sec - start.tv_sec;
		long microseconds = end.tv_usec - start.tv_usec;
		double execution_time = seconds + microseconds*1e-6;
		printf("DONE \n",execution_time);
		
		printf("Took %.3f seconds\n",execution_time);
	}
}
