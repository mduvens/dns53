#include<stdio.h> 
#include<string.h>   
#include<stdlib.h>    
#include<sys/socket.h>    
#include<arpa/inet.h> 
#include<netinet/in.h>
#include<unistd.h>
#include <time.h>
#include <assert.h>

/* Should be 53, but when developping I do not want to change my dns server */
#define PORT 15353	

#define MAX_LENGTH 1024

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

typedef struct {
    uint16_t compression;
    uint16_t type;
    uint16_t class;
    uint32_t ttl;
    uint16_t length;
    struct in_addr addr;
} __attribute__((packed)) dns_record_a;

void DieWithError(char*errorMessage){
    perror(errorMessage);
    exit(1);
}

/*
 * Just parse the buffer manually and create the encoded version
 */
int encode_hostname(char *dest, char *hostname) {
    // www.google.com
    //  3www
    //  6google
    //  3com 
    //  0
    int len = strlen(hostname);
    int j = 1; // index for destination
    int prev = 0;
    int word_len = 0;
    for (int i = 0; i < len; i++) {
        if ((hostname[i] != '\0') && (hostname[i] != '.')) {
            dest[j] = hostname[i];
            word_len++;
            j++;
        } else {
            dest[prev] = word_len;
            prev += word_len + 1;
            word_len = 0;
            j++;
        }
    }
    dest[prev] = word_len;
    dest[j] = 0;
    return j+1;
}
/*
 * Use strtok to parse the stream, should be more pretty, but
 * not too sure about that
 */
int encode_hostname2(char *dest, char *hostname) {
    // www.google.com
    //  3www
    //  6google
    //  3com 
    //  0
    char *token = strtok(hostname, ".");
    
    int len = 0;
    int offset = 0;
    while (token != NULL) {
        len = strlen(token);
        dest[offset] = len;
        offset++;
        strncpy(dest+offset, token, len);
        offset += len;
        token = strtok(NULL, ".");
    }
    dest[offset] = 0;
    return offset+1;
}

ssize_t dns_query(char *dns_server, int port, char *payload, unsigned int payload_len) {
	// Create udp socket
	int sock_fd = socket(AF_INET, SOCK_DGRAM, 0);

	struct sockaddr_in address;
    address.sin_addr.s_addr = inet_addr(dns_server);    // Convert IPv4 address string to binary representation
	address.sin_family = AF_INET;
    address.sin_port = htons(port);

    ssize_t len = sendto(sock_fd, payload, payload_len, 0, (struct sockaddr*) &address, sizeof(struct sockaddr_in));
    socklen_t src_addr_len = 0;
    memset(payload, 0, MAX_LENGTH);        // Set payload to 0
    len = recvfrom(sock_fd, payload, MAX_LENGTH, 0, (struct sockaddr *) &address, (socklen_t*) &src_addr_len);
    return len;
}

int main(int argc, char *argv[]){
	if (argc != 3) {
		printf("Wrong arguments\n");
		return 0;
	}

	srand(time(NULL));	// initialize the random generator with a always changing number

	char *dns_server = argv[1];
	char *hostname = argv[2];

    char *udp_payload = calloc(MAX_LENGTH, sizeof(char));   // Allocate and set to 0

    int offset = 0;
    dns_header_t *dns_header = (dns_header_t *)(udp_payload + offset);
    dns_header->xid = htons(rand());     // Should be random
    dns_header->flags = htons(0x0100);   // 01 - Read, 00 - Question
    dns_header->qdcount = htons(1);      // argv[2] is only one hostname to resolve, so only one question
    offset += sizeof(dns_header_t);  	// Offset for name

    offset += encode_hostname2(udp_payload + offset, hostname);            //  Encode hostname

    dns_question_t *dns_question = (dns_question_t *)(udp_payload + offset);
    dns_question->dnsclass = htons(1);   // Type A
    dns_question->dnstype = htons(1);    // Class Internet
    offset += sizeof(dns_question_t);

	ssize_t len = dns_query(dns_server, PORT, udp_payload, offset);

    printf("Received payload:");
    for (int i = 0; i < len; i++) {
        if ((i % 8) == 0) printf("\t");
        if ((i % 16) == 0) printf("\n");
        printf(" %02X", (unsigned char)udp_payload[i]);
    }
    printf("\n\n");
    // fflush(stdout);

    dns_header_t *response_header = (dns_header_t *)udp_payload;
    assert((ntohs (response_header->flags) & 0xf) == 0);

    uint8_t *start_of_name =(uint8_t *) (udp_payload + sizeof (dns_header_t));
    uint8_t total = 0;
    uint8_t *field_length = start_of_name;

    while (*field_length != 0){
        total += *field_length + 1;
        *field_length = '.';
        field_length = start_of_name + total;
    }
    
    *field_length = '\0';

    /* Skip null byte, qtype, and qclass to get to first answer */
    dns_record_a *records = (dns_record_a *) (field_length + 5);

    for (int i = 0; i < ntohs (response_header->ancount); i++){
        printf ("TYPE: %d\n", ntohs(records[i].type));
        printf ("CLASS: %d" "\n", ntohs(records[i].class));
        printf ("TTL: %d\n", ntohl(records[i].ttl));
        printf ("IPv4: %s\n", inet_ntoa(records[i].addr));
    }
    fflush(stdout);
	return 0;
}