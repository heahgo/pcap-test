#include <pcap.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdint.h>
#include <netinet/in.h>

typedef struct ether_header {
  uint8_t dst[6]; 
  uint8_t src[6];      
  uint16_t type;                    
} ETH_HEAD;

typedef struct ip_header {
    uint8_t ver_headLen;    
    uint8_t tos;
    uint16_t tot_len;
    uint16_t id;
    uint16_t frag_off;
    uint8_t ttl;
    uint8_t protocol;
    uint16_t check;
    uint8_t saddr[4];
    uint8_t daddr[4];
  } IP_HEAD;

typedef struct tcp_header
  {
    uint16_t sport;
    uint16_t dport; 
    uint32_t seq;    
    uint32_t ack;   
    uint8_t offset_reserved;
    uint8_t flags;
    uint16_t win;   
    uint16_t sum;      
    uint16_t urp;
} TCP_HEAD;


void usage() {
	printf("syntax: pcap-test <interface>\n");
	printf("sample: pcap-test wlan0\n");
}

typedef struct {
	char* dev_;
} Param;

Param param  = {
	.dev_ = NULL
};

bool parse(Param* param, int argc, char* argv[]) {
	if (argc != 2) {
		usage();
		return false;
	}
	param->dev_ = argv[1];
	return true;
}

int main(int argc, char* argv[]) {
	if (!parse(&param, argc, argv))
		return -1;

	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t* pcap = pcap_open_live(param.dev_, BUFSIZ, 1, 1000, errbuf);
	if (pcap == NULL) {
		fprintf(stderr, "pcap_open_live(%s) return null - %s\n", param.dev_, errbuf);
		return -1;
	}

	while (true) {
		struct pcap_pkthdr* header;
		const u_char* packet;
		int res = pcap_next_ex(pcap, &header, &packet);
		if (res == 0) continue;
		if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK) {
			printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(pcap));
			break;	
		}

		ETH_HEAD *eth = (ETH_HEAD *)packet;
		IP_HEAD *ip = (IP_HEAD *)(packet + sizeof(ETH_HEAD));
		uint16_t ip_total_len = ntohs(ip->tot_len);
		uint16_t ip_head_len = (ip->ver_headLen & 15) * 4;
		TCP_HEAD *tcp = (TCP_HEAD *)(packet + sizeof(ETH_HEAD) + ip_head_len);
		uint16_t tcp_head_len = (tcp->offset_reserved >> 4) * 4;
		uint16_t data_len = ip_total_len - ip_head_len - tcp_head_len;
		uint8_t *data = (uint8_t *)(packet + sizeof(ETH_HEAD) + ip_head_len + tcp_head_len); 

		if (ntohs(eth->type) != 0x800 || ip->protocol != 6)
			continue;

		printf("\nsrc mac: %02x:%02x:%02x:%02x:%02x:%02x   ", eth->src[0], eth->src[1], eth->src[2], eth->src[3], eth->src[4],eth->src[5]);
		printf("dst mac: %02x:%02x:%02x:%02x:%02x:%02x \n", eth->dst[0], eth->dst[1], eth->dst[2], eth->dst[3], eth->dst[4], eth->dst[5]);

		printf("src ip : %d.%d.%d.%d   ", ip->saddr[0], ip->saddr[1], ip->saddr[2], ip->saddr[3]);
		printf("dst ip : %d.%d.%d.%d \n", ip->daddr[0], ip->daddr[1], ip->daddr[2], ip->daddr[3]);

		printf("src port : %hu   dst port : %hu\n", ntohs(tcp->sport), ntohs(tcp->dport));
		
		uint16_t len;
		if (data_len <= 10) 
			len = data_len;
		else
			len = 10;
		
		if (data_len == 0)
			printf("no data\n");
		for (uint8_t i = 0; i < len; i++) {
			if (i == 0)
				printf("data : ");
			printf("%02x", *(data + i));
			if (i == len - 1)
				printf("\n");
		}
	}
	pcap_close(pcap);
}