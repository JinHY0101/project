#include<stdio.h>	
#include<stdlib.h>				
#include<string.h>		
#include<netinet/in.h>			//프로토콜 및 호스트 이름을 숫자 주소로 변환하는 기능을 정의
#include<errno.h>				// errno 변수를 검사
#include<netdb.h>				//서비스 데이터베이스
#include<sys/ioctl.h>
#include<unistd.h>
#include<sys/socket.h>
#include<arpa/inet.h>			//숫자로 IP 주소를 조작하는 기능의 정의
#include<netinet/ip_icmp.h>		// icmp 헤더 선언
#include<netinet/tcp.h>			// TCP 헤더 선언
#include<netinet/udp.h>			// UDP 헤더 선언
#include<netinet/ip.h>			// IP 헤더  선언
#include<netinet/if_ether.h>	// Ethernet 헤더 선언
#include<net/ethernet.h>		
#include<sys/types.h>
#include<sys/time.h>


void ProcessPacket(unsigned char*, int, int, char ip_addr[]);
void print_ip_header(unsigned char*, int);
void print_tcp_packet(unsigned char *, int);
void print_udp_packet(unsigned char *, int);
void print_icmp_packet(unsigned char *, int);
void PrintData(unsigned char*, int);
void icmp_packet(unsigned char* Buffer, int Size);
void tcp_packet(unsigned char* Buffer, int Size);
void print_ip_header(unsigned char* Buffer, int Size);
void udp_packet(unsigned char *Buffer, int Size);

struct sockaddr_in source, dest;

int main()
{
	int saddr_size, data_size;
	struct sockaddr saddr;
	int num;
	unsigned char *buffer = (unsigned char *)malloc(65536); // 충분한 크기의 버퍼 할당
	unsigned char ip_addr[16];

	while (1) {
		printf("Select Protocol field \n 1. HTTP  2. DNS  3.ICMP\n ");
		scanf("%d", &num);
		if (num == 1){
			printf("Select IP");
			scanf("%d", ip_addr);
	}
		if (num <= 3 && num > 0)
			break;
		printf("Wrong! Select 1~3\n");
		printf("1. HTTP  2. DNS  3.ICMP\n ");

	}
	printf("Starting...\n");

	int sock_raw = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
	//raw socket 생성

	if (sock_raw < 0)
	{
		perror("Socket Error");
		return 1;
	}
	while (1)
	{
		saddr_size = sizeof saddr;

		data_size = recvfrom(sock_raw, buffer, 65536, 0, &saddr, (socklen_t*)&saddr_size);
		if (data_size <0)
		{
			printf("Recvfrom error , failed to get packets\n");
			return 1;
		}

		icmp_packet(buffer, data_size);
		tcp_packet(buffer, data_size);
		udp_packet(buffer, data_size);
		ProcessPacket(buffer, data_size, num, ip_addr[);
	}
	close(sock_raw);
	printf("Finished");
	return 0;
}


void ProcessPacket(unsigned char* buffer, int size, int num, char ip_addr[[])
{
	//이더넷 헤더를 제외하고 IP헤더만 받아옴
	struct iphdr *iph = (struct iphdr*)(buffer + sizeof(struct ethhdr));
	struct tcphdr *tcph;
	struct udphdr *udph;
	struct icmp *icmph;
	int header_size = 0;
	unsigned short iphdrlen = iph->ihl * 4;
	unsigned int protocol = iph->protocol;

	if (protocol == 6) {
		tcph = (struct tcphdr*)(buffer + iphdrlen + sizeof(struct ethhdr));
		header_size = sizeof(struct ethhdr) + iphdrlen + tcph->doff * 4;
	}
	else if (protocol == 17) {
		udph = (struct udphdr*)(buffer + iphdrlen + sizeof(struct ethhdr));
	}
	else if (protocol == 1) {
		icmph = (struct icmp*)(buffer + iphdrlen + sizeof(struct ethhdr));
	}

	char      src_ip_addr[16];
	char      dst_ip_addr[16];
	char s1[16];
	char s2[16];

	strncpy(dst_ip_addr, inet_ntoa(dest.sin_addr), 16);
	strncpy(src_ip_addr, inet_ntoa(source.sin_addr), 16);
	strncpy(s1, ip_addr, 16);

	switch (num) {
	case 1:
		// HTTP 프로토콜 필터링
		if (strcmp(dst_ip_addr, s1) == 0 || strcmp(src_ip_addr, s1) == 0)
			if (protocol == 6) {
				print_tcp_packet(buffer, size);
			}
		break;

	case 2:
		// DNS 프로토콜 필터링
		if (protocol == 17) {
			print_udp_packet(buffer, size);
		}
		break;
	case 3:
		// ICMP 프로토콜 필터링 
		if (protocol == 1) {
			print_icmp_packet(buffer, size);
			break;
		}
	}
}

// 이더넷 헤더 출력 함수
void print_ethernet_header(unsigned char* Buffer, int Size)
{
	struct ethhdr* eth = (struct ethhdr*)Buffer;

	printf("\n");
	printf("Ethernet Header ----------------------------------------------------------------\n");
	printf("|   |-Destination Address : %.2X-%.2X-%.2X-%.2X-%.2X-%.2X \n", eth->h_dest[0], eth->h_dest[1], eth->h_dest[2], eth->h_dest[3], eth->h_dest[4], eth->h_dest[5]);
	printf("|   |-Source Address      : %.2X-%.2X-%.2X-%.2X-%.2X-%.2X \n", eth->h_source[0], eth->h_source[1], eth->h_source[2], eth->h_source[3], eth->h_source[4], eth->h_source[5]);
	printf("|   |-Protocol            : %u \n", (unsigned short)eth->h_proto);
	printf("--------------------------------------------------------------------------------\n");
}

// IP헤더 출력 함수
void print_ip_header(unsigned char* Buffer, int Size)
{
	print_ethernet_header(Buffer, Size);

	unsigned short iphdrlen;

	struct iphdr* iph = (struct iphdr*)(Buffer + sizeof(struct ethhdr));
	iphdrlen = iph->ihl * 4;

	memset(&source, 0, sizeof(source));
	source.sin_addr.s_addr = iph->saddr;

	memset(&dest, 0, sizeof(dest));
	dest.sin_addr.s_addr = iph->daddr;

	printf("\n");
	printf("IP Header -----------------------------------------------------------------------\n");
	printf("|   |-IP Version        : %d\n", (unsigned int)iph->version);
	printf("|   |-IP Header Length  : %d DWORDS or %d Bytes\n", (unsigned int)iph->ihl, ((unsigned int)(iph->ihl)) * 4);
	printf("|   |-Type Of Service   : %d\n", (unsigned int)iph->tos);
	printf("|   |-IP Total Length   : %d  Bytes(Size of Packet)\n", ntohs(iph->tot_len));
	printf("|   |-Identification    : %d\n", ntohs(iph->id));
	//printf(logfile , "   |-Reserved ZERO Field   : %d\n",(unsigned int)iphdr->ip_reserved_zero);
	//printf(logfile , "   |-Dont Fragment Field   : %d\n",(unsigned int)iphdr->ip_dont_fragment);
	//printf(logfile , "   |-More Fragment Field   : %d\n",(unsigned int)iphdr->ip_more_fragment);
	printf("|   |-TTL      : %d\n", (unsigned int)iph->ttl);
	printf("|   |-Protocol : %d\n", (unsigned int)iph->protocol);
	printf("|   |-Checksum : %d\n", ntohs(iph->check));
	printf("|   |-Source IP        : %s\n", inet_ntoa(source.sin_addr));
	printf("|   |-Destination IP   : %s\n", inet_ntoa(dest.sin_addr));
	printf("--------------------------------------------------------------------------------\n");

}

void ip_header(unsigned char* Buffer, int Size)
{
	unsigned short iphdrlen;

	struct iphdr *iph = (struct iphdr *)(Buffer + sizeof(struct ethhdr));
	iphdrlen = iph->ihl * 4;

	memset(&source, 0, sizeof(source));
	source.sin_addr.s_addr = iph->saddr;

	memset(&dest, 0, sizeof(dest));
	dest.sin_addr.s_addr = iph->daddr;
}


void icmp_packet(unsigned char* Buffer, int Size)
{
	unsigned short iphdrlen;

	struct iphdr *iph = (struct iphdr *)(Buffer + sizeof(struct ethhdr));
	iphdrlen = iph->ihl * 4;

	struct icmp *icmph = (struct icmp*)(Buffer + iphdrlen + sizeof(struct ethhdr));

	int header_size = sizeof(struct ethhdr) + iphdrlen + sizeof icmph;
	ip_header(Buffer, Size);
}



void print_icmp_packet(unsigned char* Buffer, int Size)
{
	unsigned short iphdrlen;

	struct iphdr* iph = (struct iphdr*)(Buffer + sizeof(struct ethhdr));
	iphdrlen = iph->ihl * 4;

	struct icmphdr* icmph = (struct icmphdr*)(Buffer + iphdrlen + sizeof(struct ethhdr));

	int header_size = sizeof(struct ethhdr) + iphdrlen + sizeof icmph;

	printf("\n\n***********************ICMP Packet*************************\n");

	print_ip_header(Buffer, Size);

	printf("\n");

	printf("ICMP Header  -------------------------------------------------------------------\n");
	printf("|   |-Type : %d", (unsigned int)(icmph->type));

	if ((unsigned int)(icmph->type) == 11)
	{
		printf("  (TTL Expired)\n");
	}
	else if ((unsigned int)(icmph->type) == ICMP_ECHOREPLY)
	{
		printf("  (ICMP Echo Reply)\n");
	}

	printf("|   |-Code : %d\n", (unsigned int)(icmph->code));
	printf("|   |-Checksum : %d\n", ntohs(icmph->checksum));
	//printf(logfile , "   |-ID       : %d\n",ntohs(icmph->id));
	//printf(logfile , "   |-Sequence : %d\n",ntohs(icmph->sequence));
	printf("--------------------------------------------------------------------------------\n");

	printf("\n");

	printf("IP Header\n");
	PrintData(Buffer, iphdrlen);

	printf("UDP Header\n");
	PrintData(Buffer + iphdrlen, sizeof icmph);

	printf("Data Payload\n");

	PrintData(Buffer + header_size, (Size - header_size));

	printf("\n###########################################################");
}


void print_tcp_packet(unsigned char* Buffer, int Size)
{
	unsigned short iphdrlen;

	struct iphdr* iph = (struct iphdr*)(Buffer + sizeof(struct ethhdr));
	iphdrlen = iph->ihl * 4;

	struct tcphdr* tcph = (struct tcphdr*)(Buffer + iphdrlen + sizeof(struct ethhdr));

	int header_size = sizeof(struct ethhdr) + iphdrlen + tcph->doff * 4;

	printf("\n\n***********************TCP Packet*************************\n");

	print_ip_header(Buffer, Size);

	printf("\n");
	printf("TCP Header ----------------------------------------------------------------------\n");
	printf("|   |-Source Port      : %u\n", ntohs(tcph->source));
	printf("|   |-Destination Port : %u\n", ntohs(tcph->dest));
	printf("|   |-Sequence Number    : %u\n", ntohl(tcph->seq));
	printf("|   |-Acknowledge Number : %u\n", ntohl(tcph->ack_seq));
	printf("|   |-Header Length      : %d DWORDS or %d BYTES\n", (unsigned int)tcph->doff, (unsigned int)tcph->doff * 4);
	//printf(logfile , "   |-CWR Flag : %d\n",(unsigned int)tcph->cwr);
	//printf(logfile , "   |-ECN Flag : %d\n",(unsigned int)tcph->ece);
	printf("|   |-Urgent Flag          : %d\n", (unsigned int)tcph->urg);
	printf("|   |-Acknowledgement Flag : %d\n", (unsigned int)tcph->ack);
	printf("|   |-Push Flag            : %d\n", (unsigned int)tcph->psh);
	printf("|   |-Reset Flag           : %d\n", (unsigned int)tcph->rst);
	printf("|   |-Synchronise Flag     : %d\n", (unsigned int)tcph->syn);
	printf("|   |-Finish Flag          : %d\n", (unsigned int)tcph->fin);
	printf("|   |-Window         : %d\n", ntohs(tcph->window));
	printf("|   |-Checksum       : %d\n", ntohs(tcph->check));
	printf("|   |-Urgent Pointer : %d\n", tcph->urg_ptr);
	printf("--------------------------------------------------------------------------------\n");

	printf("\n");
	printf("                        DATA Dump                         ");
	printf("\n");

	printf("IP Header\n");
	PrintData(Buffer, iphdrlen);

	printf("TCP Header\n");
	PrintData(Buffer + iphdrlen, tcph->doff * 4);

	printf("Data Payload\n");
	PrintData(Buffer + header_size, Size - header_size);

	printf("\n###########################################################");
}


void tcp_packet(unsigned char* Buffer, int Size)
{
	unsigned short iphdrlen;

	struct iphdr *iph = (struct iphdr *)(Buffer + sizeof(struct ethhdr));
	iphdrlen = iph->ihl * 4;

	struct tcphdr *tcph = (struct tcphdr*)(Buffer + iphdrlen + sizeof(struct ethhdr));

	int header_size = sizeof(struct ethhdr) + iphdrlen + tcph->doff * 4;
	ip_header(Buffer, Size);
}

void print_udp_packet(unsigned char *Buffer, int Size)
{

	unsigned short iphdrlen;

	struct iphdr* iph = (struct iphdr*)(Buffer + sizeof(struct ethhdr));
	iphdrlen = iph->ihl * 4;

	struct udphdr* udph = (struct udphdr*)(Buffer + iphdrlen + sizeof(struct ethhdr));

	int header_size = sizeof(struct ethhdr) + iphdrlen + sizeof udph;

	printf("\n\n***********************UDP Packet*************************\n");

	print_ip_header(Buffer, Size);

	printf("\nUDP Header  ------------------------------------------------------------------\n");
	printf("|   |-Source Port      : %d\n", ntohs(udph->source));
	printf("|   |-Destination Port : %d\n", ntohs(udph->dest));
	printf("|   |-UDP Length       : %d\n", ntohs(udph->len));
	printf("|   |-UDP Checksum     : %d\n", ntohs(udph->check));
	printf("--------------------------------------------------------------------------------\n");


	printf("\n");
	printf("IP Header\n");
	PrintData(Buffer, iphdrlen);

	printf("UDP Header\n");
	PrintData(Buffer + iphdrlen, sizeof udph);

	printf("Data Payload\n");

	PrintData(Buffer + header_size, Size - header_size);

	printf("\n###########################################################");
}

void udp_packet(unsigned char *Buffer, int Size)
{
	unsigned short iphdrlen;

	struct iphdr *iph = (struct iphdr *)(Buffer + sizeof(struct ethhdr));
	iphdrlen = iph->ihl * 4;

	struct udphdr *udph = (struct udphdr*)(Buffer + iphdrlen + sizeof(struct ethhdr));

	int header_size = sizeof(struct ethhdr) + iphdrlen + sizeof udph;

	ip_header(Buffer, Size);
}

void PrintData(unsigned char* data, int Size)
{
	int i, j;
	for (i = 0; i < Size; i++)
	{
		if (i != 0 && i % 16 == 0)
		{
			printf("         ");
			for (j = i - 16; j<i; j++)
			{
				if (data[j] >= 32 && data[j] <= 128)
					printf("%c", (unsigned char)data[j]);

				else printf(".");
			}
			printf("\n");
		}

		if (i % 16 == 0) printf("   ");
		printf(" %02X", (unsigned int)data[i]);
		if (i == Size - 1)
		{
			for (j = 0; j<15 - i % 16; j++)
			{
				printf("   ");
			}

			printf("         ");

			for (j = i - i % 16; j <= i; j++)
			{
				if (data[j] >= 33 && data[j] <= 127)
				{
					printf("%c", (unsigned char)data[j]);
				}
				else
				{
					printf(".");
				}
			}

			printf("\n");
		}
	}
}