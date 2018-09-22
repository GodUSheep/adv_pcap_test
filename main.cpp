#include <pcap.h>
#include <stdio.h>
#include <arpa/inet.h>
#include <net/ethernet.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
void print_eth(u_int8_t *S,int length){
	for(int i=0;i<length;i++){
                if(i!=0)printf(":");
                printf("%02x",S[i]);
        }
	printf("\n");
}

void print_data(u_int8_t *DATA,int length){
	 printf("Data Length : %d\n",length);
         if(length>32)length=32;
	 printf("Data : ");
         for(int i=0;i<length;i++)
         	printf("%02x ",DATA[i]);
}

void print_information(const u_char *packet){
	struct ether_header *ETH=(struct ether_header *)packet;
	printf("Src MAC : ");
	print_eth(ETH->ether_shost,ETH_ALEN);
	printf("Dst MAC : ");
	print_eth(ETH->ether_dhost,ETH_ALEN);
	
	if(ntohs(ETH->ether_type)==ETHERTYPE_IP){
        	packet+=sizeof(struct ether_header);
		struct ip *IP=(struct ip *)packet;
		printf("Src IP : %s\n",inet_ntoa(IP->ip_src));
		printf("Dst IP : %s\n",inet_ntoa(IP->ip_dst));

		if(IP->ip_p==IPPROTO_TCP){
			packet+=IP->ip_hl*4;
			struct tcphdr *TCP=(struct tcphdr *)packet;
			printf("Src Port : %d\n",ntohs(TCP->th_sport));
			printf("Dst Port : %d\n",ntohs(TCP->th_dport));

			u_int8_t *DATA=(u_int8_t *)((u_int8_t *)TCP+TCP->doff*4);
			int length=ntohs(IP->ip_len)-IP->ip_hl*4-TCP->doff*4;
			print_data(DATA,length);
		}
	}
	printf("\n\n");
}
void usage() {
  printf("syntax: pcap_test <interface>\n");
  printf("sample: pcap_test wlan0\n");
}

int main(int argc, char* argv[]) {
  if (argc != 2) {
    usage();
    return -1;
  }

  char* dev = argv[1];
  char errbuf[PCAP_ERRBUF_SIZE];
  pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
  if (handle == NULL) {
    fprintf(stderr, "couldn't open device %s: %s\n", dev, errbuf);
    return -1;
  }

  while (true) {
    struct pcap_pkthdr* header;
    const u_char* packet;
    int res = pcap_next_ex(handle, &header, &packet);
    if (res == 0) continue;
    if (res == -1 || res == -2) break;
    printf("%u bytes captured\n", header->caplen);
    print_information(packet);
    printf("\n");
  }

  pcap_close(handle);
  return 0;
}
