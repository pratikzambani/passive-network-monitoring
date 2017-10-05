#include<stdio.h>
#include<stdlib.h>
#include<signal.h>
#include<time.h>
#include<netinet/if_ether.h>
#include<pcap.h>
#include<arpa/inet.h>

/* default snap length (maximum bytes per packet to capture) */
#define SNAP_LEN 1518

/* ethernet headers are always exactly 14 bytes [1] */
#define SIZE_ETHERNET 14

/* Ethernet addresses are 6 bytes */
#define ETHER_ADDR_LEN	6

/* Ethernet header */
struct sniff_ethernet {
        u_char  ether_dhost[ETHER_ADDR_LEN];    /* destination host address */
        u_char  ether_shost[ETHER_ADDR_LEN];    /* source host address */
        u_short ether_type;                     /* IP? ARP? RARP? etc */
};

/* IP header */
struct sniff_ip {
        u_char  ip_vhl;                 /* version << 4 | header length >> 2 */
        u_char  ip_tos;                 /* type of service */
        u_short ip_len;                 /* total length */
        u_short ip_id;                  /* identification */
        u_short ip_off;                 /* fragment offset field */
        #define IP_RF 0x8000            /* reserved fragment flag */
        #define IP_DF 0x4000            /* dont fragment flag */
        #define IP_MF 0x2000            /* more fragments flag */
        #define IP_OFFMASK 0x1fff       /* mask for fragmenting bits */
        u_char  ip_ttl;                 /* time to live */
        u_char  ip_p;                   /* protocol */
        u_short ip_sum;                 /* checksum */
        struct  in_addr ip_src,ip_dst;  /* source and dest address */
};
#define IP_HL(ip)               (((ip)->ip_vhl) & 0x0f)
#define IP_V(ip)                (((ip)->ip_vhl) >> 4)

/* TCP header */
typedef u_int tcp_seq;

struct sniff_tcp {
        u_short th_sport;               /* source port */
        u_short th_dport;               /* destination port */
        tcp_seq th_seq;                 /* sequence number */
        tcp_seq th_ack;                 /* acknowledgement number */
        u_char  th_offx2;               /* data offset, rsvd */
#define TH_OFF(th)      (((th)->th_offx2 & 0xf0) >> 4)
        u_char  th_flags;
        #define TH_FIN  0x01
        #define TH_SYN  0x02
        #define TH_RST  0x04
        #define TH_PUSH 0x08
        #define TH_ACK  0x10
        #define TH_URG  0x20
        #define TH_ECE  0x40
        #define TH_CWR  0x80
        #define TH_FLAGS        (TH_FIN|TH_SYN|TH_RST|TH_ACK|TH_URG|TH_ECE|TH_CWR)
        u_short th_win;                 /* window */
        u_short th_sum;                 /* checksum */
        u_short th_urp;                 /* urgent pointer */
};

/* UDP header */
struct sniff_udp {
        u_short uh_sport;
        u_short uh_dport;
        u_short uh_ulen;
        u_short uh_sum;
};

/*
struct timeval TimeStamp()
{
  struct timeval tv;
  gettimeofday(&tv, NULL);
  return tv;
}*/

volatile int run=1;

void sigint_handler(int signum)
{
  run=0;
}

void pkt_receive_callback(u_char *args, const struct pcap_pkthdr *header, const u_char *packet)
{
  const struct sniff_ethernet *ethernet;
  const struct sniff_ip *ip;
  const struct sniff_tcp *tcp;
  const struct sniff_udp *udp;
  const char *payload;
  
  int size_ip;
  int size_tcp;
  int size_udp;
  int size_payload;
  //int caplen = header.caplen;

  char fmt[64],buf[64];
  struct timeval tv;
  struct tm *tm;

  gettimeofday(&tv, NULL);
  tm = localtime(&tv.tv_sec);

  if(tm != NULL)
  {
    strftime(fmt, sizeof fmt, "%Y-%m-%d %H:%M:%S.%%06u ", tm);
    snprintf(buf, sizeof buf, fmt, tv.tv_usec);
    printf("%s",buf);
  }
   
  ethernet = (struct sniff_ethernet*)packet;

  printf("%02X:%02X:%02X:%02X:%02X:%02X",ethernet->ether_shost[0], ethernet->ether_shost[1], ethernet->ether_shost[2], ethernet->ether_shost[3], ethernet->ether_shost[4], ethernet->ether_shost[5]); 
  
  printf(" -> ");

  printf("%02X:%02X:%02X:%02X:%02X:%02X",ethernet->ether_dhost[0], ethernet->ether_dhost[1], ethernet->ether_dhost[2], ethernet->ether_dhost[3], ethernet->ether_dhost[4], ethernet->ether_dhost[5]); 
  
  printf(" type %u 0x%04X ", (unsigned short)ethernet->ether_type, ethernet->ether_type);
 
  if(ntohs(ethernet->ether_type) == ETHERTYPE_IP)
  {
    printf("len ");
    ip = (struct sniff_ip*)(packet + SIZE_ETHERNET);
    size_ip = IP_HL(ip)*4;
    if(size_ip < 20)
    {
      printf("Invalid IP header length %u bytes\n", size_ip);
      return;
    }
   
    if(ip->ip_p == IPPROTO_TCP)
    {
      tcp = (struct sniff_tcp*)(packet+SIZE_ETHERNET+size_ip);
      size_tcp = TH_OFF(tcp)*4;
      if(size_tcp < 20)
      {
        printf("Invalid TCP header length %u bytes\n", size_tcp);
        return;
      }
      printf("%s:%d -> %s:%d TCP ",inet_ntoa(ip->ip_src), ntohs(tcp->th_sport), inet_ntoa(ip->ip_dst), ntohs(tcp->th_dport));
    }
    else if(ip->ip_p == IPPROTO_UDP)
    {
      // inst.eecs.berkeley.edu/~ee122/fa07/projects/p2files/packet_parser.c 
      udp = (struct sniff_udp*)(packet+SIZE_ETHERNET+size_ip);
      /*size_udp = caplen - SIZE_ETHERNET - size_ip;
      if(size_udp < sizeof(struct sniff_udp))
      {
        printf("Invalid UDP header length %u bytes\n", size_udp);
        return;
      }*/
      printf("%s:%d -> %s:%d UDP ",inet_ntoa(ip->ip_src), ntohs(udp->uh_sport), inet_ntoa(ip->ip_dst), ntohs(udp->uh_dport));
    }
    else if(ip->ip_p == IPPROTO_ICMP)
    {
      printf("%s:%d -> %s:%d ICMP ",inet_ntoa(ip->ip_src), ntohs(tcp->th_sport), inet_ntoa(ip->ip_dst), ntohs(tcp->th_dport));
    }  
    else if(ip->ip_p == IPPROTO_IP)
    {
      printf("IP\n");
    }
    else
    {
      printf("Unknown proto %u %c \n", ip->ip_p, ip->ip_p);
    }

  }
}

int main(int argc, char **argv)
{
  char *device = NULL;
  char errbuffer[PCAP_ERRBUF_SIZE];
  pcap_t *handle;
  char filter_expr[] = "";
  struct bpf_program fp;
  bpf_u_int32 mask;
  bpf_u_int32 net;

  signal(SIGINT, sigint_handler);

  device = pcap_lookupdev(errbuffer);
  if(device == NULL)
  {
    fprintf(stderr, "Couldn't find default device: %s\n",errbuffer);
    exit(EXIT_FAILURE);
  }
  
  if(pcap_lookupnet(device, &net, &mask, errbuffer) == -1)
  {
    fprintf(stderr, "Couldn't get netmask for device %s: %s\n",device, errbuffer);
    net=0;
    mask=0;
  }

  handle = pcap_open_live(device, SNAP_LEN, 1, 10000, errbuffer);
  if (handle == NULL)
  {
    fprintf(stderr, "Couldn't open device %s:%s\n",device, errbuffer);
    exit(EXIT_FAILURE);
  }

  if (pcap_datalink(handle) != DLT_EN10MB)
  {
    fprintf(stderr, "Device %s is not on Ethernet protocol\n", device);
    exit(EXIT_FAILURE);
  }
  
  if (pcap_compile(handle, &fp, filter_expr, 0, net) == -1)
  {
    fprintf(stderr, "Couldn't parse filter %s:%s\n", filter_expr, pcap_geterr(handle));
    exit(EXIT_FAILURE);
  }

  if (pcap_setfilter(handle, &fp) == -1)
  {
    fprintf(stderr, "Couldn't install filter %s:%s\n",filter_expr, pcap_geterr(handle));
    exit(EXIT_FAILURE);
  }

  while(run)
  {
    pcap_loop(handle, 1, pkt_receive_callback, NULL);   
  }

  pcap_freecode(&fp);
  pcap_close(handle);

  return 0;
}
