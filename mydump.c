#include<stdio.h>
#include<stdlib.h>
#include<signal.h>
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
  const char *payload;

  ethernet = (struct sniff_ethernet*)packet;
  
  switch(ip->ip_p)
  {
    case IPPROTO_TCP:
      printf("TCP");
      break;
    case IPPROTO_UDP:
      printf("UDP");
      break; 
    case IPPROTO_ICMP:
      printf("ICMP");
      break;
    case IPPROTO_IP:
      printf("IP");
      break;
    default:
      printf("Unknown protocol");
      return;
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
