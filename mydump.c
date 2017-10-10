// confirm len
// filter expr functionality?
// fix time, localtime

#include<stdio.h>
#include<stdlib.h>
#include<unistd.h>
#include<string.h>
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

char *mystrstr(const char *str, const char *pattern, int size_str)
{
  if(!*pattern)
    return str;
  char *p1 = (char *)str;
  int i=0;
  while(i <= size_str)
  {
    char *pb = p1;
    char *p2 = (char *)pattern;
    while(*p1 && *p2 && *p1 == *p2)
    {
      p1++;
      p2++;
    }
    if(!*p2)
      return pb;
    i++;
    p1 = pb+1;
  }
  return NULL;
}

void print_line(const u_char *payload, int len, int std_line_width)
{
  if(len <= 0)
    return;
  
  const u_char *ch;
  int i, empty_spaces;

  ch = payload;
  for(i=0;i<len;i++)
  {
    printf("%02x ",*ch);
    ch++;
  }
  if(len < std_line_width)
  {
    empty_spaces = std_line_width - len;
    for(i=0;i<empty_spaces;i++)
      printf("   ");
  }
  printf("   ");

  ch=payload;
  for(i=0;i<len;i++)
  {
    if(isprint(*ch))
      printf("%c",*ch);
    else
      printf(".");
    ch++;
  }
  printf("\n");

}

void print_payload(const u_char *payload, int len)
{
  int std_line_width = 16;
  int line_len;
  int len_rem = len;
  const u_char *ch = payload;
 
  while(1)
  {
    if(len_rem <= std_line_width)
    {
      print_line(ch, len_rem, std_line_width);
      break;
    }
    line_len = std_line_width % len_rem;
    print_line(ch, line_len, std_line_width);
    len_rem = len_rem - line_len;
    ch = ch + line_len;
  } 
}

// returns on whether packet payload matches given str
// on true ie 1, packet is processed by calling callback function  
int handle_str_matching_pkt(const struct pcap_pkthdr *header, const u_char *packet, char *mstr)
{
  const struct sniff_ethernet *ethernet;
  const struct sniff_ip *ip;
  const struct sniff_tcp *tcp;
  const struct sniff_udp *udp;
  const char *payload;
  
  int size_ip;
  int size_tcp;
  int size_udp;
  int size_icmp;
  int size_payload;

  ethernet = (struct sniff_ethernet*)packet;

  if(ntohs(ethernet->ether_type) == ETHERTYPE_IP)
  {
    ip = (struct sniff_ip*)(packet + SIZE_ETHERNET);
    size_ip = IP_HL(ip)*4;
    if(size_ip < 20)
    {
      printf("Invalid IP header length %u bytes\n", size_ip);
      return 0;
    }
   
    if(ip->ip_p == IPPROTO_TCP)
    {
      tcp = (struct sniff_tcp*)(packet+SIZE_ETHERNET+size_ip);
      size_tcp = TH_OFF(tcp)*4;
      if(size_tcp < 20)
      {
        printf("Invalid TCP header length %u bytes\n", size_tcp);
        return 0;
      }
      
      payload = (u_char *)(packet+SIZE_ETHERNET+size_ip+size_tcp);
      size_payload = ntohs(ip->ip_len) - (size_ip + size_tcp);

      if(size_payload > 0)
      {
        if(mystrstr(payload, mstr, size_payload) != NULL)
          return 1;
        return 0;
      }
    }
    else if(ip->ip_p == IPPROTO_UDP)
    {
      udp = (struct sniff_udp*)(packet+SIZE_ETHERNET+size_ip);
      size_udp = 8;

      payload = (u_char *)(packet+SIZE_ETHERNET+size_ip+size_udp);
      size_payload = ntohs(ip->ip_len) - (size_ip + size_udp);

      if(size_payload > 0)
      {
        if(mystrstr(payload, mstr, size_payload) != NULL)
          return 1;
        return 0;
      }
    }
    else if(ip->ip_p == IPPROTO_ICMP)
    {
      
      size_icmp = 8;
      payload = (u_char *)(packet+SIZE_ETHERNET+size_ip+size_icmp);
      size_payload = ntohs(ip->ip_len) - (size_ip + size_icmp);
      if(size_payload > 0)
      {
        if(mystrstr(payload, mstr, size_payload) != NULL)
          return 1;
        return 0;
      }
    }  
    else
    {
      payload = (u_char *)(packet+SIZE_ETHERNET+size_ip);
      size_payload = ntohs(ip->ip_len) - (size_ip);
      if(size_payload > 0)
      {
        if(mystrstr(payload, mstr, size_payload) != NULL)
          return 1;
        return 0;
      }
    }
  }
  //else
  //  return 1;
  return 0;
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
  int size_icmp;
  int size_payload;
  //int caplen = header.caplen;
  //printf("hey there\n");
  char *mstr = NULL;
  if(args != NULL)
  {
    mstr = args;
    printf("String matching pattern is %s\n",mstr);
  }
  //printf("hey there 2\n");
  if(mstr != NULL)
  {
    if(handle_str_matching_pkt(header, packet, mstr) == 0)
      return;
  }
  //printf("alrighty\n");
  char fmt[64],buf[64];
  struct timeval tv;
  struct tm *tm;

  tv = header->ts;
  tm = localtime(&tv.tv_sec);

  if(tm != NULL)
  {
    strftime(fmt, sizeof fmt, "%Y-%m-%d %H:%M:%S.%%06u ", tm);
    snprintf(buf, sizeof buf, fmt, tv.tv_usec);
    printf("%s",buf);
  }
  //printf("printed time\n"); 
  ethernet = (struct sniff_ethernet*)packet;

  printf("%02X:%02X:%02X:%02X:%02X:%02X",ethernet->ether_shost[0], ethernet->ether_shost[1], ethernet->ether_shost[2], ethernet->ether_shost[3], ethernet->ether_shost[4], ethernet->ether_shost[5]); 
  
  printf(" -> ");

  printf("%02X:%02X:%02X:%02X:%02X:%02X",ethernet->ether_dhost[0], ethernet->ether_dhost[1], ethernet->ether_dhost[2], ethernet->ether_dhost[3], ethernet->ether_dhost[4], ethernet->ether_dhost[5]); 
  
  printf(" type 0x%X ", ntohs(ethernet->ether_type));
 
  if(ntohs(ethernet->ether_type) == ETHERTYPE_IP)
  {
    //printf("pehle\n");
    //printf("baadmein\n");
    ip = (struct sniff_ip*)(packet + SIZE_ETHERNET);
    printf("len %d\n",ntohs(ip->ip_len));
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
      printf("%s:%d -> %s:%d TCP\n",inet_ntoa(ip->ip_src), ntohs(tcp->th_sport), inet_ntoa(ip->ip_dst), ntohs(tcp->th_dport));
      
      payload = (u_char *)(packet+SIZE_ETHERNET+size_ip+size_tcp);
      size_payload = ntohs(ip->ip_len) - (size_ip + size_tcp);

      if(size_payload > 0)
      {
        print_payload(payload, size_payload);
      }
    }
    else if(ip->ip_p == IPPROTO_UDP)
    {
      udp = (struct sniff_udp*)(packet+SIZE_ETHERNET+size_ip);
      size_udp = 8;
      printf("%s:%d -> %s:%d UDP\n",inet_ntoa(ip->ip_src), ntohs(udp->uh_sport), inet_ntoa(ip->ip_dst), ntohs(udp->uh_dport));

      payload = (u_char *)(packet+SIZE_ETHERNET+size_ip+size_udp);
      size_payload = ntohs(ip->ip_len) - (size_ip + size_udp);

      if(size_payload > 0)
        print_payload(payload, size_payload);
    }
    else if(ip->ip_p == IPPROTO_ICMP)
    {
      printf("%s -> %s ICMP\n",inet_ntoa(ip->ip_src), inet_ntoa(ip->ip_dst));
      
      size_icmp = 8;
      payload = (u_char *)(packet+SIZE_ETHERNET+size_ip+size_icmp);
      size_payload = ntohs(ip->ip_len) - (size_ip + size_icmp);
      if(size_payload > 0)
        print_payload(payload, size_payload);
    }  
    else
    {
      printf("%s -> %s OTHER \n",inet_ntoa(ip->ip_src), inet_ntoa(ip->ip_dst));

      payload = (u_char *)(packet+SIZE_ETHERNET+size_ip);
      size_payload = ntohs(ip->ip_len) - (size_ip);
      if(size_payload > 0)
        print_payload(payload, size_payload);
    }
    printf("\n");
  }
  else if(ntohs(ethernet->ether_type) == ETHERTYPE_ARP)
  {
    printf("ARP\n\n");
  }
  else
    printf("\n\n");
}

int main(int argc, char **argv)
{
  char *device = NULL;
  char *rfile = NULL;
  char *mstr = NULL;
  char *filter_expr = NULL;
  char errbuffer[PCAP_ERRBUF_SIZE];
  pcap_t *handle;
  //char filter_expr[] = "";
  struct bpf_program fp;
  bpf_u_int32 mask;
  bpf_u_int32 net;

  // signal to handle Ctrl + C exits
  signal(SIGINT, sigint_handler);

  int c;
  // reading command line args
  while((c = getopt(argc, argv, "i:r:s:")) != -1)
  {
    switch(c)
    {
      case 'i':
        device = optarg;
        break;
      case 'r':
        rfile = optarg;
        break;
      case 's':
        mstr = optarg;
        break;
      case '?':
        if(optopt == 'i' || optopt == 'r' || optopt == 's')
          fprintf(stderr, "Option -%c requires an argument\n",optopt);
        else
          fprintf(stderr, "Unknown option\n");
        return 1;
      default:
        abort();
      
    }
  }

  if(optind == argc-1)
    filter_expr = argv[optind];
  filter_expr = "dst host 239.255.255.250";
  printf("filter expr is %s\n", filter_expr);
  if(device != NULL && rfile != NULL)
  {
    fprintf(stderr, "Invalid arguments. Can't use -i and -r option together\n");
    exit(EXIT_FAILURE);
  }
   
  // set default device if not provided by user
  if(device == NULL && rfile == NULL)
  {
    device = pcap_lookupdev(errbuffer);
    if(device == NULL)
    {
      fprintf(stderr, "Couldn't find default device: %s\n",errbuffer);
      exit(EXIT_FAILURE);
    }
  }

  // preparing for sniffing
  if(device != NULL && rfile == NULL)
  {  
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
  }
  // reading dump from input file
  else if(device == NULL && rfile != NULL)
  {
    handle = pcap_open_offline(rfile, errbuffer);
    if (handle == NULL)
    {
      fprintf(stderr, "Couldn't open file %s:%s\n", rfile, errbuffer);
      exit(EXIT_FAILURE);
    }
  }

  if (pcap_datalink(handle) != DLT_EN10MB)
  {
    fprintf(stderr, "Device %s is not on Ethernet protocol\n", device);
    exit(EXIT_FAILURE);
  }
  
  // handle bpf filters
  if(filter_expr != NULL)
  {
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
  }

  if(rfile == NULL)
  {
    while(run)
      pcap_loop(handle, 1, pkt_receive_callback, mstr);
  }
  else
    pcap_loop(handle, -1, pkt_receive_callback, mstr);

  //pcap_freecode(&fp);
  pcap_close(handle);

  return 0;
}
