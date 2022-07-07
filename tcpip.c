/* ------------------------------------------------------------------
 * $Id: tcpip.c,v 1.15 1998/09/22 20:35:43 savage Exp $
 * ------------------------------------------------------------------
 */
static char *id = "$Id: tcpip.c,v 1.15 1998/09/22 20:35:43 savage Exp $";

#include "config.h"

/* The include files */
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in_systm.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <netinet/ip.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/utsname.h>
#include <string.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <stdarg.h>
#include <net/if.h>

#include "tcpip.h"

/*-- LINUX routilng TABLES */
#ifdef LINUX
#include <linux/sockios.h>	/* GLIBC don't have sockios.h? */
typedef struct
  {
    char ifname[17];
    struct in_addr addr;
  }
interfacerec;

typedef struct
  {
    struct in_addr addr;
    unsigned long naddr;	/* netmask */
    interfacerec *iface;
  }
routerec;

short numinterfaces, numroutes;
interfacerec *interfaces;
routerec *routes;
#endif /* LINUX */

#ifdef PCAP
#include <pcap.h>
pcap_t *PCapHdlr=NULL;
#endif

/* Standard Macro */
#ifndef MIN
#define MIN(x,y) (x<y) ? x : y;
#endif

int sendsock, readsock;
unsigned short ipident;

/* This function will determine the checksum for a specific packet. Used by */
/*  nearly EVERYTHING on the internet */
unsigned short
inet_checksum (void *addr, int len)
{
  register int nleft = len;
  register u_short *w = addr;
  register int sum = 0;
  u_short answer = 0;

  /*
   *  Our algorithm is simple, using a 32 bit accumulator (sum),
   *  we add sequential 16 bit words to it, and at the end, fold
   *  back all the carry bits from the top 16 bits into the lower
   *  16 bits.
   */
  while (nleft > 1)
    {
      sum += *w++;
      nleft -= 2;
    }

  /* mop up an odd byte, if necessary */
  if (nleft == 1)
    {
      *(u_char *) (&answer) = *(u_char *) w;
      sum += answer;
    }

  /*
   * add back carry outs from top 16 bits to low 16 bits
   */
  sum = (sum >> 16) + (sum & 0xffff);	/* add hi 16 to low 16 */
  sum += (sum >> 16);		/* add carry */
  answer = ~sum;		/* truncate to 16 bits */
  return (answer);
}

struct psuedohdr  {
  struct in_addr source_address;
  struct in_addr dest_address;
  unsigned char place_holder;
  unsigned char protocol;
  unsigned short length;
} psuedohdr;

unsigned short tcp_checksum(char *packet,
                           int length,
                           struct in_addr source_address,
                           struct in_addr dest_address)
{
  char *psuedo_packet;
  unsigned short cksum;
  
  psuedohdr.protocol = IPPROTO_TCP;
  psuedohdr.length = htons(length);
  psuedohdr.place_holder = 0;

  psuedohdr.source_address = source_address;
  psuedohdr.dest_address = dest_address;
  
  if((psuedo_packet = malloc(sizeof(psuedohdr) + length)) == NULL)  {
    perror("malloc");
    exit(EXIT_FAILURE);
  }
  
  memcpy(psuedo_packet,&psuedohdr,sizeof(psuedohdr));
  memcpy((psuedo_packet + sizeof(psuedohdr)),
         packet,length);
  
  cksum = inet_checksum((unsigned short *)psuedo_packet,(length + sizeof(psuedohdr)));
  free(psuedo_packet);
  return cksum;
}

/* This will resolve the host specified by host (either IP or domain name) */
/*  and return the result in sa */
short
resolve_host (char *host, struct sockaddr_in *sa)
{
  struct hostent *ent;

  if (!host[0])
    {
      fprintf (stderr, "error: unknown host %s\n", host);
      return (-1);
    }
  memset (sa, 0, sizeof (struct sockaddr));
  sa->sin_family = AF_INET;
  sa->sin_addr.s_addr = inet_addr (host);
  if ((long) inet_addr (host) == -1)
    {
      ent = gethostbyname (host);
      if (ent != NULL)
	{
	  sa->sin_family = ent->h_addrtype;
	  memcpy ((caddr_t) & sa->sin_addr, ent->h_addr, ent->h_length);
	  return (0);
	}
      else
	{
	  fprintf (stderr, "error: unknown host %s\n", host);
	  return (-1);
	}
    }
  return (0);
}

/* Sends a TCP packet */
void
sendtcp (spoofrec * spoof, unsigned short flags, short rep)
{
  struct tcphdr tcp;
  struct ip ip;
  static char pkt[8192];
  int i;

/*-- IP HDR --*/
  ip.ip_hl = 5;
  ip.ip_v = 4;
  ip.ip_tos = 0;
#ifdef NEEDS_HTONS_IP_LEN
  ip.ip_len = htons (40);
#else
  ip.ip_len = 40;
#endif 
  ip.ip_id = htons (31337 + spoof->sport);
  ip.ip_off = 0;
  ip.ip_ttl = 255;
  ip.ip_p = IPPROTO_TCP;
  ip.ip_src = spoof->from.sin_addr;
  ip.ip_dst = spoof->dest.sin_addr;
#ifdef HAVE_STRUCT_IP_CSUM
#define ip_sum ip_csum
#endif
  ip.ip_sum = 0;
  ip.ip_sum = inet_checksum ((void *) &ip, sizeof (ip));

/*-- TCP HDR --*/
  tcp.th_sport = htons (spoof->sport);
  tcp.th_dport = htons (spoof->dport);
  tcp.th_seq = htonl (spoof->seq);
  tcp.th_ack = 0;
#ifdef X2_OFF
  tcp.th_x2_off = 0x50;
#else
  tcp.th_x2 = 0;
  tcp.th_off = 5;
#endif /* X2_OFF */
  tcp.th_flags = flags;
  tcp.th_win = htons (0x1234);
  tcp.th_urp = 0;
  tcp.th_sum = 0;

/*-- TCP Checksum --*/
#ifdef SOLARIS_CKSUM_BUG
  tcp.th_sum = sizeof (struct tcphdr);
#else 
  tcp.th_sum = tcp_checksum ((char *) &tcp,
			     sizeof (struct tcphdr),
			     spoof->from.sin_addr,
			     spoof->dest.sin_addr);
#endif /* SOLARIS_CKSUM_BUG */

  memcpy (pkt, (char *) &ip, sizeof (ip));
  memcpy (pkt + sizeof (ip), (void *) &tcp, sizeof (tcp));

  for (i = 0; i < rep; i++)
    if (sendto (sendsock, (void *) pkt, sizeof (ip) + sizeof (tcp), 0, (struct sockaddr *) &spoof->dest, sizeof (spoof->dest)) < 0)
      perror ("sending message");

}

/* Get's a TCP packet */
#define MAXSIZE	65535

short
gettcp (spoofrec * spoof, tcprec * dtcp)
{
  char buf[MAXSIZE], *p=buf;
  tcprec *tcp;

#ifndef PCAP
  int numread;

  if ((numread = read (readsock, buf, MAXSIZE)) < 0)
    return (0);

#else /* PCAP form tft.c by Lamont Granquist <lamontg@HITL.WASHINGTON.EDU> */

  struct pcap_pkthdr head;
  static int offset;
  int datalink;
  
  if( ! PCapHdlr ) {
    fprintf(stderr, "Error: libpcap not initialised.\n");
    return 0;
  }
    
  if((datalink = pcap_datalink(PCapHdlr)) < 0) 
    {
      fprintf(stderr, "libpcap: no datalink info: %s\n", pcap_geterr(PCapHdlr));
      return 0;
    }
  
    switch(datalink) {
      case DLT_EN10MB:
        offset = 14; break;
      case DLT_NULL:
      case DLT_PPP:
        offset =  4; break;
      case DLT_SLIP:
        offset = 16; break;
      case DLT_RAW:
        offset =  0; break;
      case DLT_SLIP_BSDOS:
      case DLT_PPP_BSDOS:
        offset = 24; break;
      case DLT_ATM_RFC1483:
        offset =  8; break;
      case DLT_IEEE802:
        offset = 22; break;
      default:
        fprintf(stderr, "unknown datalink type (%d)", datalink);
        return(0);
    }

  p = (char *) pcap_next(PCapHdlr, &head);
  if(!p)
    return 0;
  
  p+=offset;
  
#endif /* PCAP */

  /* Check to see if it's an IP packet */
  if ((p[0] >> 4) != 4)
    return (0);

  /* Check to see if it's a TCP packet */
  if (p[9] != 6)
    return (0);

  tcp = (tcprec *) & p[20];
  /* Check to see if it's from the correct host */
  if (memcmp (&spoof->dest.sin_addr, &p[12], 4) != 0)
   return (0);

  memcpy ((void *) dtcp, (void *) tcp, sizeof (tcprec));
  return (1);
}


/*-- Linux: Search out IP in Routing tables --*/
/*-- Other: Return hostname ip ---------------*/
struct in_addr
getlocalip (unsigned long dest)
{
  static struct in_addr ina;
#ifdef LINUX  /*---------------------------------------------- LINUX --*/
  int i;

  for (i = 0; i < numroutes; i++)
    {
      if ((dest & routes[i].naddr) == (unsigned long) routes[i].addr.s_addr)
        {
          return (routes[i].iface->addr);
        }
    }

#else /* !LINUX ---------------------------------------------- OTHER --*/
  struct sockaddr_in sin; 
  char myname[80];
  
 if( gethostname(myname,sizeof(myname)-1) || resolve_host(myname,&sin) < 0) {
	fprintf(stderr,"*** Unable to determine local IP from hostname\n");
 } else {
 	return (sin.sin_addr);
 }

#endif /* LINUX -------------------------------------------------------*/ 
  ina.s_addr = 0;
  return ina;
}

#ifdef LINUX
/*-- --*/
void init_route_tables(void)
{
  int ifsock, i, i1, found;
  struct ifconf ifc;
  struct ifreq *ifr;
  char buf[1024], iface[16], *ptr;
  FILE *f;

  /* Create a channel to the NET kernel. */
  if ((ifsock = socket (AF_INET, SOCK_DGRAM, 0)) < 0)
    {
      perror ("socket");
      exit (EXIT_FAILURE);
    }

  ifc.ifc_len = sizeof (buf);
  ifc.ifc_buf = buf;
  if (ioctl (ifsock, SIOCGIFCONF, &ifc) < 0)
    {
      perror ("opening interface socket");
      close (ifsock);
      exit (EXIT_FAILURE);
    }

  numinterfaces = (ifc.ifc_len / sizeof (struct ifreq));
  interfaces = (interfacerec *) malloc (numinterfaces * sizeof (interfacerec));

  ifr = ifc.ifc_req;
  for (i = 0; i < numinterfaces; i++, ifr++)
    {
      strcpy (interfaces[i].ifname, ifr->ifr_name);
      memcpy (&interfaces[i].addr, &((struct sockaddr_in *) &ifr->ifr_addr)->sin_addr, sizeof (struct in_addr));
      if (ioctl (ifsock, SIOCGIFADDR, ifr) < 0)
        printf ("Couldn't get address for %s\n", ifr->ifr_name);
    }
  close (ifsock);

  if ((f = fopen ("/proc/net/route", "r")) == NULL)
    {
      perror ("opening /proc/net/route");
      exit (EXIT_FAILURE);
    }

  numroutes = 0;
  fgets (buf, sizeof (buf), f);         /* strip out description line */
  while (!feof (f))
    {
      fgets (buf, sizeof (buf), f);
      numroutes++;
    }
  numroutes--;

  routes = (routerec *) malloc (numroutes * sizeof (routerec));

  rewind (f);

  fgets (buf, sizeof (buf), f); 
  for (i = 0; i < numroutes; i++)
    {
      if (fgets (buf, sizeof (buf), f) == NULL)
        {
          /* Important, since an interface might have been removed since our counting,
             causing us to parse bogus data */
          fputs ("Error reading /proc/net/route: iface count mismatch\n", stderr);
          fclose (f);
          exit (EXIT_FAILURE);
        }
      if ( strlen (buf) == sizeof(buf)-1 )
        {
          /* skip long lines */
          fputs ("Long (corrupt) line encountered, skipping.\n", stderr);
          while ((fgets (buf, sizeof (buf), f)))
            if (buf [strlen (buf) - 1] == '\n')
              break;
          continue; /* continue with next regular line (or fail if EOF */
        }
      ptr = strtok (buf, "\t ");
      if (!ptr)
        continue;
      if (strlen (ptr) >= sizeof (iface))
        continue; /* would overflow if fed with bogus data in a chroot()ed environment */
      else
        strcpy (iface, ptr);
      ptr = strtok (NULL, "\t ");       /* hack avoiding fscanf */
      routes[i].addr.s_addr=(unsigned long)strtol(ptr,NULL,16);
      for (i1 = 0; i1 < 6; i1++)
        {
          ptr = strtok (NULL, "\t ");   /* ignore Gateway Flags RefCnt Use Metric */
        }
      if (!ptr) {
        fputs ("Error parsing /proc/net/route\n", stderr);
        continue;
      }
      routes[i].naddr=(unsigned long)strtol(ptr,NULL,16);   /* Netmask */

      found = 0;
      for (i1 = 0; i1 < numinterfaces; i1++)
        {
          if (strcmp (interfaces[i1].ifname, iface) == 0)
            {
              routes[i].iface = &interfaces[i1];
              found = 1;
            }

        }

      if (!found)
         {
          printf ("Couldn't find interface %s\n", iface);
          exit (EXIT_FAILURE);
        }
   }
  fclose (f);
}
#endif /* LINUX */

#ifdef PCAP
int init_pcap(char *cmdbuf) {

  bpf_u_int32         localnet, netmask;
  struct bpf_program  fcode;
  char                ebuf[PCAP_ERRBUF_SIZE];
  int                 i;
  extern char *DEVICE;
  
  i = pcap_snapshot(PCapHdlr);
  if (pcap_lookupnet(DEVICE, &localnet, &netmask, ebuf) < 0) {
    localnet = 0;
    netmask  = 0;
    fprintf(stderr, "%s", ebuf);
  }
  if (pcap_compile(PCapHdlr, &fcode, cmdbuf, 1, netmask) < 0) {
    fprintf(stderr, "%s", pcap_geterr(PCapHdlr));
    return -1;
  }
  if (pcap_setfilter(PCapHdlr, &fcode) < 0) {
    fprintf(stderr, "%s", pcap_geterr(PCapHdlr));
    return -1;
  }

  return 0;
}
#endif /* PCAP */

void
init_tcpip (void)
{
  int on=1;
#ifndef PCAP
  int rsflags;
#else
  extern char *DEVICE;
  char ebuf[PCAP_ERRBUF_SIZE];
#endif
  

#ifdef LINUX /*-- routing tables --*/
  init_route_tables();
#endif /*-- LINUX routing tables --*/
  
  /*-- SEND RAW socket --*/
  if ((sendsock = socket (AF_INET, SOCK_RAW, IPPROTO_RAW)) < 0)
    {
      perror ("opening raw send socket");
      exit (EXIT_FAILURE);
    }
  if (setsockopt (sendsock, IPPROTO_IP, IP_HDRINCL, (char *) &on, sizeof (on)) < 0)
    {
      perror ("setting option IP_HDRINCL");
      exit (EXIT_FAILURE);
    }

#ifndef PCAP    
  /*-- READ RAW socket --*/
  if ((readsock = socket (AF_INET, SOCK_RAW, IPPROTO_TCP)) < 0)
    {
      perror ("opening raw read socket");
      exit (EXIT_FAILURE);
    }
  if ((rsflags = fcntl (readsock, F_GETFL)) == -1)
    {
      perror ("fcntl(readsock,F_GETFL)");
      exit (EXIT_FAILURE);
    }

  if (fcntl (readsock, F_SETFL, rsflags | O_NONBLOCK) == -1)
    {
      perror ("fcntl(readsock,F_SETFL)");
      exit (EXIT_FAILURE);
   }
#ifdef RAW_NEEDS_BIND
  name.sin_family = AF_INET;
  name.sin_addr.s_addr = INADDR_ANY;
  name.sin_port = 10000;
  if (bind (readsock, (struct sockaddr *) &name, sizeof (name)))
    {
      perror ("binding read socket");
      exit (EXIT_FAILURE);
    }
#endif /* RAW_NEEDS_BIND */ 
#else /* PCAP */ 

  if (DEVICE == NULL) {
    DEVICE = pcap_lookupdev(ebuf);
    if (DEVICE == NULL) {
      fprintf(stderr, "pcap_lookupdev: %s", ebuf);
      exit (EXIT_FAILURE);
    }
  }
  PCapHdlr = pcap_open_live(DEVICE, 64, 0, 100, ebuf);
  if (PCapHdlr == NULL) {
    fprintf(stderr, "pcap_open_live: %s", ebuf);
    exit (EXIT_FAILURE);
  }

#endif /* PCAP */    
}

char *
tcpip_id (void)
{
  return id;
}
