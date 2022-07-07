/* These are the structures for the IP, TCP and ICMP headers */
/* $Id: tcpip.h,v 1.5 1998/09/22 20:35:43 savage Exp $ */
typedef struct
  {
    unsigned char vh;
    unsigned char stype;
    unsigned short length;
    unsigned short ident;
    unsigned short frag;
    unsigned char ttl;
    unsigned char protocol;
    unsigned short cksum;
    struct in_addr sip;
    struct in_addr dip;
  }
iprec;

typedef struct
  {
    unsigned short sport;
    unsigned short dport;
    unsigned long seqnum;
    unsigned long acknum;
    unsigned char txoff;
    unsigned char flags;
    unsigned short window;
    unsigned short cksum;
    unsigned short urgentptr;
  }
tcprec;

typedef struct
  {
    struct in_addr sip;
    struct in_addr dip;
    unsigned char zero;
    unsigned char proto;
    unsigned short tcplen;
  }
tcpsrec;

typedef struct
  {
    unsigned char type;
    unsigned char code;
    unsigned short cksum;
    unsigned long zero;
    iprec ip;
    unsigned short sport;
    unsigned short dport;
    unsigned long seq;
  }
icmprec;

/* #define's for the TCP flags */
#define YYY 0x80
#define XXX 0x40
#define URG 0x20
#define ACK 0x10
#define PSH 0x08
#define RST 0x04
#define SYN 0x02
#define FIN 0x01

/* Structure for a spoofed connection */
typedef struct
  {
    struct sockaddr_in from;
    struct sockaddr_in dest;
    unsigned short sport;
    unsigned short dport;
    unsigned long seq;
    unsigned long ack;
  }
spoofrec;

/* -------------- Prototiping --------------- */
void init_tcpip(void);
int init_pcap(char*);
unsigned short in_cksum (unsigned short *, int);  
void sendip (spoofrec *, char *, short, short *, short *, short);
unsigned short tcpcksum (spoofrec *, char *, short);
short resolve_host (char *, struct sockaddr_in *);
short gettcp (spoofrec *, tcprec *);
void sendtcp (spoofrec *, unsigned short, short); 
void sendicmp (spoofrec *, struct sockaddr_in *, unsigned short);
struct in_addr getlocalip (unsigned long dest);
char *tcpip_id(void);

