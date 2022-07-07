/***************************************************************
 *
 * Proyecto:	QueSO ( Que Sistema Operativo ?? )      
 * Autor:       Jordi Murgo <savage@apostols.org>
 * Descripcion:	Determina el tipo de Sistema Operativo de una
 *              maquina concreta a partir del comportamiento 
 *              de su pila TCP/IP ante paquetes TCP 'raros'.
 *              Ver el codigo para mas informacion.
 * Licencia:	GNU GPL 
 *
 ***************************************************************
 * Agradecimientos a ToXyN, b0fh y a los colegas del canal #hack
 *		   especialmente a syn por la traduccion del doc
 ***************************************************************
 * CVS: $Id: queso.c,v 1.20 1998/09/22 20:35:43 savage Exp $
 ***************************************************************/

#include "config.h"

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>

#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>
#include <time.h>
#include <string.h>
#include <unistd.h>

#ifdef PCAP
#include <pcap.h>
#endif /* PCAP */

extern char *optarg;
extern int optind, opterr, optopt;

#include "tcpip.h"

static char *id = "$Id: queso.c,v 1.20 1998/09/22 20:35:43 savage Exp $";

#define ACK_HACK  1000
#define RANDOM_ACK (ACK_HACK+666)
#define MAXPKT 6

int PKTDEBUG = 0;
int CONFIGDEBUG = 0;
int SALVAR = 0;
int MAXTIMER = 3;
int VECES = 1;
int Zzz = 100;
int DEFPORT = 80;
char *DEVICE=NULL, DEVBUFF[255];

/*----- CFG_FILE_NAME moved to Makefile -----*/
static char CFGFILE[255] = DFLT_CONFIG_FILE;

/*------------- Prototiping -----------------*/
void debugtcp (unsigned long, tcprec);
void usage (const char *);
int checkos (struct sockaddr_in, short);

/*------------- Print TCP HDR ---------------*/
void
debugtcp (unsigned long myseq, tcprec tcp)
{
  fprintf (stderr, "%d->%d S:%1d A:%s%lX W:%04X U:%X F: ",
	   ntohs (tcp.sport), ntohs (tcp.dport),
	   (tcp.seqnum?1:0),
	   tcp.acknum?"+":" ",
	   (tcp.acknum?(unsigned long) ntohl (tcp.acknum)-myseq:0),
	   ntohs (tcp.window), ntohs (tcp.urgentptr));

  if (tcp.flags & URG)
    fprintf (stderr, "URG ");
  if (tcp.flags & SYN)
    fprintf (stderr, "SYN ");
  if (tcp.flags & RST)
    fprintf (stderr, "RST ");
  if (tcp.flags & FIN)
    fprintf (stderr, "FIN ");
  if (tcp.flags & ACK)
    fprintf (stderr, "ACK ");
  if (tcp.flags & PSH)
    fprintf (stderr, "PSH ");
  if (tcp.flags & XXX)
    fprintf (stderr, "XXX ");
  if (tcp.flags & YYY)
    fprintf (stderr, "YYY ");
  fprintf (stderr, "\n");
}

void
usage (const char *progname)
{
  fprintf (stderr, "QueSO (c) 1998 savage@apostols.org\n");
#ifdef ENGLISH
  fprintf (stderr, "Usage: %s [-options] host.com[/bits][:port] ...\nOptions:\n", progname);
  fprintf (stderr, "       -v         Version\n");
  fprintf (stderr, "       -d         Debug mode, print received PKTs.\n");
  fprintf (stderr, "       -w         Update %s when new OS is found.\n",
	   CFGFILE);
  fprintf (stderr, "       -p port    Select default remote port. (default=%d)\n",
	   DEFPORT);
  fprintf (stderr, "       -f srcIP   Select correct In/Out IP.\n");
#ifdef PCAP
  fprintf (stderr, "       -i iface   Select reception interface.\n");
#endif /* PCAP */
  fprintf (stderr, "       -c file    Alternate config file.\n");
  fprintf (stderr, "       -t seconds Set reception timeout. (default=%d)\n",
	   MAXTIMER);
  fprintf (stderr, "       -n times   How many times PKTs are sent. (default=%d)\n",
	   VECES);
  fprintf (stderr, "       -z usec.   To avoid flood. (default=%d)\n",
	   Zzz);
#else
  fprintf (stderr, "Uso: %s [-options] host.com[/bits][:puerto] ...\nOpciones:\n", progname);
  fprintf (stderr, "       -v         Version del Programa\n");
  fprintf (stderr, "       -d         Modo 'debug', imprime PKTs recibidos.\n");
  fprintf (stderr, "       -w         Actualiza %s con el nuevo patron desconocido.\n",
	   CFGFILE);
  fprintf (stderr, "       -p puerto  Selecciona el puerto remoto. (por defecto=%d)\n",
	   DEFPORT);
  fprintf (stderr, "       -f srcIP   Selecciona la IP de Entrada/Salida.\n");
#ifdef PCAP
  fprintf (stderr, "       -i iface   Selecciona la Interface de captura.\n");
#endif /* PCAP */
  fprintf (stderr, "       -c archivo Lee los patrones desde otro archivo.\n");
  fprintf (stderr, "       -t tiempo  Establece el timeout de recepcion (por defecto=%d)\n",
	   MAXTIMER);
  fprintf (stderr, "       -n veces   Numero de envios de los PKTs (por defecto=%d)\n",
	   VECES);
  fprintf (stderr, "       -z useg.   Para evitar flood. (por defecto=%d)\n",
	   Zzz);

#endif /* ENGLISH */
  fprintf (stderr, "\n");
  exit (EXIT_FAILURE);
}

typedef struct
{
  unsigned short set;
  unsigned long seq;
  unsigned long ack;
  unsigned short urg;
  unsigned short win;
  unsigned short flag;
}
OSRES;

#define SILENT	0

int
check_os (struct sockaddr_in from, struct sockaddr_in dest, short dport)
{
  spoofrec spoof;
  tcprec tcp;
  unsigned short start, s;
  int n;
  long timeout;
  FILE *f;
  char line[1024];
  unsigned long myseq;
#ifdef PCAP
  char fromtxt[16], desttxt[16];
  char bpftxt[4096];
#endif


  OSRES r[MAXPKT + 1];
  for (n = 0; n <= MAXPKT; n++)
    {
      r[n].set = 0;
    }

  srand (time (NULL) & 0x0000ffff);
  start = s = (rand () % 26000) + 4000;
  spoof.seq = myseq = rand ();
  spoof.ack = 0;
  spoof.from = from;
  spoof.dest = dest;
  spoof.dport = dport;

  if (PKTDEBUG)
    {
      fprintf (stderr, "Starting %s:%u -> ", inet_ntoa (from.sin_addr), start);
      fprintf (stderr, "%s:%u\n", inet_ntoa (dest.sin_addr), dport);
    }

#ifdef PCAP
  strncpy (fromtxt, inet_ntoa (from.sin_addr), sizeof (fromtxt));
  strncpy (desttxt, inet_ntoa (dest.sin_addr), sizeof (desttxt));

  sprintf (bpftxt, "src host %s and dst host %s and tcp and src port %d and ( dst port %d",
	   desttxt, fromtxt, dport, start);
  for (n = 1; n <= MAXPKT; n++)
    {
      sprintf (fromtxt, " or dst port %d", start + n);
      strcat (bpftxt, fromtxt);
    }
  strcat (bpftxt, " )");
  
  if (CONFIGDEBUG)
    fprintf (stderr, "BPF: %s\n", bpftxt);
    
  if( init_pcap( bpftxt ) ) 
  	return 0;  
#endif /* PCAP */

  /*-- PKT 0 --*/
  spoof.sport = s++;
  sendtcp (&spoof, SYN, VECES);
  usleep (Zzz);

  /*-- PKT 1 --*/
  spoof.sport = s++;
  sendtcp (&spoof, SYN | ACK, VECES);
  usleep (Zzz);

  /*-- PKT 2 --*/
  spoof.sport = s++;
  sendtcp (&spoof, FIN, VECES);
  usleep (Zzz);

  /*-- PKT 3 --*/
  spoof.sport = s++;
  sendtcp (&spoof, FIN | ACK, VECES);
  usleep (Zzz);
  
  /*-- PKT 4 --*/
  spoof.sport = s++;
  sendtcp (&spoof, SYN | FIN, VECES);
  usleep (Zzz);

  /*-- PKT 5 --*/
  spoof.sport = s++;
  sendtcp (&spoof, PSH, VECES);
  usleep (Zzz);

  /*-- PKT 6 --*/
  spoof.sport = s++;
  sendtcp (&spoof, SYN | XXX | YYY, VECES);
  usleep (Zzz);

  timeout = time (NULL) + MAXTIMER;


  while ((timeout > time (NULL)))
    {
      if (gettcp (&spoof, &tcp))
	{
	  if (ntohs (tcp.sport) == dport)
	    {
	      n = ntohs (tcp.dport) - start;
	      if (n < 0 || n > MAXPKT)
		continue;	/* ignore invalid pkts */
	      if (r[n].set == 1)
		continue;	/* ignore duppes */

	      if (PKTDEBUG)
		{
		  fprintf (stderr, "IN  #%-2u: ", ntohs (tcp.dport) - start);
		  debugtcp (myseq, tcp);
		}

	      r[n].seq = tcp.seqnum ? 1 : 0;
	      r[n].ack = tcp.acknum ? (ntohl(tcp.acknum)-myseq+ACK_HACK) : 0;
	      if(r[n].ack > RANDOM_ACK)
		r[n].ack = RANDOM_ACK;
	      r[n].win = ntohs (tcp.window);
	      r[n].flag = tcp.flags;
	      r[n].set = 1;
	      r[n].urg = tcp.urgentptr ? 1 : 0;
	    }
	}
      else
	usleep (Zzz);
    }

  /*---------- CHECK RESULT -----------*/
  if ((f = fopen (CFGFILE, "r")))
    {
      char osname[256];		/* should be smaller than line[], 256 should suffice */
      unsigned short flag1 = 0, found = 0, linez = 0;
      unsigned short pn = 0, ps = 0, pa = 0, pw = 0, pf = 0, pu = 0;
      char *p;

      while (fgets (line, sizeof (osname) - 1, f))
	{
	  if (line[0] == '\n')
	    {
	      if (flag1 && found == linez)
		{
		  printf ("%s:%d\t%s", inet_ntoa (dest.sin_addr), dport, osname);
		  fclose (f);
		  if (osname[1] == '-')
		    return 0;	/* Not accurate response */
		  else
		    return 1;
		}
	    }

	  if (line[0] == '*')
	    {
	      strcpy (osname, line);
	      if (CONFIGDEBUG)
		fprintf (stderr, "\n%s", line);
	      flag1 = 1;
	      found = 0, linez = 0;
	      continue;
	    }

	  /*------ PARSE LINE ---*/
	  linez++;
	  p = strtok (line, " ");
	  if (p && isdigit (*p))
	    pn = atoi (p);
	  else
	    {
	      linez = 0;
	      flag1 = 0;
	      found = 0;
	      continue;
	    }
	  
	  /*-- seq --*/
	  p = strtok (NULL, " ");
	  if (p)
	    ps = atoi (p);

	  /*-- ack --*/
	  p = strtok (NULL, " ");
	  if (p) 
	    {
	      if( *p == 'R' )
		pa = RANDOM_ACK;
	      else if( *p == '+' )
		pa = atoi (p)+ACK_HACK; /*-- extended ACK field --*/
	      else 
		pa = atoi (p);
	    }
	  
	  /*-- win --*/
	  p = strtok (NULL, " ");
	  if (p)
	    pw = 0xffff & strtol (p, NULL, 16);

	  /*-- flags --*/
	  p = strtok (NULL, " \n");
	  if (p)
	    {
	      if (CONFIGDEBUG)
		fprintf (stderr, "%d %d %d %-4X %-7s ", pn, ps, pa, pw, p);
	      pf = 0;
	      if (strchr (p, 'S'))
		pf |= SYN;
	      if (strchr (p, 'R'))
		pf |= RST;
	      if (strchr (p, 'A'))
		pf |= ACK;
	      if (strchr (p, 'F'))
		pf |= FIN;
	      if (strchr (p, 'P'))
		pf |= PSH;
	      if (strchr (p, 'X'))
		pf |= XXX;
	      if (strchr (p, 'Y'))
		pf |= YYY;
	      if (strchr (p, 'U'))
		pu = 1;
	      else
		pu = 0;
	    }


	  if (!r[pn].set)
	    {
	      if (pf)
		{
		  if (CONFIGDEBUG)
		    fprintf (stderr, " ** Not received but configured\n");
		  found = 0;
		  flag1 = 0;
		  continue;
		}
	      if (CONFIGDEBUG)
		fprintf (stderr, " ** Ok, not received and not configured\n");
	      found++;
	      continue;
	    }

	  if ( 
	      ( pa>=ACK_HACK?(pa==r[pn].ack):pa==(r[pn].ack>0) ) &&
	      ps == r[pn].seq &&
	      ((pw == r[pn].win)
	       || (pw == 1 && r[pn].win)
	       || (!pw && !r[pn].win)
	       ) &&
	      pf == r[pn].flag &&
	      pu == r[pn].urg )
	    {
	      if (CONFIGDEBUG)
		fprintf (stderr, " ** Ok, Found\n");
	      found++;
	      continue;
	    }
	  else
	    {
	      if (CONFIGDEBUG)
		fprintf (stderr, " ** FAILED %d,%d,%d,%d,%02X != %ld,%ld,%d,%d,%02X\n", 
			 ps, pa, pw, pu, pf, 
			 r[pn].seq,r[pn].ack,r[pn].win,r[pn].urg,r[pn].flag);
	      found = 0;
	      flag1 = 0;
	      continue;
	    }
	}

      fseek (f, 0L, SEEK_END);
      fclose (f);

      if (!SALVAR)
	f = stderr;
      else
	f = fopen (CFGFILE, "a");

      if (!f)
	{
#ifdef ENGLISH
	  fprintf (stderr, "Can't open RW %s\n", CFGFILE);
#else
	  fprintf (stderr, "No puedo abrir %s para Escritura\n", CFGFILE);
#endif
	  return 0;
	}
      fseek (f, 0L, SEEK_END);

#ifdef ENGLISH
      if (SALVAR)
	printf ("%s:%d\t*- Unknown OS, writting new patern %s\n", inet_ntoa (dest.sin_addr), dport, CFGFILE);
      else
	printf ("%s:%d\t*- Unknown OS, pleez update %s\n", inet_ntoa (dest.sin_addr), dport, CFGFILE);
#else
      if (SALVAR)
	printf ("%s:%d\t*- SO desconocido, salvando nuevo patron en %s\n", inet_ntoa (dest.sin_addr), dport, CFGFILE);
      else
	printf ("%s:%d\t*- SO desconocido, actualice %s\n", inet_ntoa (dest.sin_addr), dport, CFGFILE);
#endif

      if (PKTDEBUG || SALVAR)
	{
#ifdef ENGLISH
	  fprintf (f, "\n*- Unknown OS @ %s:%d\n",
		   inet_ntoa (dest.sin_addr),
		   dport);
#else
	  fprintf (f, "\n*- SO desconocido en %s:%d\n",
		   inet_ntoa (dest.sin_addr),
		   dport);
#endif
	  for (pn = 0; pn <= MAXPKT; pn++)
	    {
	      line[0] = 0;
	      if (r[pn].urg)
		strcat (line, "U");
	      if (r[pn].flag & SYN)
		strcat (line, "S");
	      if (r[pn].flag & RST)
		strcat (line, "R");
	      if (r[pn].flag & ACK)
		strcat (line, "A");
	      if (r[pn].flag & FIN)
		strcat (line, "F");
	      if (r[pn].flag & PSH)
		strcat (line, "P");
	      if (r[pn].flag & XXX)
		strcat (line, "X");
	      if (r[pn].flag & YYY)
		strcat (line, "Y");
	      if (r[pn].set) 
		{
		  fprintf ( f, "%d %ld %s",
			   pn, r[pn].seq, (r[pn].ack==RANDOM_ACK?"R":((r[pn].ack>=ACK_HACK)?"+":"")) );
		  if(r[pn].ack!=RANDOM_ACK) 
		      fprintf ( f, "%ld", (r[pn].ack>=ACK_HACK)?r[pn].ack-ACK_HACK:r[pn].ack);
		  fprintf ( f, " %d %s\n", r[pn].win ? 1 : 0, line);
		}
	      else
		fprintf (f, "%d - - - -\n", pn);
	    }

	}

      fprintf (f, "\n");
      fclose (f);
      
      return 0;
    }

#ifdef ENGLISH
  fprintf (stderr, "Can't open RO %s \n", CFGFILE);
#else
  fprintf (stderr, "No pude abrir %s en Solo-Lectura\n", CFGFILE);
#endif
  return -1;
}


/* -------------------------------------------------------- *
 * The main function 
 * -------------------------------------------------------- */
int
main (int argc, char *argv[])
{
  struct sockaddr_in dest, from;
  unsigned short port;
  char *s, *p;
  int c;
  int accuracy;
  int limit = 0;
  int bits = 32;		/* single host */
  unsigned long firsthost, lasthost, netmask, host;
  
  /*
   * Unbuffer stdout and stderr
   */
  setvbuf (stderr, NULL, _IONBF, 0);
  setvbuf (stdout, NULL, _IONBF, 0);

  /*-- Init addr --*/
  from.sin_addr.s_addr = dest.sin_addr.s_addr = 0;

  /*
   * Chek Argumentz
   */
  while ((c = getopt (argc, argv, "i:p:c:t:n:f:z:vdwkh?")) != EOF)
    {
      switch (c)
	{
	case 'p':
	  DEFPORT = atoi (optarg);
	  break;
	case 'v':
	  printf ("%s\n", id);
	  printf ("%s\n", tcpip_id ());
	  exit (EXIT_SUCCESS);
	case 'c':
	  if (strlen (optarg) >= sizeof (CFGFILE))
	    fputs ("Filename for config file too long, ignoring.\n", stderr);
	  else
	    strcpy (CFGFILE, optarg);
	  break;
	case 't':
	  MAXTIMER = atoi (optarg);
	  break;
	case 'n':
	  VECES = atoi (optarg);
	  break;
	case 'f':
	  if (resolve_host (optarg, &from) < 0)
	    exit (EXIT_FAILURE);
	  break;
	case 'd':
	  PKTDEBUG = 1;
	  break;
	case 'k':
	  CONFIGDEBUG = 1;
	  break;
	case 'w':
	  SALVAR = 1;
	  break;
	case 'z':
	  Zzz = atoi (optarg);
	  break;
	case 'i':
	  strncpy(DEVBUFF,optarg,sizeof(DEVBUFF-1));
	  DEVICE=DEVBUFF;
	  break;
	default:
	  usage (argv[0]);
	  return (EXIT_FAILURE);
	}
    }

  if (optind >= argc)
    usage (argv[0]);

  /*-- Init raw sockets, we need r00t here --*/
  init_tcpip ();
  
  /*-- drops down to original user privileges --*/
  if (!geteuid ())
    setuid (getuid ());

  /*-- Hostname or IP --*/
  for(; argv[optind]; optind++) {
    s = argv[optind];
    limit = 0;

    
    /*-- NetMask --*/
    if ((p = strchr (argv[optind], '/')) != 0)
      {
	*p = 0;
	bits = atoi (++p);
	if (bits < 0)
	  {
	    bits *= -1;
	    limit = -1;
	  }
	else
	  {
	    if (strchr (p, '-'))
	      limit = 1;
	  }
      }
    else
      {
	p = s;
	bits = 32;
      }

    /*-- Port --*/
    if ((p = strchr (p, ':')) != 0)
      {
	*p = 0;
	port = atoi (++p);
      }
    else
      {
	  port = DEFPORT;
      }
    
    if (resolve_host (s, &dest) < 0)
      exit (EXIT_FAILURE);
    

    if (!from.sin_addr.s_addr)
      from.sin_addr = getlocalip (dest.sin_addr.s_addr);
    
    if (!from.sin_addr.s_addr)
      {
#ifdef ENGLISH
	fprintf (stderr, "Unable to determine Local IP, use -f parameter\n");
#else
	fprintf (stderr, "Imposible determinar la IP local, usa el parametro -f\n");
#endif
	exit (EXIT_FAILURE);
      }
    
    host = ntohl (dest.sin_addr.s_addr);
    netmask = ~(0xFFFFFFFFL >> bits);
    /*-- WARNING: 32bit arquitectures have problems when bits==32 --*/
    firsthost = (host & netmask) + 1;
    lasthost = (host | ~(netmask)) - 1;
    
    if (limit < 0)
      lasthost = host;
    else if (limit > 0)
      firsthost = host;
    
    if (bits < 31) 
      {
	/*-- 0 to 30 bits --*/
	for (host = firsthost; host <= lasthost; host++)
	  {
	    dest.sin_addr.s_addr = htonl (host);
	    accuracy = check_os (from, dest, port);
	  }
      }
    else
      {
	/*-- 31 and 32 bits, ignore mask and check only the host --*/
	accuracy = check_os (from, dest, port);
      }
  }
  
  exit (EXIT_SUCCESS);
}
