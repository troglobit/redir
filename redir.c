/* $Id$
 *
 * redir	- a utility for redirecting tcp connections
 *
 * Author:	Nigel Metheringham
 *		Nigel.Metheringham@ThePLAnet.net
 *
 * Based on, but much modified from, code originally written by
 * sammy@freenet.akron.oh.us - original header is below.
 *
 * redir is released under the GNU General Public license,
 * version 2, or at your discretion, any later version.
 *
 */

/* 
 * redir is currently maintained by Sam Creasey (sammy@oh.verio.com).
 * Please send patches, etc. there.
 *
 */

/* 980601: dl9sau
 * added some nice new features:
 *
 *   --bind_addr=my.other.ip.address
 *       forces to use my.other.ip.address for the outgoing connection
 *   
 *   you can also specify, that redir listens not on all IP addresses of
 *   your system but only for the given one, i.e.:
 *      if my host has the addresses
 *        irc.thishost.my.domain  and  mail.thishost.my.domain
 *      but you want that your users do connect for the irc redir service
 *      only on irc.thishost.my.domain, then do it this way:
 *        redir irc.fu-berlin.de irc.thishost.mydomain:6667 6667
 *   my need was that:
 *        addr1.first.domain  6667 redirects to irc.first.net  port 6667
 *   and  addr2.second.domain 6667 redirects to irc.second.net port 6667
 *   while addr1 and addr2 are the same maschine and the ports can be equal.
 *
 *  enjoy it!
 *    - thomas  <thomas@x-berg.in-berlin.de>, <dl9sau@db0tud.ampr.org>
 *
 *  btw: i tried without success implementing code for the following scenario:
 *    redir --force_addr irc.fu-berlin.de 6667 6667
 *  if "--force_addr" is given and a user connects to my system, that address
 *  of my system will be used on the outgoing connection that the user
 *  connected to.
 *  i was not successful to determine, to which of my addresses the user
 *  has connected.
 */
 
/* 990320 added support for ftp connection done by the client, now this code 
 *        should work for all ftp clients.
 *	  
 *   - harald <harald.holzer@eunet.at>
 */
 
/* 991221 added options to simulate a slow connection and to limit
 *	  bandwidth.
 *
 *   - Emmanuel Chantréau <echant@maretmanu.org>
 */

#include "config.h"

#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <getopt.h>
#include <syslog.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <time.h>
#include <sys/wait.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <errno.h>

#ifdef USE_TCP_WRAPPERS
#include <tcpd.h>
#endif

#define debug(fmt, args...)	if (do_debug) syslog(LOG_DEBUG, fmt, ##args)

int inetd      = 0;
int background = 1;
int timeout    = 0;
int do_debug   = 0;
int do_syslog  = 0;

char *target_addr = NULL;
int   target_port = 0;
char *local_addr  = NULL;
int   local_port  = 0;
char *bind_addr   = NULL;

#ifndef NO_FTP
int ftp = 0;
#endif

int transproxy = 0;

#ifndef NO_SHAPER
int max_bandwidth = 0;
int random_wait   = 0;
int wait_in_out   = 3; /* bit 0: wait for "in", bit 1: wait for "out" */
int wait_in       = 1;
int wait_out      = 1;
#endif

unsigned int bufsize = BUFSIZ;
char *connect_str = NULL;	/* CONNECT string passed to proxy */
char *ident       = NULL;

#ifndef NO_FTP
/* what ftp to redirect */
#define FTP_PORT 1
#define FTP_PASV 2
#endif

#ifdef USE_TCP_WRAPPERS
struct request_info request;
int     allow_severity = LOG_INFO;
int     deny_severity = LOG_WARNING;
#endif /* USE_TCP_WRAPPERS */

#define REDIR_IN  1
#define REDIR_OUT 0

/* prototype anything needing it */
static void do_accept(int servsock, struct sockaddr_in *target);
static int bindsock(char *addr, int port, int fail);

#ifndef NO_SHAPER
/* Used in this program to write something in a socket, it has the same
   parameters and return value as "write", but with the flag "in": true if
   it's the "in" socket and false if it's the "out" socket */
static inline ssize_t redir_write(int fd, const void *buf, size_t size, int in)
{
	ssize_t result;
	int wait;

	wait = in ? wait_in : wait_out;
	if (random_wait > 0 && wait) {
		fd_set empty;
		struct timeval waitbw; /* for bandwidth */
		int rand_time;
    
		FD_ZERO(&empty);

		rand_time = rand() % (random_wait * 2);
		debug("random wait: %u", rand_time);
		waitbw.tv_sec  = rand_time / 1000;
		waitbw.tv_usec = rand_time % 1000;

		select(1, &empty, NULL, NULL, &waitbw);
	}

	result = write(fd, buf, size);

	if (max_bandwidth > 0 && wait) {
		fd_set empty;
		unsigned long bits;
		struct timeval waitbw; /* for bandwidth */

		FD_ZERO(&empty);

		/* wait to be sure tu be below the allowed bandwidth */
		bits = size * 8;
		debug("bandwidth wait: %lu", 1000 * bits / max_bandwidth);
		waitbw.tv_sec  = bits/max_bandwidth;
		waitbw.tv_usec = (1000 * (bits % max_bandwidth)) / max_bandwidth;

		select(1, &empty, NULL, NULL, &waitbw);
	}

	return result;
}
#else
/* macro if traffic shaper is disabled */
#define redir_write(fd, buf, size, in) write(fd, buf,size)
#endif

static int usage(int code)
{
	extern char *__progname;

	fprintf(stderr,"\n"
		"Usage: %s [-hidtnsIxbfpzmwov] [SRC]:PORT [DST]:PORT\n", __progname);
	fprintf(stderr, "\n"
		"Options:\n"
		"  -h,--help               Show this help text\n"
		"  -i,--inetd              Run from inetd, SRC:PORT comes from stdin\n"
		"  -d,--debug              Enable debugging info\n"
		"  -t,--timeout=SEC        Set timeout to SEC seconds\n"
		"  -n,--foreground         Run in foreground, do not detach from terminal\n"
		"  -s,--syslog             Log messages to syslog\n"
		"  -I,--ident=NAME         Identity, tag syslog messages with NAME\n"
		"  -x,--connect=STR        CONNECT string passed to proxy server\n"
#ifdef USE_TCP_WRAPPERS
		"                          Also used as service name for TCP wrappers\n"
#endif
		"  -b,--bind=IP            Force specific IP to bind() to when listening\n"
		"                          for incoming connections\n"

#ifndef NO_FTP
		"  -f,--ftp=TYPE           Redirect ftp connections.  Where type is\n"
		"                          one of: 'port', 'pasv', or 'both'\n"
#endif
		"  -p,--transproxy         run in linux's transparent proxy mode\n"
#ifndef NO_SHAPER
		"  -z,--bufsize=BYTES      size of the traffic shaping buffer\n"
		"  -m,--max-bandwidth=BPS  limit the bandwidth\n"
		"  -w,--random-wait=MSEC   Wait MSEC milliseconds before each packet\n"
		"  -o,--wait-in-out=FLAG   1 wait for in, 2 out, 3 in&out\n"
#endif
		"  -v,--version            Show program version\n"
		"\n"
		"SRC and DST are optional, %s will revert to use 0.0.0.0 (ANY)\n"
		"Bug report address: %s\n"
		"\n", __progname, PACKAGE_BUGREPORT);

	return code;
}

static int parse_ipport(char *arg, char *buf, size_t len)
{
	int port;
	char *ptr;
	struct servent *s;

	if (!arg || !buf || !len)
		return -1;

	ptr = strchr(arg, ':');
	if (!ptr)
		return -1;

	*ptr++ = 0;
	snprintf(buf, len, "%s", arg);

	s = getservbyname(ptr, "tcp");
	if (s != NULL)
		port = ntohs(s->s_port);
	else
		port = atoi(ptr);

	return port;
}

static void parse_args(int argc, char *argv[])
{
	static struct option long_options[] = {
		{"help",          no_argument,       0, 'h'},
		{"bind_addr",     required_argument, 0, 'b'},
		{"bind",          required_argument, 0, 'b'},
		{"debug",         no_argument,       0, 'd'},
		{"timeout",       required_argument, 0, 't'},
		{"inetd",         no_argument,       0, 'i'},
		{"ident",         required_argument, 0, 'I'},
		{"name",          required_argument, 0, 'I'},
		{"syslog",        no_argument,       0, 's'},
		{"connect",       required_argument, 0, 'x'},
#ifndef NO_FTP
		{"ftp",           required_argument, 0, 'f'},
#endif
		{"transproxy",    no_argument,       0, 'p'},
#ifndef NO_SHAPER
                {"bufsize",       required_argument, 0, 'z'},
                {"max_bandwidth", required_argument, 0, 'm'}, /* compat */
                {"max-bandwidth", required_argument, 0, 'm'},
                {"random_wait",   required_argument, 0, 'w'}, /* compat */
                {"random-wait",   required_argument, 0, 'w'},
                {"wait_in_out",   required_argument, 0, 'o'}, /* compat */
                {"wait-in-out",   required_argument, 0, 'o'},
#endif
		{"version",       no_argument,       0, 'v'},
		{0, 0, 0, 0}
	};
	
	extern int optind;
	int opt;
	char src[INET6_ADDRSTRLEN] = "", dst[INET6_ADDRSTRLEN] = "";
#ifndef NO_FTP
	char *ftp_type = NULL;
#endif
 
	while ((opt = getopt_long(argc, argv, "dhinsfpI:t:b:x:z:m:w:o:v", long_options, NULL)) != -1) {
		switch (opt) {
		case 'x':
			connect_str = optarg;
			break;

		case 'b':
			bind_addr = optarg;
			break;

		case 'd':
			do_debug++;
			break;

		case 'h':
			exit(usage(0));

		case 't':
			timeout = atol(optarg);
			break;

		case 'i':
			inetd++;
			break;

		case 'I':
			/* This is the ident which is added to syslog messages */
			ident = optarg;
			break;

		case 'n':
			background = 0;
			do_syslog--;
			break;

		case 's':
			do_syslog++;
			break;

#ifndef NO_FTP	    
		case 'f':
			ftp_type = optarg;
			if (!ftp_type)
				exit(usage(1));
			break;
#endif	     

		case 'p':
			transproxy++;
			break;

#ifndef NO_SHAPER
                case 'z':
			bufsize = (unsigned int)atol(optarg);
			if (bufsize < 256) {
				syslog(LOG_ERR, "Too small buffer (%d), must be at least 256 bytes!", bufsize);
				exit(usage(1));
			}
			break;
 
                case 'm':
			max_bandwidth = atol(optarg);
			break;
 
                case 'w':
			random_wait = atol(optarg);
			break;
 
                case 'o':
			wait_in_out = atol(optarg);
			wait_in     = wait_in_out & 1;
			wait_out    = wait_in_out & 2;
			break;
#endif
		case 'v':
			fprintf(stderr, "%s\n", PACKAGE_VERSION);
			exit(0);

		default:
			exit(usage(1));
		}
	}

	if (optind >= argc)
		exit(usage(2));

	if (inetd) {
		/* In inetd mode we redirect from src=stdin to dst:port */
		target_port = parse_ipport(argv[optind], dst, sizeof(dst));
		if (strlen(dst) > 1)
			target_addr = strdup(dst);
	} else {
		/* We need at least [src]:port, if src is left out we listen to any */
		local_port = parse_ipport(argv[optind++], src, sizeof(src));
		if (-1 == local_port)
			exit(usage(3));
		if (strlen(src) > 1)
			local_addr = strdup(src);

		target_port = parse_ipport(argv[optind], dst, sizeof(dst));
		if (strlen(dst) > 1)
			target_addr = strdup(dst);
	}

	if (!ident) {
		if ((ident = (char *) strrchr(argv[0], '/')))
			ident++;
		else
			ident = argv[0];
	}

#ifndef NO_FTP
	/* some kind of ftp being forwarded? */
	if (ftp_type) {
		if (!strncasecmp(ftp_type, "port", 4)) 
			ftp = FTP_PORT;
		else if (!strncasecmp(ftp_type, "pasv", 4))
			ftp = FTP_PASV;
		else if (!strncasecmp(ftp_type, "both", 4))
			ftp = FTP_PORT | FTP_PASV;
		else
			exit(usage(1));
	}
#endif	      
}

#ifndef NO_FTP
/* with the --ftp option, this one changes passive mode replies from
   the ftp server to point to a new redirector which we spawn,
   now it also change the PORT commando when the client accept the
   dataconnection */
   
void ftp_clean(int send, char *buf, unsigned long *bytes, int ftpsrv)
{
	char *port_start;
	int rporthi, lporthi;
	int lportlo, rportlo;
	int lport, rport;
	int remip[4];
	int localsock;
	socklen_t socksize = sizeof(struct sockaddr_in);

	struct sockaddr_in newsession;
	struct sockaddr_in sockname;

	if (ftpsrv == 0) {
		/* is this a port commando ? */
		if (strncmp(buf, "PORT", 4)) {
			redir_write(send, buf, (*bytes), REDIR_OUT);
			return;
		}
		/* parse the old address out of the buffer */
		port_start = strchr(buf, ' ');

		sscanf(port_start, " %d,%d,%d,%d,%d,%d", &remip[0], &remip[1],
		       &remip[2], &remip[3], &rporthi, &rportlo);
	} else {
		/* is this a passive mode return ? */
		if (strncmp(buf, "227", 3)) {
			redir_write(send, buf, (*bytes), REDIR_OUT);
			return;
		}
		
		/* parse the old address out of the buffer */
		port_start = strchr(buf, '(');
		
		sscanf(port_start, "(%d,%d,%d,%d,%d,%d", &remip[0], &remip[1],
		       &remip[2], &remip[3], &rporthi, &rportlo);
	}
    
	/* get the outside interface so we can listen */
	if (getsockname(send, (struct sockaddr *)&sockname, &socksize) != 0) {
		syslog(LOG_ERR, "Failed getsockname(): %s", strerror(errno));
		exit(1);
	}

	rport = (rporthi << 8) | rportlo;

	/* we need to listen on a port for the incoming connection.
	   we will use the port 0, so let the system pick one. */
	localsock = bindsock(inet_ntoa(sockname.sin_addr), 0, 1);
	if (localsock == -1) {
		syslog(LOG_ERR, "Failed bindsock(): %s", strerror(errno));
		exit(1);
	}
	
	/* get the real info */
	if (getsockname(localsock, (struct sockaddr *)&sockname, &socksize) < 0) {
		syslog(LOG_ERR, "Failed getsockname(): %s", strerror(errno));
		exit(1);
	}

	lport = ntohs(sockname.sin_port);
	lporthi = (lport >> 8) & 0xff;
	lportlo = lport & 0xff;

	if (ftpsrv == 0) {
		/* send the new port and ipaddress to the server */
		(*bytes) = sprintf(buf, "PORT %d,%d,%d,%d,%d,%d\n",
				   sockname.sin_addr.s_addr & 0xff, 
				   (sockname.sin_addr.s_addr >> 8) & 0xff, 
				   (sockname.sin_addr.s_addr >> 16) & 0xff,
				   sockname.sin_addr.s_addr >> 24, lporthi, lportlo);
	} else {
		/* send the new port and ipaddress to the client */
		(*bytes) = sprintf(buf, "227 Entering Passive Mode (%d,%d,%d,%d,%d,%d)\n",
				   sockname.sin_addr.s_addr & 0xff, 
				   (sockname.sin_addr.s_addr >> 8) & 0xff, 
				   (sockname.sin_addr.s_addr >> 16) & 0xff,
				   sockname.sin_addr.s_addr >> 24, lporthi, lportlo);
	}
	newsession.sin_port = htons(rport);
	newsession.sin_family = AF_INET;
	newsession.sin_addr.s_addr = remip[0] | (remip[1] << 8)
		| (remip[2] << 16) | (remip[3] << 24);

	debug("ftpdata server ip: %s", inet_ntoa(newsession.sin_addr));
	debug("ftpdata server port: %d", rport);
	debug("listening for ftpdata on port %d", lport);
	debug("listening for ftpdata on addr %s", inet_ntoa(sockname.sin_addr));


	/* now that we're bound and listening, we can safely send the new
	   string without fear of them getting a connection refused. */
	redir_write(send, buf, (*bytes), REDIR_OUT);     

	/* make a new process to handle the dataconnection correctly,
	   for the PASV mode this isn't a problem because after sending the 
	   PASV command, the data connection, get active. For the PORT command
	   the server must send a success, if starting here with the copyloop
	   the success command never arrive the client.*/
	
	switch (fork()) {
     	case -1: /* Error */
		syslog(LOG_ERR, "Failed calling fork(): %s", strerror(errno));
		_exit(1);

	case 0:  /* Child */
		/* turn off ftp checking while the data connection is active */
		ftp = 0;
		do_accept(localsock, &newsession);
		close(localsock);
     		_exit(0);

     	default: /* Parent */
		close(localsock);
		break;
	}
}
#endif


static void copyloop(int insock, int outsock, int timeout_secs)
{
	fd_set iofds;
	fd_set c_iofds;
	int max_fd;			/* Maximum numbered fd used */
	struct timeval timeout;
	unsigned long bytes;
	unsigned long bytes_in = 0;
	unsigned long bytes_out = 0;
	unsigned int start_time, end_time;
	char *buf;

	/* Record start time */
	start_time = (unsigned int)time(NULL);

	/* file descriptor bits */
	FD_ZERO(&iofds);
	FD_SET(insock, &iofds);
	FD_SET(outsock, &iofds);
    
	if (insock > outsock)
		max_fd = insock;
	else
		max_fd = outsock;

	buf = malloc(bufsize);
	if (!buf) {
		syslog(LOG_ERR, "Failed allocating session buffer: %s", strerror(errno));
		goto no_mem;
	}

	debug("Entering copyloop() - timeout is %d", timeout_secs);
	while (1) {
		(void) memcpy(&c_iofds, &iofds, sizeof(iofds));

		/* Set up timeout, Linux returns seconds left in this structure
		 * so we have to reset it before each select(). */
		timeout.tv_sec = timeout_secs;
		timeout.tv_usec = 0;


		if (select(max_fd + 1, &c_iofds, NULL, NULL, (timeout_secs ? &timeout : NULL)) <= 0) {
			syslog(LOG_NOTICE, "Connection timeout: %d sec", timeout_secs);
			break;
		}

		if (FD_ISSET(insock, &c_iofds)) {
			bytes = read(insock, buf, bufsize);
			if (bytes <= 0)
				break;

			/* Make sure to terminate buffer before passing it to ftp_clean() */
			buf[bytes] = 0;

#ifndef NO_FTP
			if (ftp & FTP_PORT)
				/* if we're correcting FTP, lookup for a PORT commando
				   in the buffer, if yes change this and establish 
				   a new redirector for the data */
				ftp_clean(outsock, buf, &bytes,0); 
			else
#endif
				if (redir_write(outsock, buf, bytes, REDIR_OUT) != bytes)
					break;
			bytes_out += bytes;
		}
		if (FD_ISSET(outsock, &c_iofds)) {
			bytes = read(outsock, buf, bufsize);
			if (bytes <= 0)
				break;

			/* Make sure to terminate buffer before passing it to ftp_clean() */
			buf[bytes] = 0;

#ifndef NO_FTP
			/* if we're correcting for PASV on ftp redirections, then
			 * fix buf and bytes to have the new address, among other
			 * things */
			if (ftp & FTP_PASV)
				ftp_clean(insock, buf, &bytes,1);
			else 
#endif
				if (redir_write(insock, buf, bytes, REDIR_IN) != bytes)
					break;
			bytes_in += bytes;
		}
	}
	debug("Leaving main copyloop");
	free(buf);
no_mem:
/*
  setsockopt(insock, SOL_SOCKET, SO_REUSEADDR, &reuse_addr, sizeof(reuse_addr));
  setsockopt(insock, SOL_SOCKET, SO_LINGER, &linger_opt, sizeof(SO_LINGER)); 
  setsockopt(outsock, SOL_SOCKET, SO_REUSEADDR, &reuse_addr, sizeof(reuse_addr));
  setsockopt(outsock, SOL_SOCKET, SO_LINGER, &linger_opt, sizeof(SO_LINGER)); 
*/
	shutdown(insock,0);
	shutdown(outsock,0);
	close(insock);
	close(outsock);
	debug("copyloop - sockets shutdown and closed");
	end_time = (unsigned int) time(NULL);
	debug("copyloop - connect time: %8d seconds", end_time - start_time);
	debug("copyloop - transfer in:  %8ld bytes", bytes_in);
	debug("copyloop - transfer out: %8ld bytes", bytes_out);
	syslog(LOG_NOTICE, "Disconnect %d secs, %ld in %ld out", (end_time - start_time), bytes_in, bytes_out);
}

void doproxyconnect(int socket)
{
	int x;
	char buf[128];

	/* write CONNECT string to proxy */
	sprintf((char *)&buf, "CONNECT %s HTTP/1.0\n\n", connect_str);
	x = write(socket, (char *)&buf, strlen(buf));
	if (x < 1) {
		syslog(LOG_ERR, "Failed writing to proxy: %s", strerror(errno));
		exit(1);
	}

	/* now read result */
	x = read(socket, (char *)&buf, sizeof(buf));
	if (x < 1) {
		syslog(LOG_ERR, "Failed reading reply from proxy: %s", strerror(errno));
		exit(1);
	}
	/* no more error checking for now -- something should be added later */
	/* HTTP/1.0 200 Connection established */
}


/* lwait for a connection and move into copyloop...  again,
   ftp redir will call this, so we don't dupilcate it. */
static void do_accept(int servsock, struct sockaddr_in *target)
{
	int clisock, status;
	int targetsock;
	struct sockaddr_in client, addr_out;
	socklen_t clientlen = sizeof(client);
     
	memset(&client, 0, sizeof(client));
	memset(&addr_out, 0, sizeof(addr_out));

	debug("top of accept loop");
	clisock = accept(servsock, (struct sockaddr *)&client, &clientlen);
	if (clisock < 0) {
		syslog(LOG_ERR, "Failed calling accept(): %s", strerror(errno));

		switch(errno) {
		case EHOSTUNREACH:
		case ECONNRESET:
		case ETIMEDOUT:
			return;  /* non-fatal errors */

		default:
			exit(1); /* all other errors assumed fatal */
		}
	}
     
	debug("peer IP is %s", inet_ntoa(client.sin_addr));
	debug("peer socket is %d", ntohs(client.sin_port));

	/*
	 * Double fork here so we don't have to wait later
	 * This detaches us from our parent so that the parent
	 * does not need to pick up dead kids later.
	 *
	 * This needs to be done before the hosts_access stuff, because
	 * extended hosts_access options expect to be run from a child.
	 */
	switch (fork()) {
     	case -1: /* Error */
		syslog(LOG_ERR, "Server failed fork(): %s", strerror(errno));
     		_exit(1);

     	case 0:  /* Child */
     		break;

     	default: /* Parent */
     		/* Wait for child (who has forked off grandchild) */
     		(void) wait(&status);

     		/* Close sockets to prevent confusion */
		close(clisock);
     		return;
	}

	/* We are now the first child. Fork again and exit */
	  
	switch (fork()) {
     	case -1: /* Error */
		syslog(LOG_ERR, "Failed duoble fork(): %s", strerror(errno));
     		_exit(1);

     	case 0:  /* Child */
     		break;

     	default: /* Parent */
     		_exit(0);
	}
     
	/* We are now the grandchild */

#ifdef USE_TCP_WRAPPERS
	request_init(&request, RQ_DAEMON, ident, RQ_FILE, clisock, 0);
	sock_host(&request);
	sock_hostname(request.client);
	sock_hostaddr(request.client);

	if (!hosts_access(&request)) {
		refuse(&request);
		_exit(0);
	}

	syslog(LOG_INFO, "Connection from %s", eval_client(&request));
#endif /* USE_TCP_WRAPPERS */

	if ((targetsock = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
		syslog(LOG_ERR, "Failed creating target socket: %s", strerror(errno));
		_exit(1);
	}

	if (transproxy) {
		memcpy(&addr_out, &client, sizeof(struct sockaddr_in));
		addr_out.sin_port = 0;
	}
          
	/* Set up outgoing IP addr (optional) */
	if (bind_addr && !transproxy) {
		struct hostent *hp;

		addr_out.sin_family = AF_INET;
		addr_out.sin_port = 0;
		hp = gethostbyname(bind_addr);
		if (hp == NULL) {
			syslog(LOG_ERR, "Failed resolving outbound IP address, %s: %s", bind_addr, strerror(errno));
			exit(1);
		}
		memcpy(&addr_out.sin_addr, hp->h_addr, hp->h_length);

		debug("IP address for target is %s", inet_ntoa(addr_out.sin_addr));
	}

	if (bind_addr || transproxy) {
		/* this only makes sense if an outgoing IP addr has been forced;
		 * at this point, we have a valid targetsock to bind() to.. */
		/* also, if we're in transparent proxy mode, this option
		   never makes sense */

		if (bind(targetsock, (struct sockaddr *)&addr_out, sizeof(addr_out)) < 0) {
			/* the port parameter fetch the really port we are listening,
			 * it should only be different if the input value is 0 (let
			 * the system pick a port) */
			syslog(LOG_ERR, "Failed binding target socket: %s", strerror(errno));
			_exit(1);
		}
		debug("outgoing IP is %s", inet_ntoa(addr_out.sin_addr));
	}

	if (connect(targetsock, (struct sockaddr *)target, sizeof(struct sockaddr_in)) < 0) {
		syslog(LOG_ERR, "Failed connecting to target %s: %s", inet_ntoa(addr_out.sin_addr), strerror(errno));
		_exit(1);
	}
     
	debug("connected to %s", inet_ntoa(target->sin_addr));
	if (do_syslog) { /* XXX: Check loglevel >= LOG_INFO in the future */
		char tmp1[20] = "", tmp2[20] = "";

		inet_ntop(AF_INET, &client.sin_addr, tmp1, sizeof(tmp1));
		inet_ntop(AF_INET, &target->sin_addr, tmp2, sizeof(tmp2));
	  
		syslog(LOG_INFO, "Connecting %s:%d to %s:%d",
		       tmp1, ntohs(client.sin_port),
		       tmp2, ntohs(target->sin_port));
	}

	/* do proxy stuff */
	if (connect_str)
		doproxyconnect(targetsock);

#ifndef NO_SHAPER
	/* initialise random number if necessary */
	if (random_wait > 0)
		srand(getpid());
#endif

	copyloop(clisock, targetsock, timeout);
	exit(0);	/* Exit after copy */
}

/*
 * bind to a new socket, we do this out here because passive-fixups
 * are going to call it too, and there's no sense dupliciting the
 * code.
 *
 * fail is true if we should just return a -1 on error, false if we
 * should bail.
 */
static int bindsock(char *addr, int port, int fail)
{
	int ret, sd;
	struct sockaddr_in server;
	int reuse_addr = 1;                 /* allow address reuse */
	struct linger linger_opt = { 0, 0}; /* do not linger */

	/*
	 * Get a socket to work with.  This socket will
	 * be in the Internet domain, and will be a
	 * stream socket.
	 */
	sd = socket(AF_INET, SOCK_STREAM, 0);
	if (sd < 0) {
		if (fail)
			return -1;

		syslog(LOG_ERR, "Failed creating server socket: %s", strerror(errno));
		exit(1);
	}

	memset(&server, 0, sizeof(server));
	server.sin_family = AF_INET;
	server.sin_port = htons(port);
	if (addr != NULL) {
		struct hostent *hp;
	  
		debug("listening on %s", addr);
		if ((hp = gethostbyname(addr)) == NULL) {
			syslog(LOG_ERR, "Cannot resolve hostname %s: %s", addr, strerror(errno));
			exit(1);
		}
		memcpy(&server.sin_addr, hp->h_addr, hp->h_length);
	} else {
		debug("local IP is default");
		server.sin_addr.s_addr = htonl(inet_addr("0.0.0.0"));
	}
     
	ret = setsockopt(sd, SOL_SOCKET, SO_REUSEADDR, &reuse_addr, sizeof(reuse_addr));
	if (ret != 0) {
		if (fail) {
			close(sd);
			return -1;
		}

		syslog(LOG_ERR, "Failed setting socket option SO_REUSEADDR: %s", strerror(errno));
		exit(1);
	}

	ret = setsockopt(sd, SOL_SOCKET, SO_LINGER, &linger_opt, sizeof(linger_opt)); 
	if (ret != 0) {
		if (fail) {
			close(sd);
			return -1;
		}

		syslog(LOG_ERR, "Failed setting socket option SO_LINGER: %s", strerror(errno));
		exit(1);
	}
     
	/*
	 * Try to bind the address to the socket.
	 */
	if (bind(sd, (struct sockaddr *)&server, sizeof(server)) < 0) {
		if (fail) {
			close(sd);
			return -1;
		}

		syslog(LOG_ERR, "Failed binding server socket: %s", strerror(errno));
		exit(1);
	}
     
	/*
	 * Listen on the socket.
	 */
	if (listen(sd, 10) < 0) {
		if (fail) {
			close(sd);
			return -1;
		}

		syslog(LOG_ERR, "Failed calling listen() on server socket: %s", strerror(errno));
		exit(1);
	}
     
	return sd;
}

int main(int argc, char *argv[])
{
	int log_opts = LOG_PID | LOG_CONS | LOG_NDELAY;

	parse_args(argc, argv);

#ifdef LOG_PERROR
	if (!background && do_syslog < 1)
		log_opts |= LOG_PERROR;
#endif
	openlog(ident, log_opts, LOG_DAEMON);

	if (inetd) {
		int targetsock;
		char *target_ip;
		struct sockaddr_in target;
		struct sockaddr_in client, addr_out;
		socklen_t client_size = sizeof(client);

		memset(&target, 0, sizeof(target));
		memset(&client, 0, sizeof(client));
		memset(&addr_out, 0, sizeof(addr_out));

#ifdef USE_TCP_WRAPPERS
		request_init(&request, RQ_DAEMON, ident, RQ_FILE, 0, 0);
		sock_host(&request);
		sock_hostname(request.client);
		sock_hostaddr(request.client);
	
		if (!hosts_access(&request))
			refuse(&request);
#endif /* USE_TCP_WRAPPERS */

		if (!getpeername(0, (struct sockaddr *)&client, &client_size)) {
			debug("peer IP is %s", inet_ntoa(client.sin_addr));
			debug("peer socket is %d", ntohs(client.sin_port));
		}

		memset(&target, 0, sizeof(target));
		target.sin_family = AF_INET;
		target.sin_port = htons(target_port);
		if (target_addr != NULL) {
			struct hostent *hp;

			debug("target is %s", target_addr);
			if ((hp = gethostbyname(target_addr)) == NULL) {
				syslog(LOG_ERR, "Unknown host %s", target_addr);
				exit(1);
			}
			memcpy(&target.sin_addr, hp->h_addr, hp->h_length);
		} else {
			debug("target is default");
			target.sin_addr.s_addr = htonl(inet_addr("0.0.0.0"));
		}

		target_ip = strdup(inet_ntoa(target.sin_addr));
		debug("target IP address is %s", target_ip);
		debug("target port is %d", target_port);

		targetsock = socket(AF_INET, SOCK_STREAM, 0);
		if (targetsock < 0) {
			syslog(LOG_ERR, "Failed creating target socket: %s", strerror(errno));
			exit(1);
		}

		if (transproxy) {
			memcpy(&addr_out, &client, sizeof(struct sockaddr_in));
			addr_out.sin_port = 0;
		}

		/* Set up outgoing IP addr (optional) */
		if (bind_addr && !transproxy) {
			struct hostent *hp;

			addr_out.sin_family = AF_INET;
			addr_out.sin_port = 0;
			hp = gethostbyname(bind_addr);
			if (hp == NULL) {
				syslog(LOG_ERR, "Cannot resolve outbound IP address %s", bind_addr);
				exit(1);
			}
			memcpy(&addr_out.sin_addr, hp->h_addr, hp->h_length);

			debug("IP address for target is %s", inet_ntoa(addr_out.sin_addr));
		}

		if (bind_addr || transproxy) {
			/* this only makes sense if an outgoing IP addr has been forced;
			 * at this point, we have a valid targetsock to bind() to.. */
			if (bind(targetsock, (struct sockaddr *)&addr_out, sizeof(addr_out)) < 0) {
				syslog(LOG_ERR, "Failed binding to outbound address: %s", strerror(errno));
				return 1;
			}
			debug("outgoing IP is %s", inet_ntoa(addr_out.sin_addr));
		}

		if (connect(targetsock, (struct sockaddr *)&target, sizeof(target)) < 0) {
			syslog(LOG_ERR, "Failed connecting to target %s: %s", target_ip, strerror(errno));
			return 1;
		}

		syslog(LOG_INFO, "Connecting %s:%d to %s:%d", inet_ntoa(client.sin_addr), ntohs(client.sin_port),
		       target_ip, ntohs(target.sin_port));

		/* Just start copying - one side of the loop is stdin - 0 */
		copyloop(0, targetsock, timeout);
	} else {
		int sd;
	
		if (background) {
			syslog(LOG_DEBUG, "Daemonizing ...");
			if (-1 == daemon(0, 0)) {
				syslog(LOG_ERR, "Failed daemonizing: %s", strerror(errno));
				return 1;
			}
		}

		sd = bindsock(local_addr, local_port, 0);
		if (sd == -1) {
			syslog(LOG_ERR, "Failed bindsock(): %s", strerror(errno));
			return 1;
		}

		/*
		 * Accept connections.  When we accept one, ns
		 * will be connected to the client.  client will
		 * contain the address of the client.
		 */
		while (1) {
			char *target_ip;
			struct sockaddr_in target;

			memset(&target, 0, sizeof(target));
			target.sin_family = AF_INET;
			target.sin_port = htons(target_port);
			if (target_addr != NULL) {
				struct hostent *hp;

				debug("target is %s", target_addr);
				if ((hp = gethostbyname(target_addr)) == NULL) {
					syslog(LOG_ERR, "Unknown host %s", target_addr);
					exit(1);
				}
				memcpy(&target.sin_addr, hp->h_addr, hp->h_length);
			} else {
				debug("target is default");
				target.sin_addr.s_addr = htonl(inet_addr("0.0.0.0"));
			}

			target_ip = strdup(inet_ntoa(target.sin_addr));
			debug("target IP address is %s", target_ip);
			debug("target port is %d", target_port);

			do_accept(sd, &target);
		}
	}

	return 0;
}
