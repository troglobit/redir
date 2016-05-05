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

#define FTP_PORT 1
#define FTP_PASV 2

#define REDIR_IN  1
#define REDIR_OUT 0

#define debug(fmt, args...)	if (do_debug) syslog(LOG_DEBUG, fmt, ##args)

int inetd      = 0;
int background = 1;
int timeout    = 0;
int do_debug   = 0;
int do_syslog  = 0;
int transproxy = 0;

char *target_addr = NULL;
int   target_port = 0;
char *local_addr  = NULL;
int   local_port  = 0;
char *bind_addr   = NULL;

#ifndef NO_FTP
int ftp = 0;
#endif

#ifndef NO_SHAPER
int max_bandwidth = 0;
int random_wait   = 0;
int wait_in_out   = 3; /* bit 0: wait for "in", bit 1: wait for "out" */
int wait_in       = 1;
int wait_out      = 1;
#endif

size_t bufsize    = BUFSIZ;
char *connect_str = NULL;	/* CONNECT string passed to proxy */
char *ident       = NULL;

/* prototype anything needing it */
static int client_accept(int sd, struct sockaddr_in *target);
static int server_socket(char *addr, int port, int fail);

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
		waitbw.tv_sec  = bits / max_bandwidth;
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
		"  -b,--bind=IP            Force specific IP to bind() to when listening\n"
		"                          for incoming connections\n"
		"  -h,--help               Show this help text\n"
		"  -d,--debug              Enable debugging info\n"
#ifndef NO_FTP
		"  -f,--ftp=TYPE           Redirect FTP connections.  Where type is\n"
		"                          one of: 'port', 'pasv', or 'both'\n"
#endif
		"  -i,--inetd              Run from inetd, SRC:PORT comes from stdin\n"
		"                          Usage: %s [OPTIONS] [DST]:PORT\n"
		"  -I,--ident=NAME         Identity, tag syslog messages with NAME\n"
		"  -n,--foreground         Run in foreground, do not detach from terminal\n"
		"  -p,--transproxy         run in linux's transparent proxy mode\n"
		"  -s,--syslog             Log messages to syslog\n"
		"  -t,--timeout=SEC        Set timeout to SEC seconds, default off (0)\n"
		"  -v,--version            Show program version\n"
		"  -x,--connect=STR        CONNECT string passed to proxy server\n"
#ifdef USE_TCP_WRAPPERS
		"                          Also used as service name for TCP wrappers\n"
#endif
#ifndef NO_SHAPER
		"\n"
		"Traffic Shaping:\n"
		"  -m,--max-bandwidth=BPS  Limit the bandwidth to BPS bits/second\n"
		"  -o,--wait-in-out=FLAG   Wait for in(1), out(2), or in&out(3)\n"
		"  -w,--random-wait=MSEC   Wait MSEC milliseconds before each packet\n"
		"  -z,--bufsize=BYTES      Size of the traffic shaping buffer\n"
#endif
		"\n"
		"SRC and DST are optional, %s will revert to use 0.0.0.0 (ANY)\n"
		"Bug report address: %s\n"
		"\n", __progname, __progname, PACKAGE_BUGREPORT);

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
#define FTP_OPTS "f"
#else
#define FTP_OPTS ""
#endif

#ifndef NO_SHAPER
#define SHAPER_OPTS "m:o:w:z:"
#else
#define SHAPER_OPTS ""
#endif
	while ((opt = getopt_long(argc, argv, "b:dhiI:npst:vx:" FTP_OPTS SHAPER_OPTS, long_options, NULL)) != -1) {
		switch (opt) {
		case 'b':
			bind_addr = optarg;
			break;

		case 'd':
			do_debug++;
			break;

#ifndef NO_FTP
		case 'f':
			ftp_type = optarg;
			if (!ftp_type)
				exit(usage(1));
			break;
#endif

		case 'h':
			exit(usage(0));

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

		case 'p':
			transproxy++;
			break;

		case 's':
			do_syslog++;
			break;

		case 't':
			timeout = atol(optarg);
			break;

#ifndef NO_SHAPER
                case 'm':
			max_bandwidth = atol(optarg);
			break;
 
                case 'o':
			wait_in_out = atol(optarg);
			wait_in     = wait_in_out & 1;
			wait_out    = wait_in_out & 2;
			break;

                case 'w':
			random_wait = atol(optarg);
			break;

                case 'z':
			bufsize = (unsigned int)atol(optarg);
			if (bufsize < 256) {
				syslog(LOG_ERR, "Too small buffer (%zd), must be at least 256 bytes!", bufsize);
				exit(usage(1));
			}
			break;
 #endif
		case 'v':
			fprintf(stderr, "%s\n", PACKAGE_VERSION);
			exit(0);

		case 'x':
			connect_str = optarg;
			break;

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
   
void ftp_clean(int send, char *buf, ssize_t *bytes, int ftpsrv)
{
	char *port_start;
	int rporthi, lporthi;
	int lportlo, rportlo;
	int lport, rport;
	int remip[4];
	int sd;
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
	sd = server_socket(inet_ntoa(sockname.sin_addr), 0, 1);
	if (sd == -1) {
		syslog(LOG_ERR, "Failed creating server socket: %s", strerror(errno));
		exit(1);
	}
	
	/* get the real info */
	if (getsockname(sd, (struct sockaddr *)&sockname, &socksize) < 0) {
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
		client_accept(sd, &newsession);
		close(sd);
     		_exit(0);

     	default: /* Parent */
		close(sd);
		break;
	}
}
#endif


static void copyloop(int insock, int outsock, int timeout_secs)
{
	int max_fd;			/* Maximum numbered fd used */
	struct timeval timeout;
	ssize_t bytes;
	ssize_t bytes_in = 0;
	ssize_t bytes_out = 0;
	unsigned int start_time, end_time;
	char *buf;

	/* Record start time */
	start_time = (unsigned int)time(NULL);

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
		fd_set iofds;

		FD_ZERO(&iofds);
		FD_SET(insock, &iofds);
		FD_SET(outsock, &iofds);

		/* Set up timeout, Linux returns seconds left in this structure
		 * so we have to reset it before each select(). */
		timeout.tv_sec = timeout_secs;
		timeout.tv_usec = 0;

		if (select(max_fd + 1, &iofds, NULL, NULL, (timeout_secs ? &timeout : NULL)) <= 0) {
			syslog(LOG_DEBUG, "Connection timeout: %d sec", timeout_secs);
			break;
		}

		if (FD_ISSET(insock, &iofds)) {
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
				ftp_clean(outsock, buf, &bytes, 0);
			else
#endif
				if (redir_write(outsock, buf, bytes, REDIR_OUT) != bytes)
					break;
			bytes_out += bytes;
		}

		if (FD_ISSET(outsock, &iofds)) {
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
	free(buf);
no_mem:
	shutdown(insock, SHUT_RDWR);
	shutdown(outsock, SHUT_RDWR);
	close(insock);
	close(outsock);
	end_time = (unsigned int)time(NULL);
	syslog(LOG_INFO, "Disconnect after %d sec, %ld bytes in, %ld bytes out", (end_time - start_time), bytes_in, bytes_out);
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

#ifdef USE_TCP_WRAPPERS
static int verify_request(int sd)
{
	struct request_info ri;

	request_init(&ri, RQ_DAEMON, ident, RQ_FILE, sd, 0);
	sock_host(&ri);
	sock_hostname(ri.client);
	sock_hostaddr(ri.client);

	if (!hosts_access(&ri)) {
		syslog(LOG_WARNING, "Connection from %s DENIED", eval_client(&ri));
		refuse(&ri);
		return -1;
	}

	syslog(LOG_INFO, "Connection from %s ALLOWED", eval_client(&ri));

	return 0;
}
#endif /* USE_TCP_WRAPPERS */

static int target_init(char *addr, int port, struct sockaddr_in *target)
{
	target->sin_family = AF_INET;
	target->sin_port = htons(port);
	if (addr) {
		struct hostent *hp;

		debug("target is %s", addr);
		hp = gethostbyname(addr);
		if (!hp) {
			syslog(LOG_ERR, "Unknown host %s", addr);
			return -1;
		}
		memcpy(&target->sin_addr, hp->h_addr, hp->h_length);
	} else {
		debug("target is default");
		target->sin_addr.s_addr = htonl(inet_addr("0.0.0.0"));
	}

	return 0;
}

static int target_connect(int client, struct sockaddr_in *target)
{
	int sd;
	char *target_ip;
	struct sockaddr_in peer, addr_out;
	socklen_t peerlen = sizeof(peer);

	memset(&peer, 0, sizeof(peer));
	memset(&addr_out, 0, sizeof(addr_out));

#ifdef USE_TCP_WRAPPERS
	if (verify_request(sd))
		return -1;
#endif /* USE_TCP_WRAPPERS */

	if (!getpeername(client, (struct sockaddr *)&peer, &peerlen)) {
		debug("peer IP is %s", inet_ntoa(peer.sin_addr));
		debug("peer socket is %d", ntohs(peer.sin_port));
	}

	target_ip = strdup(inet_ntoa(target->sin_addr));
	debug("target IP address is %s", target_ip);
	debug("target port is %d", ntohs(target->sin_port));

	if (transproxy) {
		memcpy(&addr_out, &peer, sizeof(struct sockaddr_in));
		addr_out.sin_port = 0;
	}

	/* Set up outgoing IP addr (optional) */
	if (bind_addr && !transproxy) {
		struct hostent *hp;

		addr_out.sin_family = AF_INET;
		addr_out.sin_port = 0;
		hp = gethostbyname(bind_addr);
		if (!hp) {
			syslog(LOG_ERR, "Failed resolving outbound IP address, %s: %s", bind_addr, strerror(errno));
			return -1;
		}
		memcpy(&addr_out.sin_addr, hp->h_addr, hp->h_length);

		debug("IP address for target is %s", inet_ntoa(addr_out.sin_addr));
	}

	sd = socket(AF_INET, SOCK_STREAM, 0);
	if (sd < 0) {
		syslog(LOG_ERR, "Failed creating target socket: %s", strerror(errno));
		return -1;
	}

	if (bind_addr || transproxy) {
		if (bind(sd, (struct sockaddr *)&addr_out, sizeof(addr_out)) < 0) {
			syslog(LOG_ERR, "Failed binding to outbound address: %s", strerror(errno));
			return -1;
		}
	}

	if (connect(sd, (struct sockaddr *)target, sizeof(*target)) < 0) {
		syslog(LOG_ERR, "Failed connecting to target %s: %s", target_ip, strerror(errno));
		return -1;
	}

	syslog(LOG_INFO, "Connecting %s:%d to %s:%d", inet_ntoa(peer.sin_addr),
	       ntohs(peer.sin_port), target_ip, ntohs(target->sin_port));

	return sd;
}

static int client_accept(int sd, struct sockaddr_in *target)
{
	int client, status;

	debug("Waiting for client to connect on server socket ...");
	client = accept(sd, NULL, NULL);
	if (client < 0) {
		syslog(LOG_ERR, "Failed calling accept(): %s", strerror(errno));

		switch(errno) {
		case EHOSTUNREACH:
		case ECONNRESET:
		case ETIMEDOUT:
			return 0; /* non-fatal errors */

		default:
			return 1; /* all other errors assumed fatal */
		}
	}
     
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
		close(client);
		return 1;

     	case 0:  /* Child */
     		break;

     	default: /* Parent */
     		/* Wait for child (who has forked off grandchild) */
		(void)wait(&status);

     		/* Close sockets to prevent confusion */
		close(client);
		return 0;
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
	sd = target_connect(client, target);
	if (sd < 0)
		_exit(1);

	/* do proxy stuff */
	if (connect_str)
		doproxyconnect(sd);

#ifndef NO_SHAPER
	/* initialise random number if necessary */
	if (random_wait > 0)
		srand(getpid());
#endif

	copyloop(client, sd, timeout);
	exit(0);

	return 0;
}

/*
 * bind to a new socket, we do this out here because passive-fixups
 * are going to call it too, and there's no sense dupliciting the
 * code.
 *
 * fail is true if we should just return a -1 on error, false if we
 * should bail.
 */
static int server_socket(char *addr, int port, int fail)
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
			if (fail) {
				close(sd);
				return -1;
			}

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
		int sd;
		struct sockaddr_in target;

		memset(&target, 0, sizeof(target));
		if (target_init(target_addr, target_port, &target))
			return 1;

		sd = target_connect(STDIN_FILENO, &target);
		if (sd < 0)
			return 1;

		copyloop(STDIN_FILENO, sd, timeout);
	} else {
		int sd;
	
		if (background) {
			syslog(LOG_DEBUG, "Daemonizing ...");
			if (-1 == daemon(0, 0)) {
				syslog(LOG_ERR, "Failed daemonizing: %s", strerror(errno));
				return 1;
			}
		}

		sd = server_socket(local_addr, local_port, 0);
		if (sd == -1) {
			syslog(LOG_ERR, "Failed server_socket(): %s", strerror(errno));
			return 1;
		}

		while (1) {
			struct sockaddr_in target;

			memset(&target, 0, sizeof(target));
			if (target_init(target_addr, target_port, &target))
				return 1;

			if (client_accept(sd, &target))
				return 1;
		}
	}

	return 0;
}
