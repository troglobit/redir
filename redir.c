/* A TCP port redirector for UNIX
 *
 * Copyright (c) 1996-1999  Sam Creasey <sammy@oh.verio.com>
 * Copyright (c) 1996       Nigel Metheringham <Nigel.Metheringham@ThePLAnet.net>
 * Copyright (c) 2016       Joachim Nilsson <troglobit@gmail.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, see <http://www.gnu.org/licenses/>
 */

#include "config.h"

#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <getopt.h>
#define SYSLOG_NAMES
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

int inetd      = 0;
int background = 1;
int timeout    = 0;
int loglevel   = LOG_NOTICE;
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
char *prognm      = PACKAGE_NAME;

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
		syslog(LOG_DEBUG, "random wait: %u", rand_time);
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
		syslog(LOG_DEBUG, "bandwidth wait: %lu", 1000 * bits / max_bandwidth);
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
	fprintf(stderr,"\n"
		"Usage: %s [-hinspv] [-b IP]  [-f TYPE] [-I NAME] [-l LEVEL] [-t SEC]\n"
		"                       [-x STR] [-m BPS] [-o FLAG] [-w MSEC] [-z BYTES]\n"
		"                       [SRC]:PORT [DST]:PORT\n", prognm);
	fprintf(stderr, "\n"
		"Options:\n"
		" -b, --bind=IP            Force specific IP to bind() to when listening for\n"
		"                          incoming connections.  Not applicable with -p\n"
		" -h, --help               Show this help text\n"
#ifndef NO_FTP
		" -f, --ftp=TYPE           Redirect FTP connections.  Where type is\n"
		"                          one of: 'port', 'pasv', or 'both'\n"
#endif
		" -i, --inetd              Run from inetd, SRC:PORT comes from stdin\n"
		"                          Usage: %s [OPTIONS] [DST]:PORT\n"
		" -I, --ident=NAME         Identity, tag syslog messages with NAME\n"
#ifdef USE_TCP_WRAPPERS
		"                          Also used as service name for TCP wrappers\n"
#endif
		" -l, --loglevel=LEVEL     Set log level: none, err, notice*, info, debug\n"
		" -n, --foreground         Run in foreground, do not detach from terminal\n"
		" -p, --transproxy         Run in Linux's transparent proxy mode\n"
		" -s, --syslog             Log messages to syslog\n"
		" -t, --timeout=SEC        Set timeout to SEC seconds, default off (0)\n"
		" -v, --version            Show program version\n"
		" -x, --connect=STR        CONNECT string passed to proxy server\n"
#ifdef COMPAT_OPTIONS
		"\n"
		"Compatibility options:\n"
		"     --lport=PORT         Local port (when not running from inetd)\n"
		"     --laddr=ADDRESS      Local address (when not running from inetd)\n"
		"     --cport=PORT         Remote port to redirect traffic to\n"
		"     --caddr=ADDRESS      Remote address to redirect traffic to\n"
#endif
#ifndef NO_SHAPER
		"\n"
		"Traffic Shaping:\n"
		" -m, --max-bandwidth=BPS  Limit the bandwidth to BPS bits/second\n"
		" -o, --wait-in-out=FLAG   Wait for in(1), out(2), or in&out(3)\n"
		" -w, --random-wait=MSEC   Wait MSEC milliseconds before each packet\n"
		" -z, --bufsize=BYTES      Size of the traffic shaping buffer\n"
#endif
		"\n"
		"SRC and DST are optional, %s will revert to use 0.0.0.0 (ANY)\n"
		"Bug report address: %s\n"
		"\n", prognm, prognm, PACKAGE_BUGREPORT);

	return code;
}

static int loglvl(char *level)
{
	int i;

	for (i = 0; prioritynames[i].c_name; i++) {
		if (!strcmp(prioritynames[i].c_name, level))
			return prioritynames[i].c_val;
	}

	return atoi(level);
}

static int parse_port(char *arg)
{
	int port;
	struct servent *s;

	s = getservbyname(arg, "tcp");
	if (s != NULL)
		port = ntohs(s->s_port);
	else
		port = atoi(arg);

	return port;
}

static int parse_ipport(char *arg, char *buf, size_t len)
{
	char *port;

	if (!arg || !buf || !len)
		return -1;

	port = strchr(arg, ':');
	if (!port)
		return -1;
	*port++ = 0;

	snprintf(buf, len, "%s", arg);

	return parse_port(port);
}

static char *progname(char *arg0)
{
	char *nm;

	nm = strrchr(arg0, '/');
	if (nm)
		nm++;
	else
		nm = arg0;

	return nm;
}

static void parse_args(int argc, char *argv[])
{
	static struct option long_options[] = {
		{"help",          no_argument,       0, 'h'},
		{"bind_addr",     required_argument, 0, 'b'},
		{"bind",          required_argument, 0, 'b'},
		{"timeout",       required_argument, 0, 't'},
		{"inetd",         no_argument,       0, 'i'},
		{"ident",         required_argument, 0, 'I'},
		{"loglevel",      required_argument, 0, 'l'},
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
#ifdef COMPAT_OPTIONS
		{"caddr",         required_argument, 0, 128},
		{"cport",         required_argument, 0, 129},
		{"laddr",         required_argument, 0, 130},
		{"lport",         required_argument, 0, 131},
#endif
		{"version",       no_argument,       0, 'v'},
		{0, 0, 0, 0}
	};
	
	extern int optind;
	int opt, compat = 0;
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
	prognm = progname(argv[0]);
	while ((opt = getopt_long(argc, argv, "b:hiI:l:npst:vx:" FTP_OPTS SHAPER_OPTS, long_options, NULL)) != -1) {
		switch (opt) {
		case 'b':
			bind_addr = optarg;
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

		case 'l':
			loglevel = loglvl(optarg);
			if (-1 == loglevel)
				exit(usage(1));
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
#ifdef COMPAT_OPTIONS
		case 128:	/* --caddr=1.2.3.4 */
			compat      = 1;
			target_addr = strdup(optarg);
			break;

		case 129:	/* --cport=80 */
			compat      = 1;
			target_port = atoi(optarg);
			break;

		case 130:	/* --laddr=127.0.0.1 */
			compat     = 1;
			local_addr = strdup(optarg);
			break;

		case 131:	/* --lport=8080 */
			compat     = 1;
			local_port = atoi(optarg);
			break;
#endif
		default:
			exit(usage(1));
		}
	}

	if (compat) {
		background = 0;
		do_syslog--;
		goto done;
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

done:
	if (!ident)
		ident = prognm;

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

	syslog(LOG_DEBUG, "ftpdata server ip: %s", inet_ntoa(newsession.sin_addr));
	syslog(LOG_DEBUG, "ftpdata server port: %d", rport);
	syslog(LOG_DEBUG, "listening for ftpdata on port %d", lport);
	syslog(LOG_DEBUG, "listening for ftpdata on addr %s", inet_ntoa(sockname.sin_addr));


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

	syslog(LOG_DEBUG, "Entering copyloop() - timeout is %d", timeout_secs);
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

		syslog(LOG_DEBUG, "target is %s:%d", addr, port);
		hp = gethostbyname(addr);
		if (!hp) {
			syslog(LOG_ERR, "Unknown host %s", addr);
			return -1;
		}
		memcpy(&target->sin_addr, hp->h_addr, hp->h_length);
	} else {
		syslog(LOG_DEBUG, "target is default, 0.0.0.0:%d", port);
		target->sin_addr.s_addr = htonl(inet_addr("0.0.0.0"));
	}

	return 0;
}

static int target_connect(int client, struct sockaddr_in *target)
{
	int sd;
	struct sockaddr_in peer, addr_out;
	socklen_t peerlen = sizeof(peer);

	memset(&peer, 0, sizeof(peer));
	memset(&addr_out, 0, sizeof(addr_out));

#ifdef USE_TCP_WRAPPERS
	if (verify_request(client))
		return -1;
#endif /* USE_TCP_WRAPPERS */

	if (!getpeername(client, (struct sockaddr *)&peer, &peerlen)) {
		syslog(LOG_DEBUG, "peer IP is %s", inet_ntoa(peer.sin_addr));
		syslog(LOG_DEBUG, "peer socket is %d", ntohs(peer.sin_port));
	}

	syslog(LOG_DEBUG, "target IP address is %s", inet_ntoa(target->sin_addr));
	syslog(LOG_DEBUG, "target port is %d", ntohs(target->sin_port));

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

		syslog(LOG_DEBUG, "IP address for target is %s", inet_ntoa(addr_out.sin_addr));
	}

	sd = socket(AF_INET, SOCK_STREAM, 0);
	if (sd < 0) {
		syslog(LOG_ERR, "Failed creating target socket: %s", strerror(errno));
		return -1;
	}

	if (bind_addr || transproxy) {
		if (bind(sd, (struct sockaddr *)&addr_out, sizeof(addr_out)) < 0) {
			syslog(LOG_ERR, "Failed binding to outbound address: %s", strerror(errno));
			close(sd);
			return -1;
		}
	}

	if (connect(sd, (struct sockaddr *)target, sizeof(*target)) < 0) {
		syslog(LOG_ERR, "Failed connecting to target %s: %s", inet_ntoa(target->sin_addr), strerror(errno));
		close(sd);
		return -1;
	}

	syslog(LOG_INFO, "Connecting %s:%d to %s:%d", inet_ntoa(peer.sin_addr), ntohs(peer.sin_port),
	       inet_ntoa(target->sin_addr), ntohs(target->sin_port));

	return sd;
}

static int client_accept(int sd, struct sockaddr_in *target)
{
	int client, status;

	syslog(LOG_DEBUG, "Waiting for client to connect on server socket ...");
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
	  
		syslog(LOG_DEBUG, "listening on %s:%d", addr, port);
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
		syslog(LOG_DEBUG, "local IP is default, listening on 0.0.0.0:%d", port);
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
	setlogmask(LOG_UPTO(loglevel));

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
