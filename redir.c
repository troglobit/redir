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

/* Redir, the code to which is below, is actually a horrible hack of my 
 * other cool network utility, daemon, which is actually a horrible hack 
 * of ora's using C sample code, 12.2.c.  But, hey, they do something.
 * (and that's the key.)
 *      -- Sammy (sammy@freenet.akron.oh.us)
 */

#define  VERSION "0.7"

#include <stdio.h>
#include <string.h>
#include <signal.h>
#include <getopt.h>
#include <syslog.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/wait.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>

#define debug(x)	if (dodebug) fprintf(stderr, x)
#define debug1(x,y)	if (dodebug) fprintf(stderr, x, y)

extern int errno;
int dodebug = 0;
int dosyslog = 0;

#ifdef NEED_STRRCHR
#define strrchr rindex
#endif /* NEED_STRRCHR */

#ifdef NEED_STRDUP
char *
strdup(char * str)
{
    char * result;

    if (result = (char *) malloc(strlen(str) + 1))
	strcpy(result, str);

    return result;
}
#endif /* NEED_STRDUP */
void
redir_usage(char *name)
{
    fprintf(stderr,"usage:\n");
    fprintf(stderr, 
	    "\t%s [options] [remote-host] listen_port connect_port\n", 
	    name);
    fprintf(stderr, "\t%s --inetd [options] [remote-host] connect_port\n", name);
    fprintf(stderr, "\n\tOptions are:-\n");
    fprintf(stderr, "\t\t--inetd\t\trun from inetd\n");
    fprintf(stderr, "\t\t--debug\t\toutput debugging info\n");
    fprintf(stderr, "\t\t--timeout=<n>\tset timeout to n seconds\n");
    fprintf(stderr, "\t\t--syslog=\tlog messages to syslog\n");
    fprintf(stderr, "\t\t--name=<str>\ttag syslog messages with 'str'\n");
    fprintf(stderr, "\n\tVersion %s - $Id$\n", VERSION);
    exit(2);
}

void
parse_args(int argc,
	   char * argv[],
	   char ** target_addr,
	   int * target_port,
	   int * local_port,
	   int * timeout,
	   int * dodebug,
	   int * inetd,
	   int * dosyslog)
{
    static struct option long_options[] = {
	{"debug",    no_argument,       0, 'd'},
	{"timeout",  required_argument, 0, 't'},
	{"inetd",    no_argument,       0, 'i'},
	{"ident",    required_argument, 0, 'n'},
	{"name",     required_argument, 0, 'n'},
	{"syslog",   no_argument,       0, 's'},
	{0,0,0,0}		/* End marker */
    };
    int option_index = 0;
    extern int optind;
    int opt;
    struct servent *portdesc;
    char * ident = NULL;

    while ((opt = getopt_long(argc, argv, "disn:t:", 
			      long_options, &option_index)) != -1) {
	switch (opt) {
	case 'd':
	    (*dodebug)++;
	    break;

	case 't':
	    *timeout = atol(optarg);
	    break;

	case 'i':
	    (*inetd)++;
	    break;

	case 'n':
	    /* This is the ident which is added to syslog messages */
  	    ident = optarg;
	    break;

	case 's':
	    (*dosyslog)++;
	    break;

	default:
	    redir_usage(argv[0]);
	    exit(1);
	    break;
	}
    }

    /* Check number of args */
    if (*inetd) {
	if (((argc - optind) == 1) || ((argc - optind) == 2)) {
	    if ((argc - optind) == 2) {
		*target_addr = argv[optind++];
	    } else {
		target_addr = NULL;
	    }

	    *local_port = 0;
	    if ((portdesc = getservbyname(argv[optind], "tcp")) != NULL) {
		*target_port = ntohs(portdesc->s_port);
	    } else {
		*target_port = atol(argv[optind]);
	    }
	    optind++;

	} else {
	    redir_usage(argv[0]);
	    exit(1);
	}
    } else {
	if (((argc - optind) == 2) || ((argc - optind) == 3)) {
	    if ((argc - optind) == 3) {
		*target_addr = argv[optind++];
	    } else {
		target_addr = NULL;
	    }

	    if ((portdesc = getservbyname(argv[optind], "tcp")) != NULL) {
		*local_port = ntohs(portdesc->s_port);
	    } else {
		*local_port = atol(argv[optind]);
	    }
	    optind++;

	    if ((portdesc = getservbyname(argv[optind], "tcp")) != NULL) {
		*target_port = ntohs(portdesc->s_port);
	    } else {
		*target_port = atol(argv[optind]);
	    }
	    optind++;

	} else {
	    redir_usage(argv[0]);
	    exit(1);
	}
    }

    if (*dosyslog) {
	if (!ident) {
	    if (ident = (char *) strrchr(argv[0], '/')) {
		ident++;
	    } else {
		ident = argv[0];
	    }
	}
	openlog(ident, LOG_PID, LOG_DAEMON);
    }
    return;
}


void
copyloop(int insock, 
	 int outsock,
	 int timeout_secs)
{
    fd_set iofds;
    fd_set c_iofds;
    int max_fd;			/* Maximum numbered fd used */
    struct timeval timeout;
    unsigned long bytes;
    unsigned long bytes_in = 0;
    unsigned long bytes_out = 0;
    unsigned int start_time, end_time;
    char buf[4096];

    /* Record start time */
    start_time = (unsigned int) time(NULL);

    /* Set up timeout */
    timeout.tv_sec = timeout_secs;
    timeout.tv_usec = 0;

    /* file descriptor bits */
    FD_ZERO(&iofds);
    FD_SET(insock, &iofds);
    FD_SET(outsock, &iofds);

    
    if (insock > outsock) {
	max_fd = insock;
    } else {
	max_fd = outsock;
    }

    debug1("Entering copyloop() - timeout is %d\n", timeout_secs);
    while(1) {
	(void) memcpy(&c_iofds, &iofds, sizeof(iofds));


	if (select(max_fd + 1,
		  &c_iofds,
		  (fd_set *)0,
		  (fd_set *)0,
		  (timeout_secs ? &timeout : NULL)) <= 0) {
	    /*	    syslog(LLEV,"connection timeout: %d sec",timeout.tv_sec);*/
	    break;
	}

	if(FD_ISSET(insock, &c_iofds)) {
	    if((bytes = read(insock, buf, sizeof(buf))) <= 0)
		break;
	    if(write(outsock, buf, bytes) != bytes)
		break;
	    bytes_out += bytes;
	}
	if(FD_ISSET(outsock, &c_iofds)) {
	    if((bytes = read(outsock, buf, sizeof(buf))) <= 0)
		break;
	    if(write(insock, buf, bytes) != bytes)
		break;
	    bytes_in += bytes;
	}
    }
    debug("Leaving main copyloop\n");


    setsockopt(insock, SOL_SOCKET, SO_REUSEADDR, 1, sizeof(SO_REUSEADDR));
    setsockopt(insock, SOL_SOCKET, SO_LINGER, 0, sizeof(SO_LINGER)); 
    setsockopt(outsock, SOL_SOCKET, SO_REUSEADDR, 1, sizeof(SO_REUSEADDR));
    setsockopt(outsock, SOL_SOCKET, SO_LINGER, 0, sizeof(SO_LINGER)); 

    shutdown(insock,0);
    shutdown(outsock,0);
    close(insock);
    close(outsock);
    debug("copyloop - sockets shutdown and closed\n");
    end_time = (unsigned int) time(NULL);
    debug1("copyloop - connect time: %8d seconds\n", end_time - start_time);
    debug1("copyloop - transfer in:  %8ld bytes\n", bytes_in);
    debug1("copyloop - transfer out: %8ld bytes\n", bytes_out);
    if (dosyslog) {
	syslog(LOG_NOTICE, "disconnect %d secs, %ld in %ld out",
	       (end_time - start_time), bytes_in, bytes_out);
    }
    return;
}

int
main(int argc, char *argv[])
{

    struct sockaddr_in target, peer;
    char *target_addr;
    int target_port;
    int local_port;
    int timeout = 0;
    int inetd = 0;
    char * target_ip;

    debug("parse args\n");
    parse_args(argc, argv, &target_addr, &target_port, &local_port,
	       &timeout, &dodebug, &inetd, &dosyslog);

    /* Set up target */
    target.sin_family = AF_INET;
    target.sin_port = htons(target_port);
    if (target_addr) {
	struct hostent *hp;

	debug1("target is %s\n", target_addr);
	if ((hp = gethostbyname(target_addr)) == NULL) {
	    fprintf(stderr, "%s: host unknown.\n", target_addr);
	    exit(1);
	}
	memcpy(&target.sin_addr, hp->h_addr, hp->h_length);
    } else {
	debug("target is default\n");
	target.sin_addr.s_addr = htonl(inet_addr("0.0.0.0"));
    }

    target_ip = strdup(inet_ntoa(target.sin_addr));
    debug1("target IP address is %s\n", target_ip);
    debug1("target port is %d\n", target_port);

    if (inetd) {
	int targetsock;
	struct sockaddr_in client;
	int client_size = sizeof(client);

	if (!getpeername(0, (struct sockaddr *) &client, &client_size)) {
	  debug1("peer IP is %s\n", inet_ntoa(client.sin_addr));
	  debug1("peer socket is %d\n", client.sin_port);
	}
	if ((targetsock = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
	    perror("target: socket");
	    exit(1);
	}


	if (connect(targetsock, (struct sockaddr *) &target, 
		    sizeof(target)) < 0) {
	    perror("target: connect");
	    exit(1);
	}

	if (dosyslog) {
	    syslog(LOG_NOTICE, "connecting %s/%d to %s/%d",
		   inet_ntoa(client.sin_addr), client.sin_port,
		   target_ip, target.sin_port);
	}

	/* Just start copying - one side of the loop is stdin - 0 */
	copyloop(0, targetsock, timeout);
    } else {
	int servsock;
	struct sockaddr_in server;

	/*
	 * Get a socket to work with.  This socket will
	 * be in the Internet domain, and will be a
	 * stream socket.
	 */

	if ((servsock = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
	    perror("server: socket");
	    exit(1);
	}

	server.sin_family = AF_INET;
	server.sin_port = htons(local_port);
	server.sin_addr.s_addr = htonl(inet_addr("0.0.0.0"));

	/*
	 * Try to bind the address to the socket.
	 */

	if (bind(servsock, (struct  sockaddr  *) &server, 
		 sizeof(server)) < 0) {
	    perror("server: bind");
	    exit(1);
	}

	setsockopt(servsock, SOL_SOCKET, SO_REUSEADDR, 1, sizeof(SO_REUSEADDR));
	setsockopt(servsock, SOL_SOCKET, SO_LINGER, 0, sizeof(SO_LINGER)); 

	/*
	 * Listen on the socket.
	 */

	if (listen(servsock, 1) < 0) {
	    perror("server: listen");
	    exit(1);
	}

	/*
	 * Accept connections.  When we accept one, ns
	 * will be connected to the client.  client will
	 * contain the address of the client.
	 */

	while (1) {
	    int clisock;
	    int targetsock;
	    struct sockaddr_in client;
	    int clientlen = sizeof(client);
	    int forkpid;

	    debug("top of accept loop\n");
	    if ((clisock = accept(servsock, (struct  sockaddr  *) &client, 
				  &clientlen)) < 0) {
		perror("server: accept");
		exit(1);
	    }

	    debug1("peer IP is %s\n", inet_ntoa(client.sin_addr));
	    debug1("peer socket is %d\n", client.sin_port);

	    if ((targetsock = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
		perror("target: socket");
		exit(1);
	    }

	    if (connect(targetsock, (struct  sockaddr  *) &target, 
			sizeof(target)) < 0) {
		perror("target: connect");
		exit(1);
	    }

	    if (dosyslog)
		syslog(LOG_NOTICE, "connecting %s/%d to %s/%d",
		       inet_ntoa(client.sin_addr), client.sin_port,
		       target_ip, target.sin_port);
	    /*
	     * Double fork here so we don't have to wait later
	     * This detaches us from our parent so that the parent
	     * does not need to pick up dead kids later.
	     */
	    forkpid = fork();
	    if (forkpid == 0){
		forkpid = fork();
		if (forkpid == 0){
		    copyloop(clisock, targetsock, timeout);
		    exit(0);	/* Exit after copy */
		} else {
		    exit(0);	/* Exit back to wait in parent */
		}
	    } else {
		int status;

		/* Wait for child (who has forked off grandchild) */
		(void) wait(&status);
	    }	    

	    /* Close sockets to prevent confusion */
	    close(clisock);
	    close(targetsock);
	}
    }
}


