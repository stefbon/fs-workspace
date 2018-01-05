/*
  2010, 2011, 2012, 2103, 2014, 2015 Stef Bon <stefbon@gmail.com>

  This program is free software; you can redistribute it and/or
  modify it under the terms of the GNU General Public License
  as published by the Free Software Foundation; either version 2
  of the License, or (at your option) any later version.

  This program is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
  GNU General Public License for more details.

  You should have received a copy of the GNU General Public License
  along with this program; if not, write to the Free Software
  Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.

*/

#include "global-defines.h"

#include <stdio.h>
#include <stdlib.h>
#include <stddef.h>
#include <stdbool.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <dirent.h>
#include <errno.h>
#include <err.h>
#include <sys/time.h>
#include <time.h>
#include <pthread.h>
#include <ctype.h>
#include <inttypes.h>

#include <sys/param.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <netdb.h>

#include "logging.h"
#include "main.h"
#include "utils.h"
#include "beventloop.h"
#include "beventloop-xdata.h"
#include "workspace-interface.h"

#include "ssh-common.h"
#include "ssh-connection.h"
#include "ssh-utils.h"
#include "ssh-pubkey-utils.h"

#define _SSH_BEVENTLOOP_NAME			"SSH"

extern int read_incoming_data(int fd, void *ptr, uint32_t events);

void init_ssh_connection(struct ssh_session_s *session)
{
    struct ssh_connection_s *connection=&session->connection;

    connection->type=0;
    connection->fd=0;
    connection->xdata=NULL;

}

int connect_ssh_server(struct ssh_session_s *session, char *address, unsigned int port)
{
    int fd=-1;

    if (isvalid_ipv4(address)==1) {
	struct ssh_connection_s *connection=&session->connection;
	struct sockaddr_in *sin=&connection->socket.inet;

	memset(sin, 0, sizeof(struct sockaddr_in));

	connection->type=_SSH_CONNECTION_TYPE_IPV4;

	fd=socket(PF_INET, SOCK_STREAM, IPPROTO_TCP);

	if (fd>0) {

	    sin->sin_family = AF_INET;
	    sin->sin_port = htons(port);
	    inet_aton(address, &sin->sin_addr);

	    if (connect(fd, (struct sockaddr *) sin, sizeof(struct sockaddr_in))==0) {
		int flags=0;

		logoutput("connect_ssh_server: connected to %s:%i with fd %i", address, port, fd);
		connection->fd=fd;

		flags=fcntl(fd, F_GETFD);
		flags|=O_NONBLOCK;
		fcntl(fd, F_SETFD, flags);

	    } else {

		logoutput("connect_ssh_server: error (%i:%s) connected to %s:%i", errno, strerror(errno), address, port);
		session->status.error=errno;
		close(fd);
		fd=-1;

	    }

	} else {

	    session->status.error=errno;
	    logoutput("connect_ssh_server: unable to create fd error (%i:%s)", errno, strerror(errno));
	    fd=-1;

	}

    } else {

	session->status.error=EINVAL;
	logoutput("connect_ssh_server: unable to connect error (%i:%s)", session->status.error, strerror(session->status.error));

    }

    return fd;

}

signed char compare_session_connection(struct ssh_session_s *session, char *address, unsigned int port)
{
    struct ssh_connection_s *connection=&session->connection;
    struct sockaddr_in *sin=&connection->socket.inet;

    if (sin->sin_port == htons(port)) {
	char *tmp=inet_ntoa(sin->sin_addr);

	if (isvalid_ipv4(address) && strcmp(address, tmp)==0) return 0;

    }

    return -1;

}

void disconnect_ssh_server(struct ssh_session_s *session)
{
    struct ssh_connection_s *connection=&session->connection;

    logoutput("disconnect_ssh_server");

    if (connection->fd>0) {

	close(connection->fd);
	connection->fd=0;

    }

}

int add_session_eventloop(struct ssh_session_s *session, struct context_interface_s *interface, unsigned int *error)
{
    struct ssh_connection_s *connection=&session->connection;

    if (connection->fd>0) {

	connection->xdata=(* interface->add_context_eventloop)(interface, connection->fd, read_incoming_data, session, (char *) _SSH_BEVENTLOOP_NAME, error);

	if (connection->xdata) {

	    logoutput("add_session_eventloop: fd %i added to eventloop", connection->fd);

	} else {

	    logoutput("add_session_eventloop: failed to add fd %i to eventloop, error %i (%s)", connection->fd, *error, strerror(*error));
	    return -1;

	}

    }

    return 0;

}

void remove_session_eventloop(struct ssh_session_s *session)
{
    struct ssh_connection_s *connection=&session->connection;

    logoutput("remove_session_eventloop");

    if (connection->xdata) {

	remove_xdata_from_beventloop(connection->xdata);
	connection->xdata=NULL;

    }

}

char *get_ssh_ipv4(struct ssh_session_s *session, unsigned char what, unsigned int *error)
{
    struct ssh_connection_s *connection=&session->connection;
    struct sockaddr_in addr;
    socklen_t len=sizeof(struct sockaddr_in);
    char *result=NULL;
    char *tmp=NULL;

    if (what==0) {

	if (getsockname(connection->fd, &addr, &len)==-1) {

	    *error=errno;
	    logoutput("get_ssh_ipv4: error %i getting socket name (%s)", *error, strerror(*error));
	    return 0;

	}

    } else {

	if (getpeername(connection->fd, &addr, &len)==-1) {

	    *error=errno;
	    logoutput("get_ssh_ipv4: error %i getting socket peer (%s)", *error, strerror(*error));
	    return 0;

	}

    }

    tmp=inet_ntoa(addr.sin_addr);

    if (tmp) {

	result=strdup(tmp);
	if (result==NULL) *error=ENOMEM;

    }

    return result;

}

char *get_ssh_hostname(struct ssh_session_s *session, unsigned char what, unsigned int *error)
{
    struct ssh_connection_s *connection=&session->connection;
    struct sockaddr addr;
    socklen_t len=sizeof(struct sockaddr);
    int result=-1;
    char tmp[NI_MAXHOST];

    if (what==0) {

	if (getsockname(connection->fd, &addr, &len)==-1) {

	    *error=errno;
	    logoutput("get_ssh_hostname: error %i getting socket name (%s)", *error, strerror(*error));
	    return NULL;

	}

    } else {

	if (getpeername(connection->fd, &addr, &len)==-1) {

	    *error=errno;
	    logoutput("get_ssh_hostname: error %i getting socket peer (%s)", *error, strerror(*error));
	    return NULL;

	}

    }

    memset(tmp, '\0', NI_MAXHOST);
    result=getnameinfo(&addr, len, tmp, NI_MAXHOST, NULL, 0, NI_NAMEREQD);

    if (result==0) {
	char *hostname=NULL;

	hostname=strdup(tmp);
	if (hostname==NULL) *error=ENOMEM;
	return hostname;

    }

    if (result==EAI_MEMORY) {

	result=0;
	*error=ENOMEM;

    } else if (result==EAI_NONAME) {

	result=0;
	*error=ENOENT;

    } else if (result==EAI_SYSTEM) {

	result=0;
	*error=errno;

    } else if (result==EAI_OVERFLOW) {

	result=0;
	*error=ENAMETOOLONG;

    } else {

	result=0;
	*error=EIO;

    }

    return NULL;

}

/* check the server hostkey against the personal known_hosts file
    TODO:
    - when hostkey is a certificate look for a cert authority for this host (this host is part of the domain)
	- verify the signature using the ca's public key
	- for
	    - ssh-rsa-cert-v01: check the values e and n of the ca pubkey
	    - ssh-dss-cert-v01: check the values p, q, g, y of the ca pubkey
	    - ssh-sha2-nist*-cert-v01: check the curve identifier and "q" of the ca pubkey
	    - ssh-ed25519-cert-v01: check the pk which is the encoded ca's pubkey
*/

int check_serverkey(struct ssh_session_s *session, struct ssh_key_s *hostkey)
{
    void *ptr=NULL;
    unsigned int error=0;
    char *remotehostname=NULL;
    char *remoteipv4=NULL;
    int result=-1;

    remotehostname=get_ssh_hostname(session, 1, &error);

    if (remotehostname==NULL) {

	logoutput("check_serverkey: error %i getting remote hostname (%s)", error, strerror(error));
	goto out;

    } else {

	logoutput("check_serverkey: remote hostname %s", remotehostname);

    }

    remoteipv4=get_ssh_ipv4(session, 1, &error);

    if (remoteipv4==NULL) {

	logoutput("check_serverkey: error %i getting remote ipv4 (%s)", error, strerror(error));
	goto out;

    } else {

	logoutput("check_serverkey: remote ipv4 %s", remoteipv4);

    }

    ptr=init_known_hosts(&session->identity.pwd, _KNOWN_HOST_FILTER_KEYS, &error);
    if (ptr==NULL) goto out;

    while (get_next_known_host(ptr, &error)==0) {
	char *algo=NULL;

	/* compare host (remote hostname and remote ipv4) */

	if (compare_host_known_host(ptr, remotehostname)==-1) {

	    if (compare_host_known_host(ptr, remoteipv4)==-1) continue;

	}

	/* compare method (ssh-rsa, ssh-dss, ...)*/

	algo=get_algo_known_host(ptr);
	logoutput("check_serverkey: check algo %s", algo);
	if (get_pubkey_type(algo, strlen(algo))!=hostkey->type) continue;

	/* compare the key material */
	if (match_key_known_host(ptr, hostkey->data.ptr, hostkey->data.len)==0) {

	    result=0;
	    break;

	}

    }

    out:

    if (ptr) {

	finish_known_hosts(ptr);
	ptr=NULL;

    }

    if (remotehostname) {

	free(remotehostname);
	remotehostname=NULL;

    }

    if (remoteipv4) {

	free(remoteipv4);
	remoteipv4=NULL;

    }

    return result;

}
