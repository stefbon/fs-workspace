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

#include "common-utils/logging.h"
#include "main.h"
#include "common-utils/utils.h"
#include "common-utils/network-utils.h"
#include "common-utils/beventloop.h"
#include "common-utils/beventloop-xdata.h"
#include "common-utils/workspace-interface.h"
#include "common-utils/workerthreads.h"

#include "ssh-common.h"
#include "ssh-connections.h"
#include "ssh-utils.h"

#define _SSH_BEVENTLOOP_NAME			"SSH"

int create_ssh_networksocket(struct ssh_connection_s *connection, char *address, unsigned int port)
{
    struct fs_connection_s *c=&connection->connection;
    struct ssh_session_s *session=get_ssh_connection_session(connection);
    struct socket_ops_s *sops=c->io.socket.sops;
    struct sockaddr *addr=NULL;
    int len=0;
    int fd=-1;
    int af=0;

    if (port==0) port=session->config.port;

    if (c->type==FS_CONNECTION_TYPE_TCP4 || c->type==FS_CONNECTION_TYPE_UDP4) {

	af=AF_INET;

    } else if (c->type==FS_CONNECTION_TYPE_TCP6 || c->type==FS_CONNECTION_TYPE_UDP6) {

	af=AF_INET6;

    } else {

	goto out;

    }

    if (c->type==FS_CONNECTION_TYPE_TCP4 || c->type==FS_CONNECTION_TYPE_TCP6) {

	fd = (*sops->socket)(af, SOCK_STREAM | SOCK_NONBLOCK, IPPROTO_TCP);

    } else {

	fd = (*sops->socket)(af, SOCK_DGRAM | SOCK_NONBLOCK, IPPROTO_UDP);

    }

    if (fd==-1) {

	logoutput("create_ssh_networksocket: error %i creating socket (%s)", errno, strerror(errno));
	goto out;

    }

    if (af==AF_INET) {
	struct sockaddr_in *sin=&c->io.socket.sockaddr.inet;

	len=sizeof(struct sockaddr_in);
	memset(sin, 0, len);
	sin->sin_family = af;
	sin->sin_port = htons(port);
	inet_pton(af, address, &sin->sin_addr);
	addr=(struct sockaddr *)sin;

    } else {
	struct sockaddr_in6 *sin6=&c->io.socket.sockaddr.inet6;

	len=sizeof(struct sockaddr_in6);
	memset(sin6, 0, len);
	sin6->sin6_family = af;
	sin6->sin6_port = htons(port);
	inet_pton(af, address, &sin6->sin6_addr);
	addr=(struct sockaddr *)sin6;

    }

    if ((* sops->bind)(fd, addr, &len, 0)==-1) {

	logoutput("create_ssh_networksocket: error %i binding socket %i to address %s:%i (%s)", errno, fd, address, port, strerror(errno));
	(* sops->close)(fd);
	fd=-1;
        goto out;

    }

    /* listen */

    if ((* sops->listen)(fd, LISTEN_BACKLOG)==-1 ) {

	logoutput("create_ssh_networksocket: error %i listen on socket %i (%s)", errno, fd, strerror(errno));
	(* sops->close)(fd);
	fd=-1;

    } else {

    	logoutput("create_ssh_networksocket: fd %i", fd);

    }

    out:
    return fd;

}

int connect_ssh_connection(struct ssh_connection_s *connection, char *address, unsigned int port)
{
    struct fs_connection_s *c=&connection->connection;
    struct ssh_session_s *session=get_ssh_connection_session(connection);
    struct socket_ops_s *sops=c->io.socket.sops;
    struct sockaddr *addr=NULL;
    int len=0;
    int fd=-1;
    int af=0;

    if (port==0) port=session->config.port;

    if (c->type==FS_CONNECTION_TYPE_TCP4 || c->type==FS_CONNECTION_TYPE_UDP4) {

	af=AF_INET;

    } else if (c->type==FS_CONNECTION_TYPE_TCP6 || c->type==FS_CONNECTION_TYPE_UDP6) {

	af=AF_INET6;

    } else {

	goto error;

    }

    c->status|=FS_CONNECTION_FLAG_CONNECTING;

    if (c->type==FS_CONNECTION_TYPE_TCP4 || c->type==FS_CONNECTION_TYPE_TCP6) {

	fd=(* sops->socket)(af, SOCK_STREAM, IPPROTO_TCP);

    } else {

	fd=(* sops->socket)(af, SOCK_DGRAM, IPPROTO_UDP);

    }

    if (fd<=0) goto error;

    if (c->type==FS_CONNECTION_TYPE_TCP4 || c->type==FS_CONNECTION_TYPE_UDP4) {
	struct sockaddr_in *sin=&c->io.socket.sockaddr.inet;

	len=sizeof(struct sockaddr_in);
	memset(sin, 0, len);
	sin->sin_family = af;
	sin->sin_port = htons(port);
	inet_pton(af, address, &sin->sin_addr);
	addr=(struct sockaddr *)sin;

    } else {
	struct sockaddr_in6 *sin6=&c->io.socket.sockaddr.inet6;

	len=sizeof(struct sockaddr_in6);
	memset(sin6, 0, len);
	sin6->sin6_family = af;
	sin6->sin6_port = htons(port);
	inet_pton(af, address, &sin6->sin6_addr);
	addr=(struct sockaddr *)sin6;

    }

    if ((* sops->connect)(fd, addr, &len)==0) {
	int flags=0;

	logoutput("connect_ssh_connection: connected to %s:%i with fd %i", address, port, fd);
	c->status|=FS_CONNECTION_FLAG_CONNECTED;
	c->status-=FS_CONNECTION_FLAG_CONNECTING;
	flags=fcntl(fd, F_GETFD);
	flags|=O_NONBLOCK;
	fcntl(fd, F_SETFD, flags);

    } else {

	c->status-=FS_CONNECTION_FLAG_CONNECTING;
	c->status|=FS_CONNECTION_FLAG_DISCONNECTING;
	logoutput("connect_ssh_connection: error (%i:%s) connecting to %s:%i", errno, strerror(errno), address, port);
	c->error=errno;
	(* sops->close)(fd);
	c->status-=FS_CONNECTION_FLAG_DISCONNECTING;
	c->status|=FS_CONNECTION_FLAG_DISCONNECTED;
	goto error;

    }

    return fd;

    error:

    return -1;

}

void disconnect_ssh_connection(struct ssh_connection_s *connection)
{
    struct fs_connection_s *c=&connection->connection;

    if (c->status & FS_CONNECTION_FLAG_CONNECTED) {

    	if (c->io.socket.xdata.fd>0) {

	    logoutput("disconnect_ssh_connection: close fd %i", c->io.socket.xdata.fd);
	    (* c->io.socket.sops->close)(c->io.socket.xdata.fd);
    	    c->io.socket.xdata.fd=-1;

	}

	c->status-=FS_CONNECTION_FLAG_CONNECTED;
	c->status|=FS_CONNECTION_FLAG_DISCONNECTED;

    }
}

int add_ssh_connection_eventloop(struct ssh_connection_s *connection, unsigned int fd, int (* read_incoming_data)(int fd, void *ptr, uint32_t events), unsigned int *error)
{
    struct ssh_session_s *session=get_ssh_connection_session(connection);
    struct fs_connection_s *c=&connection->connection;
    struct context_interface_s *interface=session->interface;

    if ((* interface->add_context_eventloop)(interface, c, fd, read_incoming_data, (void *) connection, (char *) _SSH_BEVENTLOOP_NAME, error)==0) {

	logoutput("add_ssh_session_eventloop: fd %i added to eventloop", fd);
	return 0;

    }

    logoutput("add_ssh_session_eventloop: failed to add fd %i to eventloop, error %i (%s)", fd, *error, strerror(*error));
    return -1;
}

void remove_ssh_connection_eventloop(struct ssh_connection_s *connection)
{
    struct ssh_session_s *session=get_ssh_connection_session(connection);
    struct context_interface_s *interface=session->interface;
    (* interface->remove_context_eventloop)(&connection->connection);
}
