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
#include "network-utils.h"
#include "beventloop.h"
#include "beventloop-xdata.h"
#include "workspace-interface.h"
#include "workerthreads.h"

#include "ssh-common.h"
#include "ssh-connection.h"
#include "ssh-utils.h"

#define _SSH_BEVENTLOOP_NAME			"SSH"

void init_ssh_connection(struct fs_connection_s *connection)
{

    /* for now only tcp/ipv4 is supported */

    init_connection(connection, FS_CONNECTION_TYPE_TCP4, FS_CONNECTION_ROLE_CLIENT);
    connection->expire=5;
}

int connect_ssh_connection(struct fs_connection_s *connection, char *address, unsigned int port)
{
    struct socket_ops_s *sops=connection->io.socket.sops;
    struct sockaddr_in *sin=NULL;
    int len=0;
    int fd=-1;

    /* only tcp/ipv4 for now */

    if (check_family_ip_address(address, "ipv4")==0) return -1;
    connection->status|=FS_CONNECTION_FLAG_CONNECTING;

    fd=(* sops->socket)(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (fd<=0) goto error;

    sin=&connection->io.socket.sockaddr.inet;
    len=sizeof(struct sockaddr_in);
    memset(sin, 0, sizeof(struct sockaddr_in));
    sin->sin_family = AF_INET;
    sin->sin_port = htons(port);
    inet_pton(AF_INET, address, &sin->sin_addr);

    if ((* sops->connect)(fd, (struct sockaddr *) sin, &len)==0) {
	int flags=0;

	logoutput("connect_ssh_connection: connected to %s:%i with fd %i", address, port, fd);
	connection->status|=FS_CONNECTION_FLAG_CONNECTED;
	flags=fcntl(fd, F_GETFD);
	flags|=O_NONBLOCK;
	fcntl(fd, F_SETFD, flags);

    } else {

	connection->status|=FS_CONNECTION_FLAG_DISCONNECTING;
	logoutput("connect_ssh_connection: error (%i:%s) connected to %s:%i", errno, strerror(errno), address, port);
	connection->error=errno;
	(* sops->close)(fd);
	connection->status|=FS_CONNECTION_FLAG_DISCONNECTED;
	goto error;

    }

    return fd;

    error:

    return -1;

}

signed char compare_ssh_connection(struct fs_connection_s *connection, char *address, unsigned int port)
{
    return (signed char) compare_network_address(connection, address, port);
}

void disconnect_ssh_connection(struct fs_connection_s *connection)
{
    if (connection->status & FS_CONNECTION_FLAG_CONNECTED) {

    	if (connection->io.socket.xdata.fd>0) {

	    logoutput("disconnect_ssh_connection: close fd %i", connection->io.socket.xdata.fd);
	    (* connection->io.socket.sops->close)(connection->io.socket.xdata.fd);
    	    connection->io.socket.xdata.fd=-1;

	}

	connection->status-=FS_CONNECTION_FLAG_CONNECTED;
	connection->status|=FS_CONNECTION_FLAG_DISCONNECTED;

    }
}

int add_ssh_session_eventloop(struct ssh_session_s *session, unsigned int fd, int (* read_incoming_data)(int fd, void *ptr, uint32_t events), unsigned int *error)
{
    struct context_interface_s *interface=session->interface;

    if ((* interface->add_context_eventloop)(interface, &session->connection, fd, read_incoming_data, (void *) session, (char *) _SSH_BEVENTLOOP_NAME, error)==0) {

	logoutput("add_ssh_session_eventloop: fd %i added to eventloop", fd);
	return 0;

    }

    logoutput("add_ssh_session_eventloop: failed to add fd %i to eventloop, error %i (%s)", fd, *error, strerror(*error));
    return -1;
}

void remove_ssh_session_eventloop(struct ssh_session_s *session)
{
    struct context_interface_s *interface=session->interface;
    (* interface->remove_context_eventloop)(interface);
}

unsigned int get_status_ssh_session(struct ssh_session_s *session)
{
    int error=0;
    unsigned int fd=session->connection.io.socket.xdata.fd;

    if (fd>0) {
	socklen_t len=sizeof(int);
	struct socket_ops_s *sops=session->connection.io.socket.sops;

	if ((* sops->getsockopt)(fd, SOL_SOCKET, SO_ERROR, (void *) &error, &len)==0) {

	    logoutput("get_status_ssh_connection: got error %i (%s)", error, strerror(error));

	} else {

	    error=errno;
	    logoutput("get_status_ssh_connection: error %i (%s)", errno, strerror(errno));

	}

    } else {

	error=ENOTCONN;

    }

    return abs(error);

}

