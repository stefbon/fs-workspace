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

