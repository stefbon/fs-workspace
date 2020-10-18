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

struct ssh_connection_s *get_next_ssh_connection(struct ssh_connections_s *connections, struct ssh_connection_s *connection, const char *how)
{
    struct list_element_s *next=NULL;

    if (strcmp(how, "remove")==0) {

	next=get_list_head(&connections->header, SIMPLE_LIST_FLAG_REMOVE);

    } else {

	next=(connection) ? get_next_element(&connection->list) : get_list_head(&connections->header, 0);

    }

    return (next) ? (struct ssh_connection_s *)(((char *) next) - offsetof(struct ssh_connection_s, list)) : NULL;
}

signed char compare_ssh_connection(struct ssh_connection_s *connection, char *address, unsigned int port)
{
    return (signed char) compare_network_address(&connection->connection, address, port);
}

unsigned int get_status_ssh_connection(struct ssh_connection_s *connection)
{
    int error=0;
    unsigned int fd=connection->connection.io.socket.xdata.fd;

    if (fd>0) {
	socklen_t len=sizeof(int);
	struct socket_ops_s *sops=connection->connection.io.socket.sops;

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

void get_ssh_connection_expire_init(struct ssh_connection_s *c, struct timespec *expire)
{
    struct fs_connection_s *connection=&c->connection;

    get_current_time(expire);
    expire->tv_sec+=c->connection.expire;
}

void get_ssh_connection_expire_session(struct ssh_connection_s *c, struct timespec *expire)
{
    struct fs_connection_s *connection=&c->connection;

    get_current_time(expire);
    expire->tv_sec+=c->connection.expire; /* make this configurable */
}

void signal_ssh_connections(struct ssh_session_s *session)
{
    struct ssh_connections_s *c=&session->connections;

    /* signal any waiting thread for a payload (this is done via signal) */

    pthread_mutex_lock(c->mutex);
    pthread_cond_broadcast(c->cond);
    pthread_mutex_unlock(c->mutex);

}

static void common_refcount_ssh_connection(struct ssh_connection_s *connection, signed char step)
{
    struct ssh_connections_s *connections=get_ssh_connection_connections(connection);

    logoutput("common_refcount_ssh_connection: step %i con %s mut %s ", step, (connections) ? "defined" : "null", (connections && connections->mutex) ? "defined" : "null");

    /* signal any waiting thread for a payload (this is done via signal) */

    pthread_mutex_lock(connections->mutex);
    connection->refcount+=step;
    pthread_mutex_unlock(connections->mutex);
}

void increase_refcount_ssh_connection(struct ssh_connection_s *connection)
{
    common_refcount_ssh_connection(connection, 1);
}

void decrease_refcount_ssh_connection(struct ssh_connection_s *connection)
{
    common_refcount_ssh_connection(connection, -1);
}

struct ssh_session_s *get_ssh_connection_session(struct ssh_connection_s *connection)
{
    struct list_header_s *h=connection->list.h;

    if (h) {
	struct ssh_connections_s *connections=(struct ssh_connections_s *)(((char *) h) - offsetof(struct ssh_connections_s, header));

	return (struct ssh_session_s *)(((char *) connections) - offsetof(struct ssh_session_s, connections));

    }

    return NULL;
}

struct ssh_connections_s *get_ssh_connection_connections(struct ssh_connection_s *connection)
{
    struct list_header_s *h=connection->list.h;
    return ((h) ? (struct ssh_connections_s *)(((char *) h) - offsetof(struct ssh_connections_s, header)) : NULL);
}
