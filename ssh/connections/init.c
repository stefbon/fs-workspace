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
#include "ssh-send.h"
#include "ssh-receive.h"

int init_ssh_connection(struct ssh_session_s *session, struct ssh_connection_s *connection, unsigned char type)
{
    unsigned int error=0;

    memset(connection, 0, sizeof(struct ssh_connection_s));

    switch (type) {

    case FS_CONNECTION_TYPE_TCP4:
    case FS_CONNECTION_TYPE_TCP6:
    case FS_CONNECTION_TYPE_UDP4:
    case FS_CONNECTION_TYPE_UDP6:

	init_connection(&connection->connection, type, FS_CONNECTION_ROLE_CLIENT);
	break;

    default:

	return -1;

    }

    connection->flags=0;
    connection->refcount=0;
    init_list_element(&connection->list, &session->connections.header);
    connection->connection.expire=session->config.connection_expire;

    if (init_ssh_connection_send(connection)==-1) return -1;
    if (init_ssh_connection_receive(connection, &error)==-1) return -1;
    init_ssh_connection_setup(connection, "init", 0);
    connection->setup.mutex=session->connections.mutex;
    connection->setup.cond=session->connections.cond;

    return 0;

}

struct ssh_connection_s *new_ssh_connection(struct ssh_session_s *session, unsigned char type)
{
    struct ssh_connection_s *connection=malloc(sizeof(struct ssh_connection_s));

    if (connection) {

	if (init_ssh_connection(session, connection, type)==0) return connection;
	free_ssh_connection(&connection);

    }

    return connection;
}

void free_ssh_connection(struct ssh_connection_s **p_connection)
{
    struct ssh_connection_s *connection=*p_connection;

    free_ssh_connection_send(connection);
    free_ssh_connection_receive(connection);
    init_ssh_connection_setup(connection, "free", 0);
    free(connection);
    *p_connection=NULL;

}

int init_ssh_connections(struct ssh_session_s *session, pthread_mutex_t *mutex, pthread_cond_t *cond)
{
    struct ssh_connections_s *connections=&session->connections;
    struct ssh_connection_s *connection=NULL;

    /* one central signal (=mutex and cond) for all connections:
	- status of setup (init, keyexchange, transport, connected, disconnect...
	- arriving of messages
    */

    if (mutex==NULL || cond==NULL) {

	mutex=malloc(sizeof(pthread_mutex_t));
	cond=malloc(sizeof(pthread_cond_t));

	if (mutex && cond) {

	    pthread_mutex_init(mutex, NULL);
	    pthread_cond_init(cond, NULL);
	    connections->flags |= SSH_CONNECTIONS_FLAG_SIGNAL_ALLOCATED;

	} else {

	    if (mutex) free(mutex);
	    if (cond) free(cond);
	    goto error;

	}

    }

    connections->mutex=mutex;
    connections->cond=cond;
    connections->main=NULL;
    init_list_header(&connections->header, SIMPLE_LIST_TYPE_EMPTY, NULL);

    /* big todo: for now start with a tcp ipv4 connection */

    connection=new_ssh_connection(session, FS_CONNECTION_TYPE_TCP4);

    if (connection) {

	/* this is the main connection, all others created later are additional
	    like data transport over udp */

	add_list_element_first(&connections->header, &connection->list);
	connection->flags |= SSH_CONNECTION_FLAG_MAIN;
	connection->unique=connections->unique;
	connections->main=connection;
	connections->unique++;
	return 0;

    }

    error:

    free_ssh_connections(session);
    return -1;

}

void free_ssh_connections(struct ssh_session_s *session)
{
    struct ssh_connections_s *connections=&session->connections;
    struct ssh_connection_s *connection=NULL, *next=NULL;

    connection=get_next_ssh_connection(connections, NULL, "remove");

    while (connection) {

	remove_ssh_connection_eventloop(connection);
	disconnect_ssh_connection(connection);
	free_ssh_connection(&connection);
	connection=get_next_ssh_connection(connections, NULL, "remove");

    }

    if (connections->flags & SSH_CONNECTIONS_FLAG_SIGNAL_ALLOCATED) {

	pthread_mutex_destroy(connections->mutex);
	pthread_cond_destroy(connections->cond);
	free(connections->mutex);
	free(connections->cond);
	connections->flags -= SSH_CONNECTIONS_FLAG_SIGNAL_ALLOCATED;

    }

    connections->mutex=NULL;
    connections->cond=NULL;
    connections->main=NULL;

}
