/*
  2010, 2011, 2012, 2103, 2014, 2015, 2016 Stef Bon <stefbon@gmail.com>

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

#include "main.h"
#include "logging.h"

#include "common-utils/utils.h"
#include "workerthreads.h"

#include "workspace-interface.h"
#include "ssh-utils.h"

#include "ssh-common-protocol.h"
#include "ssh-common.h"

#include "ssh-connections.h"
#include "ssh-hostinfo.h"
#include "ssh-keyexchange.h"
#include "ssh-receive.h"
#include "ssh-send.h"
#include "ssh-data.h"
#include "ssh-channel.h"
#include "ssh-userauth.h"
#include "extensions/extension.h"

#define UINT32_T_MAX		0xFFFFFFFF

static pthread_mutex_t sessions_mutex=PTHREAD_MUTEX_INITIALIZER;
static unsigned char initialization=0;
static uint64_t unique_ctr=0;
static struct list_header_s sessions=INIT_LIST_HEADER;

static void add_ssh_session_sessions(struct ssh_session_s *session)
{
    pthread_mutex_lock(&sessions_mutex);
    add_list_element_last(&sessions, &session->list);
    pthread_mutex_unlock(&sessions_mutex);
}

static void remove_ssh_session_sessions(struct ssh_session_s *session)
{
    pthread_mutex_lock(&sessions_mutex);
    remove_list_element(&session->list);
    pthread_mutex_unlock(&sessions_mutex);
}

static void zero_timespec(struct timespec *t)
{
    t->tv_sec=0;
    t->tv_nsec=0;
}

static void init_session_config(struct ssh_session_s *session)
{
    struct ssh_config_s *config=&session->config;

    memset(config, 0, sizeof(struct ssh_config_s));

    config->unique=0;
    config->flags=SSH_CONFIG_FLAG_CORRECT_CLOCKSKEW;
    config->max_packet_size=SSH_CONFIG_MAX_PACKET_SIZE;
    config->max_receive_size=SSH_CONFIG_RECEIVE_BUFFER_SIZE;
    config->port=22;
    config->connection_expire=SSH_CONFIG_CONNECTION_EXPIRE;
    config->max_receiving_threads=SSH_CONFIG_MAX_RECEIVING_THREADS;
    config->max_sending_threads=SSH_CONFIG_MAX_SENDING_THREADS;

}

static void free_ssh_identity(struct ssh_session_s *session)
{
    struct ssh_identity_s *identity=&session->identity;

    if (identity->buffer) {

	free(identity->buffer);
	identity->buffer=NULL;

    }

    memset(identity, 0, sizeof(struct ssh_identity_s));
}

static int init_ssh_identity(struct ssh_session_s *session, uid_t uid, unsigned int *error)
{
    struct ssh_identity_s *identity=&session->identity;
    struct passwd *result=NULL;

    memset(identity, 0, sizeof(struct ssh_identity_s));
    identity->buffer=NULL;
    identity->size=128;
    init_ssh_string(&identity->remote_user);
    identity->identity_file=NULL;

    getpw:

    memset(&identity->pwd, 0, sizeof(struct passwd));
    result=NULL;

    identity->buffer=realloc(identity->buffer, identity->size);
    if(identity->buffer==NULL) {

	*error=ENOMEM;
	goto error;

    }

    if (getpwuid_r(uid, &identity->pwd, identity->buffer, identity->size, &result)==-1) {

	if (errno==ERANGE) {

	    identity->size+=128;
	    goto getpw; /* size buffer too small, increase and try again */

	}

	*error=errno; /* any other error is fatal */
	goto error;

    }

    logoutput("init_ssh_identity: found user %s (uid=%i, info %s) home %s", result->pw_name, result->pw_uid, result->pw_gecos, result->pw_dir);

    return 0;

    error:

    free_ssh_identity(session);
    return -1;

}

int init_ssh_backend(unsigned int *error)
{
    int result=0;

    pthread_mutex_lock(&sessions_mutex);

    if (initialization==0) {

	init_list_header(&sessions, SIMPLE_LIST_TYPE_EMPTY, NULL);
	init_ssh_send_once();
	init_ssh_receive_once();
	init_ssh_utils();
	init_keyex_once();
	result=init_ssh_backend_library(error);
	initialization=1;

    }

    pthread_mutex_unlock(&sessions_mutex);

    return result;

}

static struct ssh_session_s *_create_ssh_session(uid_t uid, struct context_interface_s *interface, pthread_mutex_t *mutex, pthread_cond_t *cond, unsigned int *error)
{
    struct ssh_session_s *session=NULL;

    session=malloc(sizeof(struct ssh_session_s));

    if (session) {

	memset(session, 0, sizeof(struct ssh_session_s));

	session->interface=interface;
	init_list_element(&session->list, &sessions);
	init_session_config(session);
	init_channels_table(session, CHANNELS_TABLE_SIZE);
	init_session_data(session);
	init_hostinfo(session);
	init_ssh_extensions(session);
	init_ssh_pubkey(session);

	if (init_ssh_connections(session, mutex, cond)==-1) {

	    logoutput("_create_ssh_session: error (%i:%s) initializing connections subsystem", *error, strerror(*error));
	    goto error;

	}

	if (init_ssh_identity(session, uid, error)==-1) {

	    logoutput("_create_ssh_session: error (%i:%s) getting user identity for uid %i", *error, strerror(*error), (unsigned int) uid);
	    goto error;

	}

	return session;

    }

    error:

    if (session) {

	free_hostinfo(session);
	free_session_data(session);
	free_channels_table(session);
	free_ssh_identity(session);
	free_ssh_connections(session);
	free(session);
	session=NULL;

    }

    return NULL;

}

static int _setup_ssh_session(struct ssh_session_s *session, struct context_interface_s *interface, int fd)
{
    unsigned int error=EIO;
    int result=-1;
    struct ssh_connection_s *connection=session->connections.main;

    logoutput("_setup_ssh_session: A");

    change_ssh_connection_setup(connection, "setup", 0, SSH_SETUP_FLAG_SETUPTHREAD, 0, NULL, NULL);

    /* setup keyexchange and payload queue here already to make sure there is a queue available
	some servers send a kexinit message just with or just behind the greeter
	it's important there is a payload queue present */

    logoutput("_setup_ssh_session: B");

    if (add_ssh_connection_eventloop(connection, fd, read_ssh_connection_signal, &error)==-1) {

	logoutput("_setup_ssh_session: error %i adding fd %i to eventloop (%s)", error, fd, strerror(error));
	goto out_setup;

    }

    logoutput("_setup_ssh_session: added fd %i to eventloop", fd);

    /* setup greeter */

    init_ssh_connection_setup(connection, "transport", SSH_TRANSPORT_TYPE_GREETER);

    /* send a greeter and wait for greeter from server */

    if (send_ssh_greeter(connection)==-1) {

	logoutput("_setup_ssh_session: error sending greeter");
	goto out_setup;

    }

    logoutput("_setup_ssh_session: greeter send");

    /* wait for the greeter from the server */

    if (wait_ssh_connection_setup_change(connection, "transport", SSH_TRANSPORT_TYPE_GREETER, SSH_GREETER_FLAG_S2C | SSH_GREETER_FLAG_C2S, NULL, NULL)==-1) {

	logoutput("_setup_ssh_session: failed receiving/reading greeter");
	goto out_setup;

    }

    /* start key exchange */

    logoutput("_setup_ssh_session: greeter finished, start key exchange");
    init_ssh_connection_setup(connection, "transport", SSH_TRANSPORT_TYPE_KEX);

    if (key_exchange(connection)==-1) {

	logoutput("_setup_ssh_session: key exchange failed");
	goto out_kex;

    }

    if (check_ssh_connection_setup(connection, "transport", SSH_TRANSPORT_TYPE_KEX, 0)<1) {

	logoutput("_setup_ssh_session: error: keyexchange failed");
	goto out_kex;

    }

    /* finish key exchange
	this means by definition that transport is setup */

    finish_ssh_connection_setup(connection, "transport", SSH_TRANSPORT_TYPE_KEX);
    finish_ssh_connection_setup(connection, "transport", 0);
    logoutput("_setup_ssh_session: key exchange finished");

    /* The Secure Shell (SSH) Transport Layer Protocol completed (RFC4253)
	start the userauth phase */

    init_ssh_connection_setup(connection, "service", SSH_SERVICE_TYPE_AUTH);

    /* service userauth for service connection (=channels) */

    if (start_ssh_auth(connection)==-1) {

	logoutput("_setup_ssh_session: authentification failed");
	goto out_auth;

    }

    if (check_ssh_connection_setup(connection, "service", SSH_SERVICE_TYPE_AUTH, 0)<1) {

	logoutput("_setup_ssh_session: error: authentification failed");
	goto out_auth;

    }

    result=0; /* only when here success*/

    out_auth:

    finish_ssh_connection_setup(connection, "service", SSH_SERVICE_TYPE_AUTH);

    out_kex:

    /* after auth. the connection is ready to use */
    finish_ssh_connection_setup(connection, "service", 0);

    out_setup:

    finish_ssh_connection_setup(connection, "setup", 0);
    logoutput("_setup_ssh_session: authentication finished");

    if (result==-1) {

	if (error==0) error=EIO;
	logoutput("_setup_ssh_session: exit with error %i (%s)", error, strerror(error));

    }

    return result;

}

void _free_ssh_session(struct ssh_session_s *session)
{

    free_ssh_connections(session);
    free_channels_table(session);
    free_hostinfo(session);
    free_ssh_identity(session);
    free_session_data(session);
    free_ssh_pubkey(session);
    free(session);
    session=NULL;

}

static void _close_ssh_session_connections(struct ssh_session_s *session, const char *how)
{
    struct ssh_connections_s *connections=&session->connections;
    struct ssh_connection_s *connection=NULL;

    pthread_mutex_lock(connections->mutex);

    if (connections->flags & SSH_CONNECTIONS_FLAG_DISCONNECT) {

	pthread_mutex_unlock(connections->mutex);
	return;

    }

    connections->flags |= SSH_CONNECTIONS_FLAG_DISCONNECTING;
    pthread_mutex_unlock(connections->mutex);

    connection=get_next_ssh_connection(connections, connection, how);

    while (connection) {

	change_ssh_connection_setup(connection, "setup", 0, SSH_SETUP_FLAG_DISCONNECTING, 0, NULL, 0);

	if (connection==connections->main && (connection->flags & SSH_CONNECTION_FLAG_DISCONNECT_SEND)==0) {

	    send_disconnect_message(connection, SSH_DISCONNECT_BY_APPLICATION);
	    connection->flags |= SSH_CONNECTION_FLAG_DISCONNECT_SEND;

	}

	remove_ssh_connection_eventloop(connection);
	disconnect_ssh_connection(connection);
	change_ssh_connection_setup(connection, "setup", 0, SSH_SETUP_FLAG_DISCONNECTED, 0, NULL, 0);

	if (strcmp(how, "remove")==0) free_ssh_connection(&connection);

	connection=get_next_ssh_connection(connections, connection, how);

    }

    pthread_mutex_lock(connections->mutex);
    connections->flags -= SSH_CONNECTIONS_FLAG_DISCONNECTING;
    connections->flags |= SSH_CONNECTIONS_FLAG_DISCONNECTED;
    pthread_cond_broadcast(connections->cond);
    pthread_mutex_unlock(connections->mutex);
}

static void _close_ssh_session_channels(struct ssh_session_s *session, const char *how)
{
    struct channel_table_s *table=&session->channel_table;
    struct simple_lock_s wlock;

    if (channeltable_writelock(table, &wlock)==0) {
	struct ssh_channel_s *channel=get_next_channel(session, NULL);

	if (channel) {

	    switch_channel_send_data(channel, "close");
	    switch_channel_receive_data(channel, "down", NULL);

	    if (strcmp(how, "remove")==0) {

		table_remove_channel(channel);
		close_channel(channel, CHANNEL_FLAG_CLIENT_CLOSE);
		free_ssh_channel(channel);
		channel=NULL;

	    }

	    channel=get_next_channel(session, channel);

	}

	channeltable_unlock(table, &wlock);

    }

}

void signal_ssh_interface(struct context_interface_s *interface, const char *what)
{
    struct ssh_session_s *session=(struct ssh_session_s *) interface->ptr;

    logoutput("signal_ssh_interface: %s", what);

    if (session==NULL) return;

    if (strcmp(what, "disconnecting")==0) {

    } else if (strcmp(what, "close")==0) {

	_close_ssh_session_channels(session, "close");
	_close_ssh_session_connections(session, "close");

    } else if (strcmp(what, "free")==0) {

	_close_ssh_session_channels(session, "remove");
	_close_ssh_session_connections(session, "remove");
	_free_ssh_session(session);
	interface->ptr=NULL;

    }

}

static struct ssh_session_s *get_full_session(uid_t uid, struct context_interface_s *interface, char *address, unsigned int port)
{
    struct ssh_session_s *session=NULL;
    struct ssh_connection_s *connection=NULL;
    unsigned int error=0;
    pthread_mutex_t *mutex=NULL;
    pthread_cond_t *cond=NULL;
    struct context_option_s option;
    int fd=-1;

    logoutput("get_full_session: %s:%i", address, port);

    if (init_ssh_backend(&error)==-1) {

	logoutput("get_full_session: error (%i:%s) init ssh backend", error, strerror(error));
	return NULL;

    }

    pthread_mutex_lock(&sessions_mutex);

    memset(&option, 0, sizeof(struct context_option_s));

    if ((* interface->get_context_option)(interface, "io:shared-mutex", &option)>0) {

	mutex=(pthread_mutex_t *) option.value.data;

    }

    memset(&option, 0, sizeof(struct context_option_s));

    if ((* interface->get_context_option)(interface, "io:shared-cond", &option)>0) {

	cond=(pthread_cond_t *) option.value.data;

    }

    session=_create_ssh_session(uid, interface, mutex, cond, &error);
    if (! session) goto unlock;
    connection=session->connections.main;
    fd=connect_ssh_connection(connection, address, port);

    if (fd>0) {

	logoutput("get_full_session: connected to %s:%i with fd %i", address, port, fd);

    } else {

	logoutput("get_full_session: unable to connect to %s:%i", address, port);
	_free_ssh_session(session);
	session=NULL;
	goto unlock;

    }

    memset(&option, 0, sizeof(struct context_option_s));

    if ((* interface->get_context_option)(interface, "option:ssh.init_timeout", &option)==_INTERFACE_OPTION_INT) {

	session->config.connection_expire=option.value.number;

    }

    /* setup the session with encryption, hmac, dh, pk etc. */

    if (_setup_ssh_session(session, interface, fd)==0) {

	add_list_element_last(&sessions, &session->list);
	session->config.unique=unique_ctr;
	unique_ctr++;

    } else {

	_close_ssh_session_connections(session, "remove");
	_free_ssh_session(session);
	session=NULL;

    }

    unlock:
    pthread_mutex_unlock(&sessions_mutex);
    return session;

}

unsigned int get_window_size(struct ssh_session_s *session)
{
    /* 2 ^ 32 - 1*/
    return (unsigned int)(UINT32_T_MAX - 1);
}

unsigned int get_max_packet_size(struct ssh_session_s *session)
{
    return session->config.max_packet_size;
}

void set_max_packet_size(struct ssh_session_s *session, unsigned int size)
{
    session->config.max_packet_size=size;
}

int create_ssh_session(uid_t uid, struct context_interface_s *interface, struct context_address_s *address, unsigned int *error)
{
    struct ssh_session_s *session=NULL;
    struct channel_table_s *table=NULL;
    char *target=NULL;
    unsigned int port=0;

    /* 20161118: only IPv4 or hostname for now
	maybe use an uri library here to get the host address and the port out of the address */

    if (!(address->network.type==_INTERFACE_ADDRESS_NETWORK)) {
 
	logoutput("create_ssh_session: error, only support for connection via ipv4 or hostname");
	*error=EINVAL;
	goto error;

    } else if (!(address->service.type==_INTERFACE_SERVICE_PORT)) {

	logoutput("create_ssh_session: error, connections other than via a network port are not supported (service type=%i)", address->service.type);
	*error=EINVAL;
	goto error;

    } else if (!(address->service.target.port.type==_INTERFACE_PORT_TCP)) {

	logoutput("create_ssh_session: error, connections other than via an tcp port are not supported (port type=%i)", address->service.target.port.type);
	*error=EINVAL;
	goto error;

    }

    translate_context_address_network(address, &target, &port, NULL);

    if (port==0) {

	port=session->config.port;
	logoutput("create_ssh_session: connecting to %s:%i (application default)", target, port);

    } else {

	logoutput("create_ssh_session: connecting to %s:%i", target, port);

    }

    /* get ssh session for target and this uid: it may be an existing one */

    session=get_full_session(uid, interface, target, port);
    if (session==NULL) goto error;

    /* add a shell */

    table=&session->channel_table;
    if (! table->shell) add_shell_channel(session);
    interface->ptr=(void *)session;

    return 0;

    error:

    logoutput("create_ssh_session: no session created for %s:%i", target, port);
    return -1;

}

static void analyze_connection_problem(void *ptr)
{
    struct ssh_connection_s *connection=(struct ssh_connection_s *) ptr;
    unsigned int error=0;

    error=get_status_ssh_connection(connection);

    if (error>0) {

	logoutput("analyze_connection_problem: error %i (%s)", error, strerror(error));

	/* TODO: store error somewhere and act upon it */

	/* when error ENOTCONN ea signal the context*/

    }

    change_ssh_connection_setup(connection, "setup", 0, SSH_SETUP_FLAG_ANALYZETHREAD, SSH_SETUP_OPTION_UNDO, NULL, NULL);

}

static int setup_cb_thread_connection_problem(struct ssh_connection_s *connection, void *data)
{
    unsigned int error=0;
    work_workerthread(NULL, 0, analyze_connection_problem, (void *) connection, &error);
    return 0;
}

int start_thread_connection_problem(struct ssh_connection_s *connection)
{
    return change_ssh_connection_setup(connection, "setup", 0, SSH_SETUP_FLAG_ANALYZETHREAD, SSH_SETUP_OPTION_XOR, setup_cb_thread_connection_problem, NULL);
}
