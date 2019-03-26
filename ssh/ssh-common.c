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
#include "ssh-common-protocol.h"
#include "ssh-common.h"
#include "ssh-common-list.h"

#include "ssh-connection.h"
#include "ssh-hostinfo.h"
#include "ssh-keyexchange.h"
#include "ssh-receive.h"
#include "ssh-send.h"
#include "ssh-data.h"
#include "ssh-channel.h"
#include "ssh-utils.h"
#include "ssh-userauth.h"
#include "extensions/extension.h"

#define UINT32_T_MAX		0xFFFFFFFF

static pthread_mutex_t done_mutex=PTHREAD_MUTEX_INITIALIZER;
static unsigned char initdone=0;

static void init_session_status(struct ssh_session_s *session)
{
    struct ssh_status_s *status=&session->status;

    pthread_mutex_init(&status->mutex, NULL);
    pthread_cond_init(&status->cond, NULL);
    status->max_packet_size=32768;
    status->remote_version_major=0;
    status->remote_version_minor=0;

    status->sessionphase.phase=0;
    status->sessionphase.sub=0;
    status->sessionphase.status=0;
    status->sessionphase.error=0;

    status->unique=0;

}

static void free_session_status(struct ssh_session_s *session)
{
    struct ssh_status_s *ssh_status=&session->status;
    pthread_mutex_destroy(&ssh_status->mutex);
    pthread_cond_destroy(&ssh_status->cond);
}

int change_sessionphase(struct ssh_session_s *session, struct sessionphase_s *sessionphase)
{
    struct ssh_status_s *status=&session->status;

    pthread_mutex_lock(&status->mutex);

    if (status->sessionphase.phase==SESSION_PHASE_DISCONNECT || (status->sessionphase.status & SESSION_STATUS_DISCONNECTING)) {

	pthread_mutex_unlock(&status->mutex);
	return -3;

    }

    status->sessionphase.phase=sessionphase->phase;
    status->sessionphase.sub=sessionphase->sub;

    pthread_mutex_unlock(&status->mutex);

    return 0;

}

int compare_sessionphase(struct ssh_session_s *session, struct sessionphase_s *sessionphase)
{
    struct ssh_status_s *status=&session->status;
    int result=-1;

    pthread_mutex_lock(&status->mutex);

    if (status->sessionphase.phase==SESSION_PHASE_DISCONNECT || (status->sessionphase.status & SESSION_STATUS_DISCONNECTING)) {

	pthread_mutex_unlock(&status->mutex);
	return -3;

    }

    if (status->sessionphase.phase==sessionphase->phase && status->sessionphase.sub==sessionphase->sub) result=0;

    pthread_mutex_unlock(&status->mutex);

    return result;

}

int change_status_sessionphase(struct ssh_session_s *session, struct sessionphase_s *sessionphase)
{
    struct ssh_status_s *status=&session->status;
    int result=0;

    pthread_mutex_lock(&status->mutex);

    if (status->sessionphase.phase==SESSION_PHASE_DISCONNECT || (status->sessionphase.status & SESSION_STATUS_DISCONNECTING)) {

	result=-3;

    } else if (sessionphase->phase == status->sessionphase.phase && sessionphase->sub == status->sessionphase.sub) {

	if ((status->sessionphase.status & SESSION_STATUS_GENERIC_FAILED) && (sessionphase->status & SESSION_STATUS_GENERIC_FAILED)==0) result=-1;
	status->sessionphase.status |= sessionphase->status;
	pthread_cond_broadcast(&status->cond);

    } else {

	result=-2;

    }

    pthread_mutex_unlock(&status->mutex);
    return result;

}

void set_sessionphase_failed(struct sessionphase_s *sessionphase)
{
    sessionphase->status |= SESSION_STATUS_GENERIC_FAILED;
}

void set_sessionphase_success(struct sessionphase_s *sessionphase)
{
    sessionphase->status |= SESSION_STATUS_GENERIC_SUCCESS;
}

void copy_sessionphase(struct ssh_session_s *session, struct sessionphase_s *sessionphase)
{
    struct ssh_status_s *status=&session->status;

    pthread_mutex_lock(&status->mutex);

    sessionphase->phase=status->sessionphase.phase;
    sessionphase->sub=status->sessionphase.sub;
    sessionphase->status=status->sessionphase.status;

    pthread_mutex_unlock(&status->mutex);

}

int wait_status_sessionphase(struct ssh_session_s *session, struct sessionphase_s *sessionphase, unsigned int s)
{
    struct ssh_status_s *status=&session->status;
    int result=0;

    pthread_mutex_lock(&status->mutex);

    if (status->sessionphase.phase==SESSION_PHASE_DISCONNECT || (status->sessionphase.status & SESSION_STATUS_DISCONNECTING)) {

	result=-3;
	goto out;

    } else if (sessionphase->phase==status->sessionphase.phase && sessionphase->sub == status->sessionphase.sub && (status->sessionphase.status & s)) {

	result=0;
	goto out;

    } else if (sessionphase->phase != status->sessionphase.phase || sessionphase->sub != status->sessionphase.sub) {

	result=-2;
	goto out;

    } else if (status->sessionphase.status & SESSION_STATUS_GENERIC_FAILED) {

	result=-1;
	goto out;

    }

    while (sessionphase->phase==status->sessionphase.phase && sessionphase->sub == status->sessionphase.sub && (status->sessionphase.status & s)==0) {

	pthread_cond_wait(&status->cond, &status->mutex);

	if (status->sessionphase.phase==SESSION_PHASE_DISCONNECT || (status->sessionphase.status & SESSION_STATUS_DISCONNECTING)) {

	    result=-3;
	    break;

	} else if (sessionphase->phase==status->sessionphase.phase && sessionphase->sub == status->sessionphase.sub && (status->sessionphase.status & s)) {

	    result=0;
	    break;

	} else if (sessionphase->phase != status->sessionphase.phase || sessionphase->sub != status->sessionphase.sub) {

	    result=-2;
	    break;

	} else if (status->sessionphase.status & SESSION_STATUS_GENERIC_FAILED) {

	    result=-1;
	    break;

	}

    }

    out:

    pthread_mutex_unlock(&status->mutex);
    return result;

}

static void free_identity(struct ssh_session_s *session)
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

    free_identity(session);
    return -1;

}

void finish_ssh_backend(void *ptr)
{
    free_group_ssh_sessions();
}

int init_ssh_backend(unsigned int *error)
{
    int result=0;

    pthread_mutex_lock(&done_mutex);

    if (initdone==0) {

	initialize_group_ssh_sessions(error);

	init_send_once();
	init_receive_once();
	init_ssh_utils();

	result=init_ssh_backend_library(error);

	initdone=1;

	/* TODO:
	    add a "free ssh backend" task at the main "end tasks list" */

	add_finish_script(finish_ssh_backend, NULL, "ssh_backend");


    }

    pthread_mutex_unlock(&done_mutex);

    return result;

}

static struct ssh_session_s *_create_ssh_session(uid_t uid, struct context_interface_s *interface, pthread_mutex_t *mutex, pthread_cond_t *cond, unsigned int *error)
{
    struct ssh_session_s *session=NULL;

    session=malloc(sizeof(struct ssh_session_s));

    if (session) {

	memset(session, 0, sizeof(struct ssh_session_s));

	session->interface=interface;

	session->list.next=NULL;
	session->list.prev=NULL;

	init_session_status(session);
	init_channels_table(session, CHANNELS_TABLE_SIZE);
	init_session_data(session);
	init_ssh_connection(&session->connection);
	init_hostinfo(session);
	init_ssh_extensions(session);
	init_ssh_pubkey(session);

	/* start without compression, encryption, hmac and publickey */

	if (init_send(session, error)==-1) {

	    logoutput("_create_ssh_session: error (%i:%s) init send", *error, strerror(*error));
	    goto error;

	}

	if (init_ssh_identity(session, uid, error)==-1) {

	    logoutput("_create_ssh_session: error (%i:%s) init identity", *error, strerror(*error));
	    goto error;

	}

	if (init_receive(session, mutex, cond, error)==-1) {

	    logoutput("_create_ssh_session: error (%i:%s) init receive", *error, strerror(*error));
	    goto error;

	}

	return session;

    }

    error:

    if (session) {

	free_receive(session);
	free_send(session);

	free_hostinfo(session);
	free_session_data(session);

	free_session_status(session);
	free_channels_table(session);
	free_identity(session);

	free(session);
	session=NULL;

    }

    return NULL;

}

static int _setup_ssh_session(struct ssh_session_s *session, struct context_interface_s *interface, int fd)
{
    struct payload_queue_s queue;
    struct sessionphase_s sessionphase;
    int result=-1;

    init_payload_queue(session, &queue);
    session->queue=&queue;

    sessionphase.phase=SESSION_PHASE_SETUP;
    sessionphase.sub=SESSION_SUBPHASE_INIT;
    sessionphase.status=0;
    sessionphase.error=0;

    if (change_sessionphase(session, &sessionphase)==0) {
	unsigned int error=0;

	if (add_ssh_session_eventloop(session, fd, read_incoming_signal_ssh, &error)==-1) {

	    if (error==0) error=EIO;
	    logoutput("_setup_ssh_session: error %i adding fd %i to eventloop (%s)", error, fd, strerror(error));
	    set_sessionphase_failed(&sessionphase);

	} else {

	    logoutput("_setup_ssh_session: added fd %i to eventloop", fd);
	    set_sessionphase_success(&sessionphase);

	}

    }

    /* send a greeter and wait for greeter from server */

    if (sessionphase.sub==SESSION_SUBPHASE_INIT && (sessionphase.status & SESSION_STATUS_GENERIC_SUCCESS) && compare_sessionphase(session, &sessionphase)==0) {
	struct timespec expire;
	int change=0;

	sessionphase.sub=SESSION_SUBPHASE_GREETER;
	sessionphase.status=0;
	change=change_sessionphase(session, &sessionphase);
	if (change<0) goto error;

	if (send_greeter(session)==-1) {

	    logoutput("_setup_ssh_session: error sending greeter");
	    set_sessionphase_failed(&sessionphase);
	    goto error;

	} else {

	    logoutput("_setup_ssh_session: greeter send");
	    sessionphase.status|=SESSION_STATUS_GREETER_C2S;

	}

	/* wait for the greeter from the server */

	if (wait_status_sessionphase(session, &sessionphase, SESSION_STATUS_GREETER_S2C)==0) {

	    logoutput("_setup_ssh_session: greeter received, continue");
	    set_sessionphase_success(&sessionphase);

	} else {

	    logoutput("_setup_ssh_session: failed receiving/reading greeter");
	    set_sessionphase_failed(&sessionphase);
	    goto error;

	}

    } else {

	goto error;

    }

    if (sessionphase.sub==SESSION_SUBPHASE_GREETER && (sessionphase.status & SESSION_STATUS_GENERIC_SUCCESS) && compare_sessionphase(session, &sessionphase)==0) {
	int change=0;

	sessionphase.sub=SESSION_SUBPHASE_KEYEXCHANGE;
	sessionphase.status=0;
	change=change_sessionphase(session, &sessionphase);
	if (change<0) goto error;

	if (key_exchange(session, &queue, &sessionphase)==0) {

	    logoutput("_setup_ssh_session: key exchange success");
	    set_sessionphase_success(&sessionphase);

	} else {

	    logoutput("_setup_ssh_session: key exchange failed");
	    set_sessionphase_failed(&sessionphase);

	}

    }

    if (sessionphase.sub==SESSION_SUBPHASE_KEYEXCHANGE && (sessionphase.status & SESSION_STATUS_GENERIC_SUCCESS) && compare_sessionphase(session, &sessionphase)==0) {
	int change=0;

	sessionphase.sub=SESSION_SUBPHASE_USERAUTH;
	sessionphase.status=0;
	change=change_sessionphase(session, &sessionphase);
	if (change<0) goto error;

	if (start_ssh_userauth(session, &queue)==0) {

	    logoutput("_setup_ssh_session: authentication succes");
	    set_sessionphase_success(&sessionphase);

	} else {

	    logoutput("_setup_ssh_session: authentication failed");
	    set_sessionphase_failed(&sessionphase);

	}

    }

    if (sessionphase.sub==SESSION_SUBPHASE_USERAUTH && (sessionphase.status & SESSION_STATUS_GENERIC_SUCCESS) && compare_sessionphase(session, &sessionphase)==0) {

	pthread_mutex_lock(&session->status.mutex);

	logoutput("_setup_ssh_session: completed");
	result=0;
	session->status.sessionphase.phase=SESSION_PHASE_CONNECTION;
	session->status.sessionphase.sub=0;
	session->status.sessionphase.status=0;

	pthread_mutex_unlock(&session->status.mutex);

    }

    session->queue=NULL;

    return result;

    error:

    logoutput("_setup_ssh_session: exit with error");
    return -1;

}

void _free_ssh_session(struct ssh_session_s *session)
{

    free_channels_table(session);
    free_hostinfo(session);
    free_identity(session);

    free_session_data(session);
    free_receive(session);
    free_send(session);

    free_session_status(session);
    free(session);
    free_ssh_pubkey(session);

    session=NULL;

}

void signal_ssh_interface(struct context_interface_s *interface, const char *what)
{
    struct ssh_session_s *session=(struct ssh_session_s *) interface->ptr;

    logoutput("signal_ssh_interface: %s", what);

    if (session==NULL) return;

    if (strcmp(what, "disconnecting")==0) {

	disconnect_ssh_session(session, 0, SSH_DISCONNECT_BY_APPLICATION);

    } else if (strcmp(what, "close")==0) {

	disconnect_ssh_connection(&session->connection);
	remove_ssh_session_eventloop(session);

    } else if (strcmp(what, "free")==0) {
	struct channel_table_s *table=&session->channel_table;
	struct ssh_channel_s *channel=NULL;
	struct simple_lock_s wlock;

	lock_group_ssh_sessions(&wlock);
	remove_ssh_session_group(session);
	unlock_group_ssh_sessions(&wlock);

	if (table->shell) {

	    channel=table->shell;
	    remove_channel(channel, CHANNEL_FLAG_CLIENT_CLOSE | CHANNEL_FLAG_SERVER_CLOSE);
	    (* channel->free)(channel);
	    table->shell=NULL;

	}

	channel=get_next_channel(session, NULL);

	while (channel) {
	    struct ssh_channel_s *next=get_next_channel(session, channel);

	    remove_channel(channel, CHANNEL_FLAG_CLIENT_CLOSE | CHANNEL_FLAG_SERVER_CLOSE);
	    (* channel->free)(channel);
	    channel=next;

	}

	remove_full_session(session);
	interface->ptr=NULL;

    }

}

struct ssh_session_s *get_full_session(uid_t uid, struct context_interface_s *interface, char *address, unsigned int port)
{
    struct ssh_session_s *session=NULL;
    void *index=NULL;
    unsigned int hashvalue=0;
    unsigned int error=0;
    pthread_mutex_t *mutex=NULL;
    pthread_cond_t *cond=NULL;
    struct context_option_s option;
    struct simple_lock_s wlock;
    int fd=-1;

    logoutput("get_full_session: %s:%i", address, port);

    if (init_ssh_backend(&error)==-1) {

	logoutput("get_full_session: error (%i:%s) init ssh backend", error, strerror(error));
	return NULL;

    }

    lock_group_ssh_sessions(&wlock);

    memset(&option, 0, sizeof(struct context_option_s));

    if ((* interface->get_context_option)(interface, "io:shared-mutex", &option)>0) {

	mutex=(pthread_mutex_t *) option.value.data;

    }

    memset(&option, 0, sizeof(struct context_option_s));

    if ((* interface->get_context_option)(interface, "io:shared-cond", &option)>0) {

	cond=(pthread_cond_t *) option.value.data;

    }

    session=_create_ssh_session(uid, interface, mutex, cond, &error);

    if (! session) {

	unlock_group_ssh_sessions(&wlock);
	return NULL;

    }

    fd=connect_ssh_connection(&session->connection, address, port);

    if (fd>0) {

	logoutput("get_full_session: connected to %s:%i", address, port);

    } else {

	logoutput("get_full_session: unable to connect to %s:%i", address, port);
	_free_ssh_session(session);
	unlock_group_ssh_sessions(&wlock);
	return NULL;

    }

    memset(&option, 0, sizeof(struct context_option_s));

    if ((* interface->get_context_option)(interface, "option:ssh.init_timeout", &option)==_INTERFACE_OPTION_INT) {

	session->connection.expire=option.value.number;

    }

    /* setup the session with encryption, hmac, dh, pk etc. */

    if (_setup_ssh_session(session, interface, fd)==0) {

	add_ssh_session_group(session);

    } else {

	send_disconnect_message(session, SSH_DISCONNECT_BY_APPLICATION);
	remove_ssh_session_eventloop(session);
	disconnect_ssh_connection(&session->connection);
	_free_ssh_session(session);
	session=NULL;

    }

    unlock_group_ssh_sessions(&wlock);

    return session;
}

void remove_full_session(struct ssh_session_s *session)
{
    struct list_element_s *list=NULL;
    struct fs_connection_s *conn=NULL;

    disconnect:

    /* disconnect and free main session */

    conn=&session->connection;
    conn->status |= FS_CONNECTION_FLAG_DISCONNECTING;

    if (conn->status & FS_CONNECTION_FLAG_CONNECTED) {

	if (session->status.sessionphase.phase==SESSION_PHASE_CONNECTION) send_disconnect_message(session, SSH_DISCONNECT_BY_APPLICATION);
	disconnect_ssh_connection(&session->connection);

    }

    remove_ssh_session_eventloop(session);
    _free_ssh_session(session);
    session=NULL;

}

unsigned int get_window_size(struct ssh_session_s *session)
{
    /* 2 ^ 32 - 1*/
    return (unsigned int)(UINT32_T_MAX - 1);
}

unsigned int get_max_packet_size(struct ssh_session_s *session)
{
    return session->status.max_packet_size;
}

void set_max_packet_size(struct ssh_session_s *session, unsigned int size)
{
    session->status.max_packet_size=size;
}

void get_session_expire_init(struct ssh_session_s *session, struct timespec *expire)
{
    struct fs_connection_s *connection=&session->connection;

    get_current_time(expire);
    expire->tv_sec+=connection->expire;
}

void get_session_expire_session(struct ssh_session_s *session, struct timespec *expire)
{
    struct fs_connection_s *connection=&session->connection;

    get_current_time(expire);
    expire->tv_sec+=connection->expire; /* make this configurable */
}

void disconnect_ssh_session(struct ssh_session_s *session, unsigned char server, unsigned int reason)
{

    if (server==0) {

	/* disconnect is done by client */

	logoutput("disconnect_ssh_session: initiated by client");

    } else {

	if (reason>0) {

	    logoutput("disconnect_ssh_session: initiated by server (reason: %i:%s)", reason, get_disconnect_reason(reason));

	} else {

	    logoutput("disconnect_ssh_session: initiated by server (reason: unknown)");

	}

    }

    pthread_mutex_lock(&session->status.mutex);

    if ((session->status.sessionphase.phase && SESSION_PHASE_DISCONNECT)==0 && (session->status.sessionphase.status & SESSION_STATUS_DISCONNECTING)==0) {

	remove_ssh_session_eventloop(session);
	if (session->status.sessionphase.phase==SESSION_PHASE_CONNECTION && server==0) send_disconnect_message(session, SSH_DISCONNECT_BY_APPLICATION);
	signal_send_disconnect(&session->send);
	signal_receive_disconnect(&session->receive);
	session->status.sessionphase.phase=SESSION_PHASE_DISCONNECT;

    }

    pthread_mutex_unlock(&session->status.mutex);

}

int create_ssh_connection(uid_t uid, struct context_interface_s *interface, struct context_address_s *address, unsigned int *error)
{
    struct ssh_session_s *session=NULL;
    char *target=NULL;
    unsigned int port=22; /* default for ssh */
    int fd=-1;

    logoutput("create_ssh_connection");

    /*
	20161118
	only IPv4 or hostname for now 
    */

    if (!(address->network.type==_INTERFACE_ADDRESS_NETWORK)) {
 
	logoutput("create_ssh_connection: error, only support for connection via ipv4 or hostname");
	*error=EINVAL;
	return -1;

    } else if (address->service.type!=_INTERFACE_SERVICE_PORT) {

	logoutput("create_ssh_connection: error, connections other than via a network port are not supported (service type=%i)", address->service.type);
	*error=EINVAL;
	return -1;

    } else if (address->service.target.port.type != _INTERFACE_PORT_TCP) {

	logoutput("create_ssh_connection: error, connections other than via an tcp port are not supported (port type=%i)", address->service.target.port.type);
	*error=EINVAL;
	return -1;

    }

    translate_context_address_network(address, &target, &port, NULL);

    logoutput("create_ssh_connection: connect to %s:%i", target, port);

    /* get ssh session for target and this uid: it may be an existing one */

    session=get_full_session(uid, interface, target, port);

    if (session) {
	struct channel_table_s *table=&session->channel_table;
	if (! table->shell) add_shell_channel(session);
	interface->ptr=(void *)session;
	return 0;

    }

    logoutput("create_ssh_connection: no session created for %s:%i", target, port);
    return -1;

}

static void analyze_connection_problem(void *ptr)
{
    struct ssh_session_s *session=(struct ssh_session_s *) ptr;
    struct fs_connection_s *connection=&session->connection;
    unsigned int tmp=0;

    pthread_mutex_lock(&session->status.mutex);

    tmp=connection->status & (FS_CONNECTION_FLAG_INIT | FS_CONNECTION_FLAG_CONNECTING | FS_CONNECTION_FLAG_CONNECTED);

    if (tmp) {
	unsigned int error=0;

	error=get_status_ssh_session(session);

	/* FOR NOW: also zero */

	if (error>0 || error==0) {

	    connection->error=(error) ? error : EIO;
	    connection->status-=tmp;
	    connection->status |= FS_CONNECTION_FLAG_DISCONNECTED;
	    disconnect_ssh_session(session, 0, 0);
	    connection->expire=0; /* prevent waiting */

	}

    }

    session->status.thread=0;
    pthread_mutex_unlock(&session->status.mutex);

}

void start_thread_connection_problem(struct ssh_session_s *session, unsigned int level)
{
    pthread_mutex_lock(&session->status.mutex);

    if (session->status.thread>0) goto unlock;

    if (session->status.sessionphase.phase==SESSION_PHASE_CONNECTION || session->status.sessionphase.phase==SESSION_PHASE_SETUP) {

	if (level==SESSION_LEVEL_SYSTEM) {
	    struct fs_connection_s *connection=&session->connection;

	    /* test the connection on low level: socket niveau */

	    if (connection->status & FS_CONNECTION_FLAG_CONNECTED) {
		unsigned int error=0;

		work_workerthread(NULL, 0, analyze_connection_problem, (void *) session, &error);
		session->status.thread=1;

	    }

	}

    }

    unlock:

    pthread_mutex_unlock(&session->status.mutex);

}

struct fs_connection_s *get_ssh_connection_ctx(void *ptr)
{
    if (ptr) {
	struct ssh_session_s *s=(struct ssh_session_s *) ptr;
	return &s->connection;
    }
    return NULL;
}
