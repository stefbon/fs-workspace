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

#include "utils.h"

#include "workspace-interface.h"
#include "ssh-common-protocol.h"
#include "ssh-common.h"
#include "ssh-common-list.h"

#include "ssh-compression.h"
#include "ssh-connection.h"
#include "ssh-encryption.h"
#include "ssh-hostinfo.h"
#include "ssh-keyx.h"
#include "ssh-kex.h"
#include "ssh-mac.h"
#include "ssh-pubkey.h"
#include "ssh-receive.h"
#include "ssh-send.h"
#include "ssh-data.h"
#include "ssh-channel-table.h"
#include "ssh-channel.h"

#include "ssh-utils.h"

#include "ssh-send-greeter.h"
#include "ssh-send-kexinit.h"
#include "ssh-send-userauth.h"
#include "ssh-userauth.h"
#include "ssh-send-transport.h"

#include "ssh-receive-greeter.h"
#include "ssh-queue-rawdata.h"
#include "ssh-queue-payload.h"
#include "ssh-receive-waitreply.h"

#include "ssh-kexinit.h"

static void init_session_status(struct ssh_session_s *session)
{
    struct ssh_status_s *status=&session->status;

    pthread_mutex_init(&status->mutex, NULL);
    pthread_cond_init(&status->cond, NULL);
    status->error=0;
    status->max_packet_size=32768;
    status->remote_version_major=0;
    status->remote_version_minor=0;
    status->status=0;
    status->substatus=0;
    status->unique=0;

}

static void free_session_status(struct ssh_session_s *session)
{
    struct ssh_status_s *status=&session->status;
    pthread_mutex_destroy(&status->mutex);
    pthread_cond_destroy(&status->cond);
}

void change_session_status(struct ssh_session_s *session, unsigned int status)
{
    pthread_mutex_lock(&session->status.mutex);
    session->status.status=status;
    session->status.substatus=0;
    pthread_mutex_unlock(&session->status.mutex);
}

int check_session_status(struct ssh_session_s *session, unsigned int status, unsigned int substatus)
{
    int result=-1;
    pthread_mutex_lock(&session->status.mutex);

    if (substatus>0) {

	result=(session->status.status==status && (session->status.substatus&substatus)) ? 0 : -1;

    } else {

	result=(session->status.status==status) ? 0 : -1;

    }

    pthread_mutex_unlock(&session->status.mutex);
    return result;
}

int check_change_session_substatus(struct ssh_session_s *session, unsigned int status, unsigned int substatus, unsigned int subnew)
{
    int result=-1;

    pthread_mutex_lock(&session->status.mutex);

    if (session->status.status==status && (substatus==0 || (session->status.substatus&substatus))) {

	if (session->status.substatus&subnew) {

	    /* already set */
	    result=1;

	} else {

	    session->status.substatus|=subnew;
	    result=0;

	}

    }

    pthread_mutex_unlock(&session->status.mutex);
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


static struct ssh_session_s *_create_ssh_session(uid_t uid, pthread_mutex_t *mutex, pthread_cond_t *cond, unsigned int *error)
{
    struct ssh_session_s *ssh_session=NULL;

    ssh_session=malloc(sizeof(struct ssh_session_s));

    if (ssh_session) {

	memset(ssh_session, 0, sizeof(struct ssh_session_s));

	ssh_session->list.next=NULL;
	ssh_session->list.prev=NULL;

	init_session_status(ssh_session);
	init_channels_table(ssh_session, CHANNELS_TABLE_SIZE);
	init_session_data(ssh_session);
	init_ssh_connection(ssh_session);
	init_hostinfo(ssh_session);

	/* start without compression, encryption, hmac and publickey */

	init_compression(ssh_session);
	init_encryption(ssh_session);
	init_mac(ssh_session);
	init_pubkey(ssh_session);
	init_send(ssh_session);

	if (init_ssh_identity(ssh_session, uid, error)==-1) {

	    logoutput("_create_ssh_session: error (%i:%s) init identity", *error, strerror(*error));
	    goto error;

	}

	if (init_receive(ssh_session, mutex, cond, error)==-1) {

	    logoutput("_create_ssh_session: error (%i:%s) init receive buffer", *error, strerror(*error));
	    goto error;

	}

	return ssh_session;

    }

    error:

    if (ssh_session) {

	free_receive(ssh_session);
	free_send(ssh_session);
	free_pubkey(ssh_session);

	free_hostinfo(ssh_session);
	free_session_data(ssh_session);

	free_session_status(ssh_session);
	free_channels_table(ssh_session);
	free_identity(ssh_session);

	free(ssh_session);
	ssh_session=NULL;

    }

    return NULL;

}

static int _setup_ssh_session(struct ssh_session_s *session, struct context_interface_s *interface)
{

    /* send a greeter and wait for greeter from server */

    if (check_change_session_substatus(session, SESSION_STATUS_SETUP, 0, SESSION_SUBSTATUS_GREETER)==0) {
	struct timespec expire;
	unsigned int error=0;

	if (add_session_eventloop(session, interface, &session->status.error)==-1) {

	    if (session->status.error==0) session->status.error=EIO;
	    logoutput("_setup_ssh_session: error %i adding fd %i to eventloop (%s)", session->status.error, session->connection.fd, strerror(session->status.error));
	    goto error;

	} else {

	    logoutput("_setup_ssh_session: added fd %i to eventloop", session->connection.fd);

	}

	if (send_greeter(session)==-1) {

	    if (session->status.error==0) session->status.error=EIO;
	    logoutput("_setup_ssh_session: error %i sending greeter (%s)", session->status.error, strerror(session->status.error));
	    goto error;

	} else {

	    logoutput("_setup_ssh_session: greeter send");

	}

	/* get/wait for the first packet from the server: greeter */

	get_session_expire_init(session, &expire);

	if (wait_reply_server_greeter(session, &expire, &error)==-1) {

	    if (session->status.error==0) session->status.error=(error>0) ? error : EIO;
	    logoutput("_setup_ssh_session: error %i waiting for server greeter (%s)", session->status.error, strerror(session->status.error));
	    goto error;

	}

    }

    if (check_change_session_substatus(session, SESSION_STATUS_SETUP, SESSION_SUBSTATUS_GREETER, SESSION_SUBSTATUS_KEYEXCHANGE)==0) {

	if (process_key_exchange(session, NULL, 1)==-1) {

	    goto error;

	}

    }

    if (check_change_session_substatus(session, SESSION_STATUS_SETUP, SESSION_SUBSTATUS_KEYEXCHANGE, SESSION_SUBSTATUS_REQUEST_USERAUTH)==0) {
	struct timespec expire;
	unsigned int error=0;
	struct ssh_payload_s *payload=NULL;
	unsigned int seq=0;
	int result=-1;

	logoutput("_setup_ssh_session: request for service ssh-userauth");

	if (send_service_request_message(session, "ssh-userauth", &seq)==-1) {

	    error=EIO;
	    logoutput("_setup_ssh_session: error %i sending service request ssh-userauth (%s)", error, strerror(error));
	    goto outrequest;

	}

	get_session_expire_init(session, &expire);

	getrequest:

	payload=get_ssh_payload(session, &expire, &seq, &error);

	if (! payload) {

	    if (error==0) error=EIO;
	    logoutput("_setup_ssh_session: error %i waiting for server SSH_MSG_SERVICE_REQUEST (%s)", error, strerror(error));
	    goto outrequest;

	}

	if (payload->type == SSH_MSG_SERVICE_ACCEPT) {
	    unsigned int len=strlen("ssh-userauth");
	    char buffer[5 + len];

	    buffer[0]=(unsigned char) SSH_MSG_SERVICE_ACCEPT;
	    store_uint32(&buffer[1], len);
	    memcpy(&buffer[5], "ssh-userauth", len);

	    if (memcmp(payload->buffer, buffer, len)==0) {

		logoutput("_setup_ssh_session: server accepted service ssh-userauth");
		result=0;

	    } else {

		logoutput("_setup_ssh_session: server has sent an invalid service accept message");
		goto outrequest;

	    }

	} else {

	    if (payload->type == SSH_MSG_IGNORE || payload->type == SSH_MSG_DEBUG) {

		process_ssh_message(session, payload);
		free(payload);
		payload=NULL;
		goto getrequest;

	    }

	    logoutput("_setup_ssh_session: server send unexpected %i: disconnect", payload->type);
	    goto outrequest;

	}

	outrequest:

	if (payload) {

	    free(payload);
	    payload=NULL;

	}

	if (result==-1) {

	    logoutput("_setup_ssh_session: userauth failed");
	    goto error;

	}

    }

    if (check_change_session_substatus(session, SESSION_STATUS_SETUP, SESSION_SUBSTATUS_REQUEST_USERAUTH, SESSION_SUBSTATUS_USERAUTH)==0) {

	if (ssh_authentication(session)==0) {

	    logoutput("_setup_ssh_session: authentication succes");

	} else {

	    logoutput("_setup_ssh_session: authentication failed");
	    goto error;

	}

    }

    pthread_mutex_lock(&session->status.mutex);

    if (session->status.status==SESSION_STATUS_SETUP &&
	session->status.substatus==(SESSION_SUBSTATUS_GREETER | SESSION_SUBSTATUS_KEYEXCHANGE | SESSION_SUBSTATUS_REQUEST_USERAUTH | SESSION_SUBSTATUS_USERAUTH)) {

	session->status.status=SESSION_STATUS_CONNECTION;
	session->status.substatus=0;

	pthread_mutex_unlock(&session->status.mutex);

	/* do not process the messages from queue anymore but start a seperate thread */

	switch_process_payload_queue(session, "session");

	return 0;

    }

    pthread_mutex_unlock(&session->status.mutex);

    error:

    logoutput("_setup_ssh_session: exit with error");
    return -1;

}

void _free_ssh_session(struct ssh_session_s *session)
{

    logoutput("_free_ssh_session");

    switch_process_rawdata_queue(session, "none");
    switch_send_process(session, "none");

    free_channels_table(session);
    free_hostinfo(session);
    free_identity(session);

    free_session_data(session);
    free_receive(session);
    free_send(session);
    free_pubkey(session);

    free_s2c_mac(session);
    free_c2s_mac(session);

    free_encrypt(session);
    free_decrypt(session);

    free_session_status(session);
    free(session);
    session=NULL;

}

void umount_ssh_session(struct context_interface_s *interface)
{
    struct ssh_session_s *session=(struct ssh_session_s *) interface->ptr;

    logoutput("umount_ssh_session");

    if (session) {
	struct channel_table_s *table=&session->channel_table;

	lock_group_ssh_sessions();
	remove_ssh_session_group(session);
	unlock_group_ssh_sessions();

	if (table->admin) {
	    struct ssh_channel_s *channel=table->admin;

	    /* admin channel still open */

	    channel=remove_channel_table_locked(session, channel, 0);

	    free_ssh_channel(table->admin);
	    table->admin=NULL;

	}

	remove_full_session(session);

    }

    interface->ptr=NULL;

}

struct ssh_session_s *get_full_session(uid_t uid, struct context_interface_s *interface, char *address, unsigned int port)
{
    struct ssh_session_s *session=NULL;
    void *index=NULL;
    unsigned int hashvalue=0;

    /*
	test there is already a session for this context
	session->channel->context == context
	or
	address-port(session) == address-port(context)
    */

    lock_group_ssh_sessions();

    session=get_next_ssh_session(&index, &hashvalue);

    while (session) {

	pthread_mutex_lock(&session->status.mutex);

	/* look for a session for the same user and to the same server */

	if (session->identity.pwd.pw_uid==uid && compare_session_connection(session, address, port)==0) {

	    /* wait for session to be complete */

	    while (! (session->status.status==SESSION_STATUS_CONNECTION)) {

		pthread_cond_wait(&session->status.cond, &session->status.mutex);

	    }

	    if (session->status.status==SESSION_STATUS_CONNECTION) {

		/* only full working sessions which are not "busy" with another channel */

		pthread_mutex_unlock(&session->status.mutex);
		break;

	    }

	}

	pthread_mutex_unlock(&session->status.mutex);
	session=get_next_ssh_session(&index, &hashvalue);

    }

    if (! session) {
	unsigned int error=0;
	pthread_mutex_t *mutex=NULL;
	pthread_cond_t *cond=NULL;
	struct context_option_s option;

	memset(&option, 0, sizeof(struct context_option_s));

	if ((* interface->get_interface_option)(interface, "shared-mutex", &option)>0) {

	    mutex=(pthread_mutex_t *) option.value.data;

	}

	memset(&option, 0, sizeof(struct context_option_s));

	if ((* interface->get_interface_option)(interface, "shared-cond", &option)>0) {

	    cond=(pthread_cond_t *) option.value.data;

	}

	session=_create_ssh_session(uid, mutex, cond, &error);

	if (! session) {

	    unlock_group_ssh_sessions();
	    return NULL;

	} else {

	    if (connect_ssh_server(session, address, port)>0) {

		logoutput("get_full_session: connected to %s:%i", address, port);

	    } else {

		logoutput("get_full_session: unable to connect to %s:%i", address, port);
		_free_ssh_session(session);
		unlock_group_ssh_sessions();
		return NULL;

	    }

	}

	/* setup the session with encryption, hmac, dh, pk etc. */

	change_session_status(session, SESSION_STATUS_SETUP);

	if (_setup_ssh_session(session, interface)==0) {

	    add_ssh_session_group(session);

	} else {

	    if (session->connection.fd>0) {

		send_disconnect_message(session, SSH_DISCONNECT_BY_APPLICATION);
		remove_session_eventloop(session);
		disconnect_ssh_server(session);

	    }

	    _free_ssh_session(session);
	    session=NULL;
	}

    }

    unlock_group_ssh_sessions();

    return session;
}

void remove_full_session(struct ssh_session_s *session)
{

    logoutput("remove full session");

    /* disconnect and free session */

    if (session->connection.fd>0) {

	if (session->status.status==SESSION_STATUS_CONNECTION) {

	    send_disconnect_message(session, SSH_DISCONNECT_BY_APPLICATION);

	}

	remove_session_eventloop(session);
	disconnect_ssh_server(session);

    }

    _free_ssh_session(session);
    session=NULL;

}

unsigned int get_window_size(struct ssh_session_s *session)
{
    return (16 * 1024 * 1024);
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
    get_current_time(expire);
    expire->tv_sec+=5; /* make this configurable */
}

void get_session_expire_session(struct ssh_session_s *session, struct timespec *expire)
{
    get_current_time(expire);
    expire->tv_sec+=1; /* make this configurable */
}

void disconnect_ssh_session(struct ssh_session_s *session, unsigned char server, unsigned int reason)
{

    if (server==0) {

	/* disconnect is done by client */

	logoutput("disconnect_ssh_session: initiated by client");

    } else {

	if (reason>0) {

	    logoutput("disconnect_ssh_session: initiated by server (reason: %i)", reason);

	} else {

	    logoutput("disconnect_ssh_session: initiated by server (reason: unknown)");

	}

    }

    pthread_mutex_lock(&session->status.mutex);

    if (session->status.status != SESSION_STATUS_DISCONNECT) {

	if (session->connection.fd>0) {

	    remove_session_eventloop(session);

	    if (session->status.status==SESSION_STATUS_CONNECTION && server==0) {

		send_disconnect_message(session, SSH_DISCONNECT_BY_APPLICATION);

	    }

	}

	/* disable sending of messages */

	switch_send_process(session, "none");
	disconnect_ssh_server(session);

	session->status.status=SESSION_STATUS_DISCONNECT;

    }

    pthread_mutex_unlock(&session->status.mutex);

}

void init_ssh_payload(struct ssh_payload_s *payload)
{
    memset(payload, 0, sizeof(struct ssh_payload_s));

    payload->type=0;
    payload->sequence=0;
    payload->len=0;
    payload->next=NULL;
    payload->prev=NULL;

}
