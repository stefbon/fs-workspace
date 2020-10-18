/*
  2010, 2011, 2012, 2103, 2014, 2015, 2016, 2017 Stef Bon <stefbon@gmail.com>

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

#include "logging.h"
#include "main.h"
#include "utils.h"

#include "ssh-common-protocol.h"
#include "ssh-common.h"
#include "ssh-connections.h"
#include "ssh-channel.h"
#include "ssh-receive.h"
#include "ssh-utils.h"

/*

    possible values:

    SSH_MSG_GLOBAL_REQUEST			80

    SSH_MSG_CHANNEL_OPEN                        90
    SSH_MSG_CHANNEL_OPEN_CONFIRMATION           91
    SSH_MSG_CHANNEL_OPEN_FAILURE                92
    SSH_MSG_CHANNEL_WINDOW_ADJUST               93
    SSH_MSG_CHANNEL_DATA                        94
    SSH_MSG_CHANNEL_EXTENDED_DATA               95
    SSH_MSG_CHANNEL_EOF                         96
    SSH_MSG_CHANNEL_CLOSE                       97
    SSH_MSG_CHANNEL_REQUEST                     98
    SSH_MSG_CHANNEL_SUCCESS                     99
    SSH_MSG_CHANNEL_FAILURE                     100

*/

/*
    - byte		SSH_MSG_GLOBAL_REQUEST
    - string		request name
    - boolean		want reply
    ....		request specific data

    like "hostkeys-00@openssh.com"
*/

static void receive_msg_global_request(struct ssh_connection_s *connection, struct ssh_payload_s *payload)
{
    struct ssh_string_s name;

    init_ssh_string(&name);

    if (read_ssh_string(&payload->buffer[1], payload->len - 1, &name) > 3) {

	logoutput("receive_msg_global_request: received request %.*s", name.len, name.ptr);

    } else {

	logoutput("receive_msg_global_request: received request, cannot read name");

    }

    pthread_mutex_lock(connection->setup.mutex);

    if (connection->setup.flags & SSH_SETUP_FLAG_DISCONNECT) {

	free_payload(&payload);

    } else if (connection->setup.flags & SSH_SETUP_FLAG_SERVICE_CONNECTION) {
	struct payload_queue_s *queue = &connection->setup.queue;

	queue_ssh_payload_locked(queue, payload);
	payload=NULL;

    }

    pthread_mutex_unlock(connection->setup.mutex);

    if (payload) {

	logoutput("receive_msg_global_request: disconnect");
	free_payload(&payload);
	disconnect_ssh_connection(connection);

    }

}

/*
    message has the following form:

    - byte		SSH_MSG_CHANNEL_OPEN_CONFIRMATION
    - uint32		recipient channel
    - uint32		sender channel
    - uint32		initial window size
    - uint32		maximum packet size

*/

static void receive_msg_channel_open_confirmation(struct ssh_connection_s *connection, struct ssh_payload_s *payload)
{

    if (payload->len<17) {

	logoutput("receive_msg_open_confirmation: message too small (size: %i)", payload->len);

    } else {
	unsigned int pos=1;
	unsigned int local_channel=0;
	struct ssh_session_s *session=get_ssh_connection_session(connection);
	struct channel_table_s *table=&session->channel_table;
	struct ssh_channel_s *channel=NULL;
	struct simple_lock_s rlock;

	local_channel=get_uint32(&payload->buffer[pos]);
	pos+=4;

	logoutput("receive_msg_open_confirmation: local channel %i", local_channel);

	channeltable_readlock(table, &rlock);
	channel=lookup_session_channel_for_payload(table, local_channel, &payload);
	channeltable_unlock(table, &rlock);

    }

    if (payload) {

	logoutput("receive_msg_open_confirmation: free payload (%i)", payload->type);
	free_payload(&payload);

    }

}

/*
    message has the following form:

    - byte		SSH_MSG_CHANNEL_OPEN_FAILURE
    - uint32		recipient channel
    - uint32		reason code
    - string		description
    - string		language tag

*/

static void receive_msg_channel_open_failure(struct ssh_connection_s *connection, struct ssh_payload_s *payload)
{

    if (payload->len<17) {

	logoutput("receive_msg_open_failure: message too small (size: %i)", payload->len);

    } else {
	unsigned int pos=1;
	unsigned int local_channel=0;
	struct ssh_session_s *session=get_ssh_connection_session(connection);
	struct channel_table_s *table=&session->channel_table;
	struct ssh_channel_s *channel=NULL;
	struct simple_lock_s rlock;

	local_channel=get_uint32(&payload->buffer[pos]);
	pos+=4;

	channeltable_readlock(table, &rlock);
	channel=lookup_session_channel_for_payload(table, local_channel, &payload);
	channeltable_unlock(table, &rlock);

    }

    if (payload) free_payload(&payload);

}

static void receive_msg_channel_window_adjust(struct ssh_connection_s *connection, struct ssh_payload_s *payload)
{
    if (payload->len<9) {

	logoutput("receive_msg_channel_window_adjust: message too small (size: %i)", payload->len);

    } else {
	unsigned int pos=1;
	unsigned int local_channel=0;
	unsigned int size=0;
	struct ssh_session_s *session=get_ssh_connection_session(connection);
	struct channel_table_s *table=&session->channel_table;
	struct ssh_channel_s *channel=NULL;
	struct simple_lock_s rlock;

	local_channel=get_uint32(&payload->buffer[pos]);
	pos+=4;
	size=get_uint32(&payload->buffer[pos]);

	logoutput("receive_msg_channel_window_adjust: channel %i size %i", local_channel, size);

	channeltable_readlock(table, &rlock);
	channel=lookup_session_channel(table, local_channel);
	if (channel) {

	    pthread_mutex_lock(&channel->mutex);
	    channel->remote_window+=size;
	    pthread_mutex_unlock(&channel->mutex);

	}
	channeltable_unlock(table, &rlock);
	free_payload(&payload);

    }

    if (payload) free_payload(&payload);

}


/*
    receive data when channel is in the init phase: replies like SSH_MSG_CHANNEL_OPEN_CONFIRMATION, SSH_MSG_CHANNEL_SUCCESS

    queue the payload in the channel specific queue
    for the waiting thread
*/

void receive_msg_channel_data_init(struct ssh_channel_s *channel, struct ssh_payload_s **p_payload)
{
    struct ssh_payload_s *payload=*p_payload;
    queue_ssh_payload_channel(channel, payload);
    *p_payload=NULL;
}

void receive_msg_channel_data_down(struct ssh_channel_s *channel, struct ssh_payload_s **p_payload)
{
    /* do nothing */
    free_payload(p_payload);
}

static void receive_msg_channel_data(struct ssh_connection_s *connection, struct ssh_payload_s *payload)
{

    /*
	call the specific handler for the channel

	- byte			SSH_MSG_CHANNEL_DATA
	- uint32		recipient channel
	- string		data

	minimum size: 1 + 4 + 4 + 1 = 10

    */

    if (payload->len>9) {
	unsigned int local_channel=0;
	unsigned int len=0;
	unsigned int pos=1;

	local_channel=get_uint32(&payload->buffer[pos]);
	pos+=4;
	len=get_uint32(&payload->buffer[pos]);
	pos+=4;

	if (len + pos == payload->len) {
	    struct ssh_session_s *session=get_ssh_connection_session(connection);
	    struct channel_table_s *table=&session->channel_table;
	    struct ssh_channel_s *channel=NULL;
	    struct simple_lock_s rlock;

	    channeltable_readlock(table, &rlock);
	    channel=lookup_session_channel_for_data(table, local_channel, &payload);
	    channeltable_unlock(table, &rlock);

	}

    }

    if (payload) free_payload(&payload);

}

static void receive_msg_channel_extended_data(struct ssh_connection_s *connection, struct ssh_payload_s *payload)
{
    /*
	process the extended data, which will be probably output from stderr
	so it's related to a command and/or subsystem (sftp)
    */

    /*
	- byte					SSH_MSG_CHANNEL_EXTENDED_DATA
	- uint32				recipient channel
	- uint32				data_type_code
	- string				data

	data type can be one of:
	(at this moment 20160919)
	- SSH_EXTENDED_DATA_STDERR		1

    */

    if (payload->len>13) {
	unsigned int local_channel=0;
	unsigned int code=0;
	unsigned int len=0;
	unsigned int pos=1;

	local_channel=get_uint32(&payload->buffer[pos]);
	pos+=4;
	code=get_uint32(&payload->buffer[pos]);
	pos+=4;
	len=get_uint32(&payload->buffer[pos]);
	pos+=4;

	if (len + pos == payload->len) {

	    if (code==SSH_EXTENDED_DATA_STDERR) {
		struct ssh_session_s *session=get_ssh_connection_session(connection);
		struct channel_table_s *table=&session->channel_table;
		struct ssh_channel_s *channel=NULL;
		struct simple_lock_s rlock;

		channeltable_readlock(table, &rlock);
		channel=lookup_session_channel_for_payload(table, local_channel, &payload);
		channeltable_unlock(table, &rlock);

	    }

	}

    }

    if (payload) free_payload(&payload);

}

/* TODO: call a handler per channel which will close the channel and anything related like sftp */

static void receive_msg_channel_eof(struct ssh_connection_s *connection, struct ssh_payload_s *payload)
{

    if (payload->len<5) {

	logoutput("receive_msg_channel_eof: message too small (size: %i)", payload->len);

    } else {
	unsigned int pos=1;
	unsigned int local_channel=0;
	struct ssh_session_s *session=get_ssh_connection_session(connection);
	struct channel_table_s *table=&session->channel_table;
	struct ssh_channel_s *channel=NULL;
	struct ssh_signal_s *signal=NULL;
	struct simple_lock_s rlock;

	local_channel=get_uint32(&payload->buffer[pos]);
	pos+=4;

	logoutput_debug("receive_msg_channel_eof: channel %i", local_channel);

	channeltable_readlock(table, &rlock);
	channel=lookup_session_channel_for_flag(table, local_channel, CHANNEL_FLAG_SERVER_EOF);
	signal=(channel) ? channel->queue.signal : NULL;
	channeltable_unlock(table, &rlock);

	if (signal) {

	    pthread_mutex_lock(signal->mutex);
	    pthread_cond_broadcast(signal->cond);
	    pthread_mutex_unlock(signal->mutex);

	}

    }

    if (payload) free_payload(&payload);

}

/*
    message has the following form:

    - byte		SSH_MSG_CHANNEL_CLOSE
    - uint32		recipient channel
*/

static void receive_msg_channel_close(struct ssh_connection_s *connection, struct ssh_payload_s *payload)
{

    if (payload->len<5) {

	logoutput("receive_msg_channel_close: message too small (size: %i)", payload->len);

    } else {
	unsigned int pos=1;
	unsigned int local_channel=0;
	struct ssh_session_s *session=get_ssh_connection_session(connection);
	struct channel_table_s *table=&session->channel_table;
	struct ssh_channel_s *channel=NULL;
	struct ssh_signal_s *signal=NULL;
	struct simple_lock_s rlock;

	local_channel=get_uint32(&payload->buffer[pos]);
	pos+=4;

	logoutput_debug("receive_msg_channel_close: channel %i", local_channel);

	channeltable_readlock(table, &rlock);
	channel=lookup_session_channel_for_flag(table, local_channel, CHANNEL_FLAG_SERVER_CLOSE);
	signal=(channel) ? channel->queue.signal : NULL;
	channeltable_unlock(table, &rlock);

	if (signal) {

	    pthread_mutex_lock(signal->mutex);
	    pthread_cond_broadcast(signal->cond);
	    pthread_mutex_unlock(signal->mutex);

	}

    }

    if (payload) free_payload(&payload);
}

static void receive_msg_channel_request(struct ssh_connection_s *connection, struct ssh_payload_s *payload)
{
    /* here what to do ? receiving a request from the server is an error */
    free_payload(&payload);
}

/*
    message looks like:
    - byte		SSH_MSG_CHANNEL_SUCCESS or SSH_MSG_CHANNEL_FAILURE
    - uint32		local channel
*/

static void receive_msg_channel_request_reply(struct ssh_connection_s *connection, struct ssh_payload_s *payload)
{

    if (payload->len<5) {

	logoutput("receive_msg_channel_request_reply: message too small (size: %i)", payload->len);

    } else {
	struct ssh_session_s *session=get_ssh_connection_session(connection);
	struct channel_table_s *table=&session->channel_table;
	struct ssh_channel_s *channel=NULL;
	unsigned int local_channel=0;
	unsigned int pos=1;
	struct simple_lock_s rlock;

	local_channel=get_uint32(&payload->buffer[pos]);
	pos+=4;

	channeltable_readlock(table, &rlock);
	channel=lookup_session_channel_for_payload(table, local_channel, &payload);
	channeltable_unlock(table, &rlock);

    }

    if (payload) free_payload(&payload);

}

void register_channel_cb()
{
    register_msg_cb(SSH_MSG_GLOBAL_REQUEST, receive_msg_global_request);

    register_msg_cb(SSH_MSG_CHANNEL_OPEN_CONFIRMATION, receive_msg_channel_open_confirmation);
    register_msg_cb(SSH_MSG_CHANNEL_OPEN_FAILURE, receive_msg_channel_open_failure);
    register_msg_cb(SSH_MSG_CHANNEL_WINDOW_ADJUST, receive_msg_channel_window_adjust);
    register_msg_cb(SSH_MSG_CHANNEL_DATA, receive_msg_channel_data);
    register_msg_cb(SSH_MSG_CHANNEL_EXTENDED_DATA, receive_msg_channel_extended_data);
    register_msg_cb(SSH_MSG_CHANNEL_EOF, receive_msg_channel_eof);
    register_msg_cb(SSH_MSG_CHANNEL_CLOSE, receive_msg_channel_close);
    register_msg_cb(SSH_MSG_CHANNEL_REQUEST, receive_msg_channel_request);
    register_msg_cb(SSH_MSG_CHANNEL_SUCCESS, receive_msg_channel_request_reply);
    register_msg_cb(SSH_MSG_CHANNEL_FAILURE, receive_msg_channel_request_reply);
}
