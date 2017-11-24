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

#include "logging.h"
#include "main.h"
#include "utils.h"

#include "workerthreads.h"
#include "workspace-interface.h"

#include "ssh-common-protocol.h"
#include "ssh-common.h"
#include "ssh-channel.h"
#include "ssh-channel-utils.h"
#include "ssh-channel-table.h"
#include "ssh-admin-channel.h"
#include "ssh-common-list.h"

#include "ssh-send-channel.h"
#include "ssh-hostinfo.h"
#include "ssh-receive-channel.h"
#include "ssh-utils.h"

extern struct workerthreads_queue_struct workerthreads_queue;

struct ssh_channel_s *get_containing_channel(struct list_element_s *list)
{
    return (struct ssh_channel_s *) ( ((char *) list) - offsetof(struct ssh_channel_s, list));
}

void add_channel_table(struct ssh_channel_s *channel)
{
    unsigned int hashvalue=0;
    struct channel_table_s *table=&channel->session->channel_table;
    struct list_head_s *list_head=NULL;

    /* add to hash table of channels */

    channel->local_channel=table->latest_channel;
    table->latest_channel++;
    hashvalue=channel->local_channel % CHANNELS_TABLE_SIZE;
    list_head=&table->hash[hashvalue];
    add_list_element_first(&(list_head->head), &(list_head->tail), &channel->list);
    table->count++;
}

void remove_channel_table(struct ssh_channel_s *channel)
{
    struct ssh_session_s *session=channel->session;
    struct channel_table_s *table=&session->channel_table;
    unsigned int hashvalue=0;
    struct list_head_s *list_head=NULL;

    hashvalue=channel->local_channel % table->table_size;
    list_head=&table->hash[hashvalue];
    remove_list_element(&list_head->head, &list_head->tail, &channel->list);
    table->count--;
}

void clean_ssh_channel_queue(struct ssh_channel_s *channel)
{
    struct ssh_payload_s *payload=channel->first;

    while (payload) {

	channel->first=payload->next;
	logoutput("clean_ssh_channel_queue: found type %i", payload->type);
	free(payload);
	payload=channel->first;

    }
}

void clear_ssh_channel(struct ssh_channel_s *channel)
{
    clean_ssh_channel_queue(channel);

    if (channel->type==_CHANNEL_TYPE_DIRECT_STREAMLOCAL) {

	if (channel->target.socket.path) {

	    free(channel->target.socket.path);
	    channel->target.socket.path=NULL;

	}

    } else if (channel->type==_CHANNEL_TYPE_DIRECT_TCPIP) {

	if (channel->target.tcpip.host) {

	    free(channel->target.tcpip.host);
	    channel->target.tcpip.host=NULL;

	}

    }

    pthread_mutex_destroy(&channel->mutex);

}

void free_ssh_channel(struct ssh_channel_s *channel)
{
    clear_ssh_channel(channel);
    free(channel);
}

void init_ssh_channel(struct ssh_channel_s *channel)
{
    struct ssh_session_s *session=channel->session;
    struct ssh_receive_s *receive=&session->receive;
    struct payload_queue_s *queue=&receive->payload_queue;

    channel->local_channel=0;
    channel->remote_channel=0;

    channel->status=CHANNEL_STATUS_INIT;
    channel->substatus=0;

    channel->max_packet_size=0; /* filled later */
    channel->actors=0;
    channel->local_window=get_window_size(session);

    /* make use of the central mutex/cond for announcing payload has arrived */

    channel->signal=&queue->signal;

    channel->first=NULL;
    channel->last=NULL;

    pthread_mutex_init(&channel->mutex, NULL);
    channel->free=free_ssh_channel;
    channel->list.next=NULL;
    channel->list.prev=NULL;

    switch_channel_send_data(channel, "default");

}

struct ssh_channel_s *new_admin_channel(struct ssh_session_s *session)
{
    struct ssh_channel_s *channel=NULL;

    channel=malloc(sizeof(struct ssh_channel_s));

    if (channel) {

	memset(channel, 0, sizeof(struct ssh_channel_s));
	channel->type=_CHANNEL_TYPE_ADMIN;
	channel->session=session;
	init_ssh_channel(channel);

    }

    return channel;

}

struct ssh_payload_s *get_ssh_payload_channel(struct ssh_channel_s *channel, struct timespec *expire, unsigned int *seq, unsigned int *error)
{
    struct ssh_signal_s *signal=channel->signal;
    int result=0;
    struct ssh_payload_s *payload=NULL;
    unsigned int len=0;

    pthread_mutex_lock(signal->mutex);

    while (! channel->first) {

	result=pthread_cond_timedwait(signal->cond, signal->mutex, expire);

	if (result==ETIMEDOUT) {

	    logoutput("get_ssh_payload_channel: timeout");
	    *error=ETIMEDOUT;
	    pthread_mutex_unlock(signal->mutex);
	    return NULL;

	} else if (seq && *seq==signal->sequence_number_error) {

	    logoutput("get_ssh_payload_channel: seq error");
	    *error=signal->error;
	    pthread_mutex_unlock(signal->mutex);
	    return NULL;

	}

    }

    *error=0;
    payload=channel->first;

    if (payload->next) {

	channel->first=payload->next;

    } else {

	channel->first=NULL;
	channel->last=NULL;

    }

    pthread_mutex_unlock(signal->mutex);

    payload->next=NULL;

    return payload;

}

void queue_ssh_payload_channel(struct ssh_channel_s *channel, struct ssh_payload_s *payload)
{
    struct ssh_signal_s *signal=channel->signal;

    payload->next=NULL;

    pthread_mutex_lock(signal->mutex);

    if (channel->last) {

	/* put after last */

	channel->last->next=payload;
	channel->last=payload;

    } else {

	channel->last=payload;
	channel->first=payload;

	pthread_cond_broadcast(signal->cond);

    }

    pthread_mutex_unlock(signal->mutex);

}

struct ssh_channel_s *remove_channel_table_locked(struct ssh_session_s *session, struct ssh_channel_s *channel, unsigned int local_channel)
{
    struct channel_table_s *table=&session->channel_table;

    if (channel) {

	if (channel->session != session) return NULL;

    }

    /* protect the handling of adding/removing channels */

    pthread_mutex_lock(&table->mutex);

    while (table->lock & TABLE_LOCK_LOCKED) {

	pthread_cond_wait(&table->cond, &table->mutex);

    }

    table->lock|=TABLE_LOCK_CLOSECHANNEL;
    pthread_mutex_unlock(&table->mutex);

    if (!channel) channel=lookup_session_channel(table, local_channel);

    if (channel) {

        if (channel->status==CHANNEL_STATUS_UP && channel->substatus==CHANNEL_SUBSTATUS_OPEN) send_channel_close_message(channel);
	switch_channel_receive_data(channel, "down", NULL);
	remove_channel_table(channel);

    }

    pthread_mutex_lock(&table->mutex);

    if (table->lock & TABLE_LOCK_CLOSECHANNEL) {

	/* release the lock */

	table->lock -= TABLE_LOCK_CLOSECHANNEL;
	pthread_cond_broadcast(&table->cond);

    }

    pthread_mutex_unlock(&table->mutex);
    return channel;

}

/* start a channel by getting confirmation from server */

int start_new_channel(struct ssh_channel_s *channel)
{
    int result=-1;
    unsigned int seq=0;
    struct ssh_payload_s *payload=NULL;
    struct ssh_session_s *session=channel->session;
    struct channel_table_s *table=&session->channel_table;

    switch_channel_receive_data(channel, "init", NULL);

    logoutput("start_new_channel: send channel open message");

    if (send_channel_open_message(channel, &seq)==0) {
	struct timespec expire;
	unsigned int error=0;

	get_channel_expire_init(channel, &expire);

	payload=get_ssh_payload_channel(channel, &expire, &seq, &error);

	if (! payload) {
	    struct ssh_session_s *session=channel->session;

	    if (session->status.error==0) session->status.error=(error>0) ? error : EIO;
	    logoutput("start_new_channel: error %i waiting for packet (%s)", session->status.error, strerror(session->status.error));
	    goto out;

	}

	if (payload->type==SSH_MSG_CHANNEL_OPEN_CONFIRMATION) {
	    unsigned int window=0;

	    /* ok (remote channel is set by receiving thread) */

	    channel->remote_channel=get_uint32(&payload->buffer[5]);
	    window=get_uint32(&payload->buffer[9]);
	    channel->max_packet_size=get_uint32(&payload->buffer[13]);

	    channel->status=CHANNEL_STATUS_UP;
	    channel->substatus=CHANNEL_SUBSTATUS_OPEN;

	    logoutput("start_new_channel: created a new channel local:remote %i:%i rem window %i max packet size %i", channel->local_channel, channel->remote_channel, window, channel->max_packet_size);
	    result=0;

	} else if (payload->type==SSH_MSG_CHANNEL_OPEN_FAILURE) {
	    unsigned int reasoncode=0;
	    unsigned int len=0;

	    reasoncode=get_uint32(&payload->buffer[5]);
	    len=get_uint32(&payload->buffer[9]);

	    if (13 + len <= payload->len) {
		unsigned char string[len+1];

		memcpy(string, &payload->buffer[13], len);
		string[len]='\0';

		logoutput("start_new_channel: failed by server: %s/%s", get_openfailure_reason(reasoncode), string);

	    } else {

		logoutput("start_new_channel: failed by server: %s", get_openfailure_reason(reasoncode));

	    }

	    goto out;

	} else {

	    logoutput("start_new_channel: unexpected reply from server: %i", payload->type);
	    goto out;

	}


    } else {

	logoutput("start_new_channel: error sending open channel message");

    }

    out:

    if (payload) {

	free(payload);
	payload=NULL;

    }

    return result;

}

void add_admin_channel(struct ssh_session_s *session)
{
    struct ssh_channel_s *channel=NULL;
    struct channel_table_s *table=&session->channel_table;
    int result=0;

    /* create the admin channel
	admin channel required for getting various info */

    channel=new_admin_channel(session);

    if (! channel) {

	logoutput("add_admin_channel: unable to create admin channel");
	return;

    }

    table=&session->channel_table;

    /* protect the handling of adding/removing channels */

    pthread_mutex_lock(&table->mutex);

    while (table->lock & TABLE_LOCK_LOCKED) {

	pthread_cond_wait(&table->cond, &table->mutex);

    }

    table->lock|=TABLE_LOCK_OPENCHANNEL;
    add_channel_table(channel);
    pthread_mutex_unlock(&table->mutex);

    if (start_new_channel(channel)==0) {

	logoutput("add_admin_channel: created admin channel");

    } else {

	result=-1;
	free_ssh_channel(channel);
	channel=NULL;

    }

    pthread_mutex_lock(&table->mutex);

    if (channel) 

    if (table->lock & TABLE_LOCK_OPENCHANNEL) {

	/* release the lock */

	table->lock -= TABLE_LOCK_OPENCHANNEL;
	pthread_cond_broadcast(&table->cond);

    }

    if (result==-1) {

	remove_channel_table(channel);
	send_channel_close_message(channel);
	free_ssh_channel(channel);
	channel=NULL;

    }

    pthread_mutex_unlock(&table->mutex);

    if (channel) {

	/* start a shell on the channel */

	if (start_remote_shell_admin(channel)==0) {
	    struct channel_table_s *table=&session->channel_table;

	    logoutput("add_admin_channel: started admin remote shell");
	    table->admin=channel;

	}

    }

}

void close_channel_generic(struct ssh_channel_s *channel)
{
    if (channel->type==_CHANNEL_TYPE_ADMIN) free_ssh_channel(channel);
}

void *create_ssh_connection(uid_t uid, struct context_interface_s *interface, struct context_address_s *address, unsigned int *error)
{
    struct ssh_session_s *session=NULL;

    /*
	20161118
	only IPv4 for now
    */

    if (!(address->type==_INTERFACE_NETWORK_IPV4)) {

	logoutput("create_ssh_connection: error, only support for ipv4");
	*error=EINVAL;
	return NULL;

    } else if (address->target.network.address==NULL || address->target.network.port==0) {

	logoutput("create_ssh_connection: error, address and/or port empty");
	*error=EINVAL;
	return NULL;

    }

    /* get ssh session for target and this uid: it may be an existing one */

    session=get_full_session(uid, interface, address->target.network.address, address->target.network.port);

    if (! session) {

	logoutput("create_ssh_connection: no session created for %s:%i", address->target.network.address, address->target.network.port);

    } else {
	struct channel_table_s *table=&session->channel_table;

	if (! table->admin) add_admin_channel(session);

    }

    return (void *) session;
}

