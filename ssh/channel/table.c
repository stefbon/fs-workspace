/*
  2016, 2017, 2018 Stef Bon <stefbon@gmail.com>

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

#include "logging.h"
#include "main.h"
#include "common-utils/utils.h"

#include "ssh-common-protocol.h"
#include "ssh-common.h"
#include "ssh-channel.h"

struct ssh_channel_s *lookup_session_channel_for_payload(struct channel_table_s *table, unsigned int nr, struct ssh_payload_s **p_payload)
{
    unsigned int hashvalue = nr % CHANNELS_TABLE_SIZE;
    struct ssh_channel_s *channel=table->hash[hashvalue].head;

    while (channel) {

	if (channel->local_channel==nr) {

	    queue_ssh_payload_channel(channel, *p_payload);
	    *p_payload=NULL;
	    break;

	}

	channel=channel->list.next;

    }

    return channel;
}

struct ssh_channel_s *lookup_session_channel_for_data(struct channel_table_s *table, unsigned int nr, struct ssh_payload_s **p_payload)
{
    unsigned int hashvalue = 0;
    struct ssh_channel_s *channel=NULL;

    //logoutput("lookup_session_channel_for_data: table %s nr %i size %i", (table) ? "defined" : "notdefined", nr, table->table_size);

    hashvalue = nr % CHANNELS_TABLE_SIZE;
    channel=table->hash[hashvalue].head;

    // logoutput("lookup_session_channel_for_data: head %s", (channel) ? "defined" : "notdefined");

    while (channel) {

	// logoutput("lookup_session_channel_for_data: found %i", channel->local_channel);

	if (channel->local_channel==nr) {
	    struct ssh_payload_s *payload=*p_payload;

	    // logoutput("lookup_session_channel_for_data: a");

	    (* channel->process_incoming_bytes)(channel, payload->len);
	    // logoutput("lookup_session_channel_for_data: b");
	    (* channel->receive_msg_channel_data)(channel, p_payload);
	    // logoutput("lookup_session_channel_for_data: c");
	    break;

	}

	channel=channel->list.next;

    }

    return channel;
}

struct ssh_channel_s *lookup_session_channel_for_flag(struct channel_table_s *table, unsigned int nr, unsigned int flag)
{
    unsigned int hashvalue = nr % CHANNELS_TABLE_SIZE;
    struct ssh_channel_s *channel=table->hash[hashvalue].head;

    while (channel) {

	if (channel->local_channel==nr) {

	    pthread_mutex_lock(&channel->mutex);
	    channel->flags |= flag;
	    pthread_mutex_unlock(&channel->mutex);
	    break;

	}

	channel=channel->list.next;

    }

    return channel;
}

struct ssh_channel_s *lookup_session_channel(struct channel_table_s *table, unsigned int nr)
{
    unsigned int hashvalue = nr % CHANNELS_TABLE_SIZE;
    struct ssh_channel_s *channel=table->hash[hashvalue].head;

    while (channel) {

	if (channel->local_channel==nr) break;
	channel=channel->list.next;

    }

    return channel;
}

void init_channels_table(struct ssh_session_s *session, unsigned int size)
{
    struct channel_table_s *table=&session->channel_table;

    table->latest_channel=0;
    table->count=0;
    table->table_size=size;
    table->shell=NULL;

    for (unsigned int i=0; i<size; i++) {

	table->hash[i].head=NULL;
	table->hash[i].tail=NULL;
    }

    init_simple_locking(&table->locking);
    table->lock=0;

}

void free_channels_table(struct ssh_session_s *session)
{
    struct channel_table_s *table=&session->channel_table;
    struct channellist_head_s *channellist_head=NULL;
    struct ssh_channel_s *channel=NULL;

    for (unsigned int i=0; i<CHANNELS_TABLE_SIZE; i++) {

	channellist_head=&table->hash[i];
	channel=channellist_head->head;

	while (channel) {

	    if (channel == channellist_head->tail) {

		channellist_head->head=NULL;
		channellist_head->tail=NULL;

	    } else {
		struct ssh_channel_s *next=channel->list.next;

		channellist_head->head=next;
		next->list.prev=NULL;

	    }

	    (* channel->free)(channel);
	    channel=channellist_head->head;

	}

    }

    clear_simple_locking(&table->locking);

}

int channeltable_readlock(struct channel_table_s *table, struct simple_lock_s *rlock)
{
    init_simple_readlock(&table->locking, rlock);
    return simple_lock(rlock);
}

int channeltable_upgrade_readlock(struct channel_table_s *table, struct simple_lock_s *rlock)
{
    return simple_upgradelock(rlock);
}

int channeltable_writelock(struct channel_table_s *table, struct simple_lock_s *wlock)
{
    init_simple_writelock(&table->locking, wlock);
    return simple_lock(wlock);
}

int channeltable_unlock(struct channel_table_s *table, struct simple_lock_s *lock)
{
    return simple_unlock(lock);
}

struct ssh_channel_s *find_channel(struct ssh_session_s *session, unsigned int type)
{
    struct channel_table_s *table=&session->channel_table;
    struct channellist_head_s *channellist_head=NULL;
    struct ssh_channel_s *channel=NULL;

    for (unsigned int i=0; i<CHANNELS_TABLE_SIZE; i++) {

	channellist_head=&table->hash[i];
	channel=channellist_head->head;

	while (channel) {

	    if (channel->type==type) break;
	    channel=channel->list.next;

	}

    }

    return channel;

}

struct ssh_channel_s *get_next_channel(struct ssh_session_s *session, struct ssh_channel_s *channel)
{
    struct channel_table_s *table=&session->channel_table;
    unsigned int hashvalue = 0;

    if (channel) {

	if (channel->list.next) return channel->list.next;
	hashvalue = (channel->local_channel % CHANNELS_TABLE_SIZE) + 1;
	if (hashvalue==CHANNELS_TABLE_SIZE) return NULL;
	channel=NULL;

    }

    for (unsigned int i=hashvalue; i<CHANNELS_TABLE_SIZE; i++) {

	channel=table->hash[i].head;
	if (channel) break;

    }

    return channel;

}

void table_add_channel(struct ssh_channel_s *channel)
{
    unsigned int hashvalue=0;
    struct channel_table_s *table=&channel->session->channel_table;
    struct channellist_head_s *list_head=NULL;

    if (channel->flags & CHANNEL_FLAG_TABLE) return;

    if (table->latest_channel==0) {

	channel->local_channel=table->latest_channel;
	table->latest_channel++;

    } else {
	unsigned int local_channel=0;

	/* try a free local channel */

	while (lookup_session_channel(table, local_channel)) local_channel++;

	channel->local_channel=local_channel;
	if (local_channel==table->latest_channel) table->latest_channel++;

    }

    hashvalue = (channel->local_channel % CHANNELS_TABLE_SIZE);
    list_head=&table->hash[hashvalue];

    if (list_head->head==NULL) {

	list_head->head=channel;
	list_head->tail=channel;

    } else {
	struct ssh_channel_s *first=list_head->head;

	channel->list.next=first;
	first->list.prev=channel;
	list_head->head=channel;

    }

    table->count++;
    channel->flags|=CHANNEL_FLAG_TABLE;

}

void table_remove_channel(struct ssh_channel_s *channel)
{
    struct ssh_session_s *session=channel->session;
    struct channel_table_s *table=&session->channel_table;
    unsigned int hashvalue=0;
    struct channellist_head_s *list_head=NULL;

    if (!(channel->flags & CHANNEL_FLAG_TABLE)) return;

    hashvalue=channel->local_channel % CHANNELS_TABLE_SIZE;
    list_head=&table->hash[hashvalue];

    if (list_head->head==channel) {

	if (list_head->tail==channel) {

	    list_head->head=NULL;
	    list_head->tail=NULL;

	} else {
	    struct ssh_channel_s *next=channel->list.next;

	    list_head->head=next;
	    next->list.prev=NULL;

	}

    } else {

	if (list_head->tail==channel) {
	    struct ssh_channel_s *prev=channel->list.prev;

	    list_head->tail=prev;
	    prev->list.next=NULL;

	} else {
	    struct ssh_channel_s *next=channel->list.next;
	    struct ssh_channel_s *prev=channel->list.prev;

	    prev->list.next=next;
	    next->list.prev=prev;

	}

    }

    channel->list.next=NULL;
    channel->list.prev=NULL;
    table->count--;
    channel->flags-=CHANNEL_FLAG_TABLE;

}

int add_channel(struct ssh_channel_s *channel, unsigned int flags)
{
    struct ssh_session_s *session=channel->session;
    struct channel_table_s *table=&session->channel_table;
    int result=-1;
    struct simple_lock_s wlock;

    /* protect the handling of adding/removing channels */

    channeltable_writelock(table, &wlock);
    table_add_channel(channel);
    channeltable_unlock(table, &wlock);

    if (flags & CHANNEL_FLAG_OPEN) {
	unsigned int error=0;

	result=0;

	if ((* channel->start)(channel, &error)==-1) {

	    channeltable_writelock(table, &wlock);
	    table_remove_channel(channel);
	    channeltable_unlock(table, &wlock);
	    result=-1;

	}

    } else {

	result=0;

    }

    return result;

}

void remove_channel(struct ssh_channel_s *channel, unsigned int flags)
{
    struct ssh_session_s *session=channel->session;
    struct channel_table_s *table=&session->channel_table;
    struct simple_lock_s wlock;

    /* protect the handling of adding/removing channels */

    if (flags & (CHANNEL_FLAG_CLIENT_CLOSE | CHANNEL_FLAG_SERVER_CLOSE)) {

	(* channel->close)(channel, flags);

    }

    channeltable_writelock(table, &wlock);
    table_remove_channel(channel);
    channeltable_unlock(table, &wlock);

}
