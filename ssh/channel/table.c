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
#include "ssh-connections.h"
#include "ssh-channel.h"

struct ssh_channel_s *lookup_session_channel_for_payload(struct channel_table_s *table, unsigned int nr, struct ssh_payload_s **p_payload)
{
    unsigned int hashvalue = nr % CHANNELS_TABLE_SIZE;
    struct list_element_s *list=get_list_head(&table->hash[hashvalue], 0);
    struct ssh_channel_s *channel=NULL;

    while (list) {

	channel=(struct ssh_channel_s *)(((char *)list) - offsetof(struct ssh_channel_s, list));

	if (channel->local_channel==nr) {

	    queue_ssh_payload_channel(channel, *p_payload);
	    *p_payload=NULL;
	    break;

	}

	list=get_next_element(list);
	channel=NULL;

    }

    return channel;
}

struct ssh_channel_s *lookup_session_channel_for_data(struct channel_table_s *table, unsigned int nr, struct ssh_payload_s **p_payload)
{
    unsigned int hashvalue = nr % CHANNELS_TABLE_SIZE;
    struct list_element_s *list=get_list_head(&table->hash[hashvalue], 0);
    struct ssh_channel_s *channel=NULL;

    while (list) {

	channel=(struct ssh_channel_s *)(((char *)list) - offsetof(struct ssh_channel_s, list));

	if (channel->local_channel==nr) {
	    struct ssh_payload_s *payload=*p_payload;

	    (* channel->process_incoming_bytes)(channel, payload->len);
	    (* channel->receive_msg_channel_data)(channel, p_payload);
	    break;

	}

	list=get_next_element(list);
	channel=NULL;

    }

    return channel;
}

struct ssh_channel_s *lookup_session_channel_for_flag(struct channel_table_s *table, unsigned int nr, unsigned int flag)
{
    unsigned int hashvalue = nr % CHANNELS_TABLE_SIZE;
    struct list_element_s *list=get_list_head(&table->hash[hashvalue], 0);
    struct ssh_channel_s *channel=NULL;

    while (list) {

	channel=(struct ssh_channel_s *)(((char *)list) - offsetof(struct ssh_channel_s, list));

	if (channel->local_channel==nr) {

	    pthread_mutex_lock(&channel->mutex);
	    channel->flags |= flag;
	    pthread_mutex_unlock(&channel->mutex);
	    break;

	}

	list=get_next_element(list);
	channel=NULL;

    }

    return channel;
}

struct ssh_channel_s *lookup_session_channel(struct channel_table_s *table, unsigned int nr)
{
    unsigned int hashvalue = nr % CHANNELS_TABLE_SIZE;
    struct list_element_s *list=get_list_head(&table->hash[hashvalue], 0);
    struct ssh_channel_s *channel=NULL;

    while (list) {

	channel=(struct ssh_channel_s *)(((char *)list) - offsetof(struct ssh_channel_s, list));
	if (channel->local_channel==nr) break;

	list=get_next_element(list);
	channel=NULL;

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

	init_list_header(&table->hash[i], SIMPLE_LIST_TYPE_EMPTY, NULL);
	// table->hash[i].head=NULL;
	// table->hash[i].tail=NULL;
    }

    init_simple_locking(&table->locking);
    table->lock=0;

}

void free_channels_table(struct ssh_session_s *session)
{
    struct channel_table_s *table=&session->channel_table;

    for (unsigned int i=0; i<CHANNELS_TABLE_SIZE; i++) {
	struct list_element_s *list=get_list_head(&table->hash[i], SIMPLE_LIST_FLAG_REMOVE);
	struct ssh_channel_s *channel=NULL;

	/* remove every element from the individual list headers */

	while (list) {

	    channel=(struct ssh_channel_s *)(((char *)list) - offsetof(struct ssh_channel_s, list));
	    (* channel->free)(channel);
	    list=get_list_head(&table->hash[i], SIMPLE_LIST_FLAG_REMOVE);

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
	struct list_element_s *list=get_list_head(&table->hash[i], 0);

	while (list) {

	    channel=(struct ssh_channel_s *)(((char *)list) - offsetof(struct ssh_channel_s, list));
	    if (channel->type==type) break;
	    list=get_next_element(list);
	    channel=NULL;

	}

    }

    return channel;

}

struct ssh_channel_s *get_next_channel(struct ssh_session_s *session, struct ssh_channel_s *channel)
{
    struct channel_table_s *table=&session->channel_table;
    unsigned int hashvalue = 0;
    struct list_element_s *list=NULL;

    if (channel) {

	list=get_next_element(&channel->list);
	if (list) return (struct ssh_channel_s *)(((char *)list) - offsetof(struct ssh_channel_s, list));
	hashvalue = (channel->local_channel % CHANNELS_TABLE_SIZE) + 1; /* start at next row */
	if (hashvalue==CHANNELS_TABLE_SIZE) return NULL;

    }

    for (unsigned int i=hashvalue; i<CHANNELS_TABLE_SIZE; i++) {

	list=get_list_head(&table->hash[i], 0);
	if (list) return (struct ssh_channel_s *)(((char *)list) - offsetof(struct ssh_channel_s, list));
    }

    return NULL;

}

void table_add_channel(struct ssh_channel_s *channel)
{
    unsigned int hashvalue=0;
    struct ssh_session_s *session=channel->session;
    struct channel_table_s *table=&session->channel_table;

    logoutput("table_add_channel: add channel %i to table", channel->local_channel);

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
    add_list_element_first(&table->hash[hashvalue], &channel->list);
    table->count++;
    channel->flags|=CHANNEL_FLAG_TABLE;

}

void table_remove_channel(struct ssh_channel_s *channel)
{
    struct ssh_session_s *session=channel->session;
    struct channel_table_s *table=&session->channel_table;

    if ((channel->flags & CHANNEL_FLAG_TABLE)==0) return;

    remove_list_element(&channel->list);
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

    logoutput("add_channel: add channel to table");

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
