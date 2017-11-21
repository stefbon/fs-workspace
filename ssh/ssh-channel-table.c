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

#include "logging.h"
#include "main.h"
#include "utils.h"

#include "ssh-common-protocol.h"
#include "ssh-common.h"
#include "ssh-channel.h"

void lock_channels_table(struct channel_table_s *table)
{
    pthread_mutex_lock(&table->mutex);
}

void unlock_channels_table(struct channel_table_s *table)
{
    pthread_mutex_unlock(&table->mutex);
}

struct ssh_channel_s *lookup_session_channel(struct channel_table_s *table, unsigned int nr)
{
    unsigned int hashvalue = nr % table->table_size;
    struct ssh_channel_s *channel=NULL;
    struct list_element_s *list=NULL;

    list=table->hash[hashvalue].head;

    while(list) {

	channel=get_containing_channel(list);
	if (channel->local_channel==nr) break;
	channel=NULL;
	list=list->next;

    }

    return channel;
}

void init_channels_table(struct ssh_session_s *session, unsigned int size)
{
    struct channel_table_s *table=&session->channel_table;

    table->latest_channel=0;
    table->count=0;
    table->table_size=size;
    table->admin=NULL;
    table->sftp=NULL;

    for (unsigned int i=0; i<size; i++) {

	table->hash[i].head=NULL;
	table->hash[i].tail=NULL;
    }

    pthread_mutex_init(&table->mutex, NULL);
    pthread_cond_init(&table->cond, NULL);
    table->lock=0;

}

void free_channels_table(struct ssh_session_s *session)
{
    struct channel_table_s *table=&session->channel_table;
    struct list_head_s *list_head=NULL;
    struct list_element_s *list=NULL;
    struct ssh_channel_s *channel=NULL;

    for (unsigned int i=0; i<table->table_size; i++) {

	list_head=&table->hash[i];
	list=get_list_head(&list_head->head, &list_head->tail);

	while(list) {

	    channel=get_containing_channel(list);
	    (* channel->free)(channel);
	    list=get_list_head(&list_head->head, &list_head->tail);

	}

    }

    pthread_mutex_destroy(&table->mutex);
    pthread_cond_destroy(&table->cond);

}

struct ssh_channel_s *find_channel(struct ssh_session_s *session, unsigned int type)
{
    struct channel_table_s *table=&session->channel_table;
    struct list_head_s *list_head=NULL;
    struct list_element_s *list=NULL;
    struct ssh_channel_s *channel=NULL;

    for (unsigned int i=0; i<table->table_size; i++) {

	list_head=&table->hash[i];
	list=list_head->head;

	while(list) {

	    channel=get_containing_channel(list);
	    if (channel->type==type) break;
	    list=list->next;
	    channel=NULL;

	}

    }

    return channel;

}