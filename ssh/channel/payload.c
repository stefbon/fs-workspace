/*
  2017, 2018 Stef Bon <stefbon@gmail.com>

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
#include "common-utils/utils.h"

#include "ssh-common-protocol.h"
#include "ssh-common.h"
#include "ssh-channel.h"
#include "ssh-utils.h"

struct ssh_payload_s *get_ssh_payload_channel(struct ssh_channel_s *channel, struct timespec *expire, unsigned int *seq, unsigned int *error)
{
    struct payload_queue_s *queue=&channel->payload_queue;
    struct ssh_signal_s *signal=queue->signal;
    int result=0;
    struct ssh_payload_s *payload=NULL;

    if (channel->flags & (CHANNEL_FLAG_SERVER_CLOSE | CHANNEL_FLAG_SERVER_EOF | CHANNEL_FLAG_OPENFAILURE)) {

	*error=ENOTCONN;
	return NULL;

    }

    logoutput("get_ssh_payload_channel");

    pthread_mutex_lock(signal->mutex);

    while (queue->list.head==NULL) {

	result=pthread_cond_timedwait(signal->cond, signal->mutex, expire);

	if (queue->list.head) {

	    break;

	} else if (result==ETIMEDOUT) {
	    struct fs_connection_s *connection=&channel->session->connection;

	    pthread_mutex_unlock(signal->mutex);
	    *error=ETIMEDOUT;
	    if (connection->status & (FS_CONNECTION_FLAG_DISCONNECTED | FS_CONNECTION_FLAG_DISCONNECTING)) {

		*error=(connection->error>0) ? connection->error : ENOTCONN;

	    }

	    return NULL;

	} else if (signal->error>0 && seq && *seq==signal->sequence_number_error) {

	    *error=signal->error;
	    pthread_mutex_unlock(signal->mutex);
	    return NULL;

	} else {
	    struct fs_connection_s *connection=&channel->session->connection;

	    if (connection->status & FS_CONNECTION_FLAG_DISCONNECTED) {

		*error=(connection->error>0) ? connection->error : ENOTCONN;
		pthread_mutex_unlock(signal->mutex);
		return NULL;

	    } else if (channel->flags & (CHANNEL_FLAG_SERVER_CLOSE | CHANNEL_FLAG_SERVER_EOF)) {

		pthread_mutex_unlock(signal->mutex);
		*error=ENOTCONN;
		return NULL;

	    }

	}

    }

    /* when here there is payload on the channel list */

    *error=0;
    payload=queue->list.head;

    if (payload->next) {
	struct ssh_payload_s *next=payload->next;

	next->prev=NULL;
	queue->list.head=next;

    } else {

	queue->list.head=NULL;
	queue->list.tail=NULL;

    }

    pthread_mutex_unlock(signal->mutex);

    payload->next=NULL;
    payload->prev=NULL;

    return payload;

}

void queue_ssh_payload_channel(struct ssh_channel_s *channel, struct ssh_payload_s *payload)
{
    struct payload_queue_s *queue=&channel->payload_queue;
    struct ssh_signal_s *signal=queue->signal;

    payload->next=NULL;
    payload->prev=NULL;

    logoutput("queue_ssh_payload_channel");

    pthread_mutex_lock(signal->mutex);

    if (queue->list.tail) {
	struct ssh_payload_s *last=queue->list.tail;

	/* put after last */

	last->next=payload;
	payload->prev=last;
	queue->list.tail=payload;

    } else {

	queue->list.head=payload;
	queue->list.tail=payload;

	pthread_cond_broadcast(signal->cond);

    }

    pthread_mutex_unlock(signal->mutex);

}

