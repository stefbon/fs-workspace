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
#include <poll.h>
#include <sys/epoll.h>

#include "main.h"
#include "logging.h"
#include "workerthreads.h"

#include "utils.h"

#include "ssh-common.h"
#include "ssh-common-protocol.h"

#include "ssh-receive.h"
#include "ssh-utils.h"

/*
    common function to wait for a ssh_payload to arrive
    on a queue; this queue can be the transport queue used to setup a connection
    or the queue to handle key reexchange

*/

struct ssh_payload_s *get_ssh_payload(struct ssh_session_s *session, struct payload_queue_s *queue, struct timespec *expire, unsigned int *sequence, unsigned int *error)
{
    struct ssh_payload_s *payload=NULL;
    struct ssh_signal_s *signal=queue->signal;

    pthread_mutex_lock(signal->mutex);

    while (queue->list.head==NULL) {

	int result=pthread_cond_timedwait(signal->cond, signal->mutex, expire);

	if (result==ETIMEDOUT) {
	    struct fs_connection_s *connection=&session->connection;

	    pthread_mutex_unlock(signal->mutex);
	    *error=ETIMEDOUT;

	    /* is there a better error causing this timeout?
		the timeout is possibly caused by connection problems */

	    if (connection->status & FS_CONNECTION_FLAG_DISCONNECTED)
		*error=(connection->error>0) ? connection->error : ENOTCONN;

	    return NULL;

	} else if (signal->error>0 && sequence && *sequence==signal->sequence_number_error) {

	    pthread_mutex_unlock(signal->mutex);
	    *error=signal->error;

	    signal->sequence_number_error=0;
	    signal->error=0;

	    return NULL;

	} else {
	    struct fs_connection_s *connection=&session->connection;

	    /* it's possible that a broadcast is send cause of connection problems */

	    if (connection->status & FS_CONNECTION_FLAG_DISCONNECTED) {

		*error=(connection->error>0) ? connection->error : ENOTCONN;
		pthread_mutex_unlock(signal->mutex);
		return NULL;

	    }

	}

    }

    *error=0;
    payload=queue->list.head;

    if (payload->next) {

	queue->list.head=payload->next;
	payload->next=NULL;
	(* queue->process_payload_queue)(queue);

    } else {

	queue->list.head=NULL;
	queue->list.tail=NULL;

    }

    pthread_mutex_unlock(signal->mutex);
    return payload;

}

    /*
	queue a new payload when a packet is found in the buffer
	size:
	header: sizeof(struct ssh_payload)
	buffer: len buffer = packet->len - packet->padding - 1

	remember data coming from a ssh server looks like:
	uint32				packet_len
	byte				padding_len (=n2)
	byte[n1]			payload (n1 = packet_len - padding_len - 1)
	byte[n2]			padded bytes, filled with random
	byte[m]				mac (m = mac_len)

	when here mac and encryption are already processed, the payload is still compressed

	NOTE:
	- first byte of payload (buffer[5]) is type of ssh message
	- if compression is used the payload is still compressed

    */

void queue_ssh_payload(struct payload_queue_s *queue, struct ssh_payload_s *payload)
{
    struct ssh_signal_s *signal=NULL;

    signal=queue->signal;

    pthread_mutex_lock(signal->mutex);

    if (queue->list.tail) {

	/* put after last */

	queue->list.tail->next=payload;
	queue->list.tail=payload;

    } else {

	queue->list.head=payload;
	queue->list.tail=payload;

	(* queue->process_payload_queue)(queue);

    }

    pthread_mutex_unlock(signal->mutex);

}

void process_payload_queue_default(struct payload_queue_s *queue)
{
    pthread_cond_broadcast(queue->signal->cond);
}

void init_payload_queue(struct ssh_session_s *session, struct payload_queue_s *queue)
{

    queue->session=session;
    queue->list.head=NULL;
    queue->list.tail=NULL;
    queue->signal=&session->receive.signal;
    queue->process_payload_queue=process_payload_queue_default;
    queue->ptr=NULL;

}
