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
#include "ssh-connections.h"
#include "ssh-receive.h"
#include "ssh-utils.h"

/*
    common function to wait for a ssh_payload to arrive
    on a queue; this queue can be the transport queue used to setup a connection
    or the queue to handle key reexchange

*/

struct ssh_payload_s *get_ssh_payload(struct ssh_connection_s *connection, struct payload_queue_s *queue, struct timespec *expire, unsigned int *sequence, unsigned int *error)
{
    struct ssh_payload_s *payload=NULL;
    struct ssh_signal_s *signal=queue->signal;
    struct list_element_s *list=NULL;

    pthread_mutex_lock(signal->mutex);

    while ((list=get_list_head(&queue->header, SIMPLE_LIST_FLAG_REMOVE))==NULL && (connection->setup.flags & SSH_SETUP_FLAG_DISCONNECT)==0) {

	int result=pthread_cond_timedwait(signal->cond, signal->mutex, expire);

	if ((list=get_list_head(&queue->header, SIMPLE_LIST_FLAG_REMOVE))) {

	    break;

	} else if (result==ETIMEDOUT) {
	    struct fs_connection_s *conn=&connection->connection;

	    pthread_mutex_unlock(signal->mutex);
	    *error=ETIMEDOUT;

	    /* is there a better error causing this timeout?
		the timeout is possibly caused by connection problems */

	    if (conn->status & FS_CONNECTION_FLAG_DISCONNECT) *error=(conn->error>0) ? conn->error : ENOTCONN;
	    return NULL;

	} else if (signal->error>0 && sequence && *sequence==signal->sequence_number_error) {

	    pthread_mutex_unlock(signal->mutex);
	    *error=signal->error;
	    signal->sequence_number_error=0;
	    signal->error=0;

	    return NULL;

	} else if (connection->setup.flags & SSH_SETUP_FLAG_DISCONNECT) {

	    *error=ENOTCONN;
	    pthread_mutex_unlock(signal->mutex);
	    return NULL;

	}

    }

    *error=0;
    payload=(list) ?(struct ssh_payload_s *)(((char *) list) - offsetof(struct ssh_payload_s, list)) : NULL;
    pthread_cond_broadcast(signal->cond);
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

void queue_ssh_payload_locked(struct payload_queue_s *queue, struct ssh_payload_s *payload)
{
    struct ssh_signal_s *signal=queue->signal;

    add_list_element_last(&queue->header, &payload->list);
    pthread_cond_broadcast(queue->signal->cond);

}

void queue_ssh_payload(struct payload_queue_s *queue, struct ssh_payload_s *payload)
{
    struct ssh_signal_s *signal=queue->signal;

    pthread_mutex_lock(signal->mutex);
    queue_ssh_payload_locked(queue, payload);
    pthread_mutex_unlock(signal->mutex);

}

void init_payload_queue(struct ssh_connection_s *connection, struct payload_queue_s *queue)
{
    init_list_header(&queue->header, SIMPLE_LIST_TYPE_EMPTY, NULL);
    queue->signal=&connection->receive.signal;
    queue->ptr=NULL;
}

void clear_payload_queue(struct payload_queue_s *queue, unsigned char dolog)
{
    struct list_element_s *list=NULL;
    struct ssh_signal_s *signal=NULL;
    struct payload_queue_s tmp;

    logoutput("clear_payload_queue");

    if (queue==NULL) return;
    signal=queue->signal;

    /* copy the list to another place to empty it, so the original can be released asap */

    pthread_mutex_lock(signal->mutex);

    memcpy(&tmp, queue, sizeof(struct payload_queue_s));
    init_list_header(&queue->header, SIMPLE_LIST_TYPE_EMPTY, NULL);

    pthread_mutex_unlock(signal->mutex);

    getpayload:

    list=get_list_head(&tmp.header, SIMPLE_LIST_FLAG_REMOVE);

    if (list) {
	struct ssh_payload_s *payload=(struct ssh_payload_s *)(((char *) list) - offsetof(struct ssh_payload_s, list));

	if (dolog) logoutput("clear_payload_queue: found payload type %i size %i", payload->type, payload->len);
	free_payload(&payload);
	goto getpayload;

    }

}

struct ssh_payload_s *receive_message_common(struct ssh_connection_s *connection, int (* cb)(struct ssh_connection_s *connection, struct ssh_payload_s *payload), unsigned int *error)
{
    struct ssh_payload_s *payload=NULL;
    struct timespec expire;
    unsigned int sequence=0;

    get_ssh_connection_expire_init(connection, &expire);

    getkexinit:

    payload=get_ssh_payload(connection, &connection->setup.queue, &expire, &sequence, error);

    if (! payload) {

	logoutput("receive_message_common: error %i waiting for packet (%s)", *error, strerror(*error));

    } else if ((* cb)(connection, payload)==0) {

	logoutput("receive_message_common: received %i message", payload->type);

    } else {

	logoutput("receive_message_common: received unexpected message (type %i)", payload->type);
	free_payload(&payload);
	goto getkexinit;

    }

    return payload;

}
