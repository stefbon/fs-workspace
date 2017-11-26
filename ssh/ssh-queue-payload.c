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
#include <poll.h>
#include <sys/epoll.h>

#include "logging.h"
#include "main.h"
#include "workerthreads.h"

#include "utils.h"

#include "ssh-common.h"
#include "ssh-common-protocol.h"

#include "ssh-receive.h"
#include "ssh-receive-greeter.h"
#include "ssh-receive-transport.h"
#include "ssh-receive-userauth.h"
#include "ssh-receive-channel.h"
#include "ssh-receive-waitreply.h"

#include "ssh-queue-rawdata.h"
#include "ssh-queue-payload.h"

#include "ssh-mac.h"
#include "ssh-encryption.h"
#include "ssh-connection.h"
#include "ssh-compression.h"

#include "ssh-utils.h"

extern void process_ssh_message(struct ssh_session_s *session, struct ssh_payload_s *payload);

/*
    wait for a ssh_payload to arrive
    - session
    - expire time whem wait expires
    - sequence number of message send, possible a not supported message is returned with this number
    - *error, value wil be set when payload not found or original operation is not supported
*/

struct ssh_payload_s *get_ssh_payload(struct ssh_session_s *session, struct timespec *expire, unsigned int *sequence, unsigned int *error)
{
    struct ssh_receive_s *receive=&session->receive;
    struct payload_queue_s *queue=&receive->payload_queue;
    int result=0;
    struct ssh_payload_s *payload=NULL;
    unsigned int len=0;

    pthread_mutex_lock(queue->signal.mutex);

    while (queue->first==NULL) {

	result=pthread_cond_timedwait(queue->signal.cond, queue->signal.mutex, expire);

	if (result==ETIMEDOUT) {

	    pthread_mutex_unlock(queue->signal.mutex);
	    *error=ETIMEDOUT;
	    return NULL;

	} else if (sequence && *sequence==queue->signal.sequence_number_error) {

	    pthread_mutex_unlock(queue->signal.mutex);
	    *error=queue->signal.error;

	    queue->signal.sequence_number_error=0;
	    queue->signal.error=0;

	    return NULL;

	}

    }

    *error=0;
    payload=queue->first;

    if (payload->next) {

	queue->first=payload->next;
	payload->next=NULL;
	(* queue->process_payload_queue)(session);

    } else {

	queue->first=NULL;
	queue->last=NULL;

    }

    pthread_mutex_unlock(queue->signal.mutex);

    payload->type=(unsigned char) payload->buffer[0];

    logoutput("get_ssh_payload: (%i) type %i", gettid(), payload->type);

    return payload;

}

/* when in session phase, get the payload from queue and process the cb associated with the message number */

static void process_queued_payload(void *ptr)
{
    struct ssh_session_s *session=(struct ssh_session_s *) ptr;
    struct ssh_payload_s *payload=NULL;
    struct timespec expire;
    unsigned int error=0;

    get_session_expire_session(session, &expire);
    payload=get_ssh_payload(session, &expire, NULL, &error);

    if (payload) {

	process_ssh_message(session, payload);

    }

}

/* when in the init phase, signal the thread which is busy setting up a session a new payload has arrived
    (remove IGNORE and DEBUG messages) */

static void process_payload_queue_init(struct ssh_session_s *session)
{
    struct ssh_receive_s *receive=&session->receive;
    struct payload_queue_s *queue=&receive->payload_queue;
    struct ssh_payload_s *payload=NULL;

    /* in the init phase (before the newkeys) there is no compression
	so it's possible to read the contents */

    payload=queue->first;

    if (payload) {

	payload->type=(unsigned char) payload->buffer[0];

	if (payload->type==SSH_MSG_UNIMPLEMENTED) {

	    /* get from queue and signal */

	    if (payload->next) {

		queue->first=payload->next;

	    } else {

		queue->first=NULL;
		queue->last=NULL;

	    }

	    queue->signal.sequence_number_error=get_uint32(&payload->buffer[1]);
	    queue->signal.error=EOPNOTSUPP;
	    free(payload);

	    pthread_cond_broadcast(queue->signal.cond);

	} else if (payload->type==SSH_MSG_IGNORE || payload->type==SSH_MSG_DEBUG) {

	    if (payload->next) {

		queue->first=payload->next;

	    } else {

		queue->first=NULL;
		queue->last=NULL;

	    }

	    free(payload);

	} else {

	    pthread_cond_broadcast(queue->signal.cond);

	}

    }

}

/* when in the full session phase start a thread to process the payload futher to take the right action */

static void process_payload_queue_session(struct ssh_session_s *session)
{
    unsigned int error=0;
    work_workerthread(NULL, 0, process_queued_payload, (void *) session, &error);
}

/* when in a disconnect phase remove everything */

static void process_payload_queue_disconnect(struct ssh_session_s *session)
{
    /* TODO */
}

/* queue data read from the rawdata queue on the payload queue
*/

void queue_ssh_packet(struct ssh_session_s *session, struct ssh_packet_s *packet)
{
    struct ssh_payload_s *payload=NULL;
    unsigned int len=packet->len - packet->padding - 1;

    /*
	allocate a new payload when a packet is found in the buffer
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

    */

    payload=malloc(sizeof(struct ssh_payload_s) + len);

    if (payload) {
	struct ssh_receive_s *receive=&session->receive;
	struct payload_queue_s *queue=&receive->payload_queue;

	memset(payload, 0, sizeof(struct ssh_payload_s) + len);

	payload->type=0;
	payload->len=len;
	payload->sequence=packet->sequence;
	payload->next=NULL;
	payload->prev=NULL;

	memcpy(payload->buffer, packet->buffer + 5, len);

	pthread_mutex_lock(queue->signal.mutex);

	if (queue->last) {

	    /* put after last */

	    queue->last->next=payload;
	    queue->last=payload;

	} else {

	    queue->last=payload;
	    queue->first=payload;

	    /* depending the phase (init or session) what to do? */

	    (* queue->process_payload_queue)(session);

	}

	pthread_mutex_unlock(queue->signal.mutex);

    } else {

	logoutput_warning("queue_ssh_packet: error allocating new ssh payload");

    }

}

void switch_process_payload_queue(struct ssh_session_s *session, const char *phase)
{
    struct ssh_receive_s *receive=&session->receive;
    struct payload_queue_s *queue=&receive->payload_queue;

    if (strcmp(phase, "init")==0 || strcmp(phase, "greeter")==0) {

	queue->process_payload_queue=process_payload_queue_init;

    } else if (strcmp(phase, "session")==0) {

	queue->process_payload_queue=process_payload_queue_session;

    }

}

int init_receive_payload_queue(struct ssh_session_s *session, pthread_mutex_t *mutex, pthread_cond_t *cond)
{
    struct ssh_receive_s *receive=&session->receive;
    struct payload_queue_s *queue=&receive->payload_queue;

    queue->first=NULL;
    queue->last=NULL;
    queue->sequence_number=0;

    queue->signal.sequence_number_error=0;
    queue->signal.error=0;

    queue->signal.signal_allocated=0;

    /* if mutex and cond for signalling already defined use these */

    if (mutex && cond) {

	queue->signal.mutex=mutex;
	queue->signal.cond=cond;

	switch_process_payload_queue(session, "init");

	return 0;

    }

    queue->signal.mutex=malloc(sizeof(pthread_mutex_t));
    queue->signal.cond=malloc(sizeof(pthread_cond_t));

    if (queue->signal.mutex && queue->signal.cond) {

	queue->signal.signal_allocated=1;

	pthread_mutex_init(queue->signal.mutex, NULL);
	pthread_cond_init(queue->signal.cond, NULL);

	switch_process_payload_queue(session, "init");

	return 0;

    }

    if (queue->signal.mutex) {

	free(queue->signal.mutex);
	queue->signal.mutex=NULL;

    }

    if (queue->signal.cond) {

	free(queue->signal.cond);
	queue->signal.cond=NULL;

    }

    return -1;

}

void free_receive_payload_queue(struct ssh_receive_s *receive)
{
    struct payload_queue_s *queue=&receive->payload_queue;

    if (queue->signal.signal_allocated==1) {

	if (queue->signal.mutex) {

	    pthread_mutex_destroy(queue->signal.mutex);
	    free(queue->signal.mutex);
	    queue->signal.mutex=NULL;

	}

	if (queue->signal.cond) {

	    pthread_cond_destroy(queue->signal.cond);
	    free(queue->signal.cond);
	    queue->signal.cond=NULL;

	}

    }

}

void clean_receive_payload_queue(struct ssh_receive_s *receive)
{
    struct payload_queue_s *queue=&receive->payload_queue;

    if (queue->first) {
	struct ssh_payload_s *payload=queue->first;

	while (payload) {

	    queue->first=payload->next;
	    free(payload);
	    payload=queue->first;

	}

    }

}
