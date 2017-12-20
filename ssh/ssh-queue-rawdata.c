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

/*
    copy buffer of the next rawdata in the queue to the current one
    remove next from queue only if all data in buffer is copied
    leave it on the queue when only a part
*/

static struct rawdata_s *copy_buffer_next_data(struct rawdata_queue_s *r_queue, struct rawdata_s *data, struct rawdata_s *next)
{

    if (next->size + data->size <= data->len) {

	/* fits in buffer */

	memcpy(data->buffer + data->size, next->buffer, next->size);
	data->size+=next->size;

	data->next=next->next;

	/* free next and repair queue */
	free(next);
	next=data->next;
	if (! next) r_queue->last=data;

    } else {
	unsigned int left=data->len - data->size;

	/* more data available (does this happen?) */

	memcpy(data->buffer + data->size, next->buffer, left);
	data->size+=left;

	memmove(next->buffer, next->buffer + left, next->size - left);
	next->size-=left;

	next=NULL;

    }

    return next;
}

static int wait_additional_data(struct rawdata_queue_s *r_queue, struct rawdata_s *data)
{
    struct rawdata_s *next=data->next;
    int result=0;

    /* append already queued data */

    while (next && data->size < data->len) {

	next=copy_buffer_next_data(r_queue, data, next);

    }

    if (data->size<data->len) {
	struct timespec expire;

	/* not enough: wait for additional data */

	get_current_time(&expire);
	expire.tv_sec+=4;

	while (data->size < data->len) {

	    result=pthread_cond_timedwait(&r_queue->cond, &r_queue->mutex, &expire);

	    next=data->next;

	    while (next && data->size < data->len) {

		next=copy_buffer_next_data(r_queue, data, next);

	    }

	    if (data->size >= data->len) {

		break;

	    } else if (result==ETIMEDOUT) {

		result=-1;
		break;

	    }

	}

    }

    return result;
}

/*	process incoming data on the receive queue
    after decryption and checking the mac queue the payload
    note this works also when mac and encryption are not used */

static void process_rawdata_session(struct rawdata_s *data)
{
    struct ssh_session_s *session=data->session;
    struct ssh_receive_s *receive=&session->receive;
    struct payload_queue_s *payload_queue=&receive->payload_queue;
    struct ssh_packet_s packet;
    unsigned int size_firstbytes=get_size_firstbytes(session);
    unsigned char firstbytes[size_firstbytes];

    getpacket:

    packet.sequence=payload_queue->sequence_number;
    packet.error=0;
    payload_queue->sequence_number++;

    data->sequence=packet.sequence;

    /* decrypt first block to know the packet length */

    if (ssh_decrypt_length(data, firstbytes, size_firstbytes)==0) {
	unsigned int maclen=get_maclen_s2c(session);

	packet.len=get_uint32(firstbytes);
	data->len=packet.len + 4 + maclen;
	data->maclen=maclen;

	if (data->len > 35000) {

	    logoutput_warning("process_rawdata_session: data length %i too big", data->len);
	    goto disconnect;

	} else if (data->len > data->size) {
	    struct rawdata_queue_s *r_queue=&receive->rawdata_queue;
	    struct timespec expire;
	    struct rawdata_s *next=NULL;
	    struct rawdata_s *keep=NULL;

	    logoutput("process_rawdata_session: data length %i bigger than size %i", data->len, data->size);

	    /* length bigger than current size: wait for additional data to recv */

	    pthread_mutex_lock(&r_queue->mutex);

	    next=data->next;
	    keep=data;

	    /* resize buffer to required length */

	    data=realloc(data, sizeof(struct rawdata_s) + data->len);

	    if (! data) {

		/* not enough memory: disconnect */
		/* repair the queue */

		if (next) {

		    r_queue->first=next;

		} else {

		    r_queue->last=NULL;
		    r_queue->first=NULL;

		}

		pthread_mutex_unlock(&r_queue->mutex);
		goto disconnect;

	    }

	    /* take into account the address of data may have been changed */

	    if (data!=keep) {

		if (r_queue->last==r_queue->first) r_queue->last=data;
		r_queue->first=data;

	    }

	    if (wait_additional_data(r_queue, data)==-1) {

		logoutput_warning("process_rawdata_session: error waiting for full packet");
		pthread_mutex_unlock(&r_queue->mutex);
		goto disconnect;

	    }

	    pthread_mutex_unlock(&r_queue->mutex);

	}

	/* do mac/tag checking when "before decrypting" is used */

	if (verify_mac_pre_decrypt(data)==0) {

	    memcpy(data->buffer, firstbytes, size_firstbytes);

	    /* decrypt rest */

	    if (ssh_decrypt_packet(data)==0) {

		packet.buffer=data->buffer;
		packet.padding=(unsigned char) *(data->buffer + 4);

		/* do mac checking when "after decrypting" is used */

		if (verify_mac_post_decrypt(data)==0) {

		    /* create packet and queue it */

		    /* TODO: get the type of the packet: this is (unsigned char) packet.buffer[5]
			if this is newkeys then switch the s2c keys/ciphers/mac/iv and set a condition var to block the incoming messages after this one
			(crypto->state??? for example)
		    */

		    logoutput("process_rawdata_session: received %i", (unsigned char) packet.buffer[5]);

		    if ((unsigned char) packet.buffer[5] == SSH_MSG_NEWKEYS) {
			struct keyexchange_s *keyexchange=session->keyexchange;

			logoutput("process_rawdata_session: received newkeys");

			if (keyexchange==NULL) {

			    logoutput("process_rawdata_session: keyexchange not initialized.... error");
			    goto disconnect;

			} else {

			    pthread_mutex_lock(&keyexchange->mutex);
			    keyexchange->keydata.status|=KEYEXCHANGE_STATUS_NEWKEYS_S2C;
			    pthread_cond_broadcast(&keyexchange->cond);
			    pthread_mutex_unlock(&keyexchange->mutex);

			}

			set_decryption_newkeys_wait(session);

			logoutput("process_rawdata_session: continue");

		    } else {

			queue_ssh_packet(session, &packet);

		    }

		} else {

		    logoutput_warning("process_rawdata_session: error check mac post");
		    reset_s2c_mac(session);
		    goto disconnect;

		}

		// reset_s2c_mac(session);

	    } else {

		logoutput_warning("process_rawdata_session: error decrypt");
		goto disconnect;

	    }

	} else {

	    logoutput_warning("process_rawdata_session: error check mac pre");
	    goto disconnect;

	}

    } else {

	logoutput_warning("process_rawdata_session: error decrypt");
	goto disconnect;

    }

    /* more packets in one batch ?*/

    if (data->len < data->size) {

	memmove(data->buffer, data->buffer + data->len, data->size - data->len);
	data->size-=data->len;
	goto getpacket;

    }

    return;

    disconnect:

    logoutput_warning("process_rawdata_session: ignoring received data");
    disconnect_ssh_session(session, 0, SSH_DISCONNECT_BY_APPLICATION);

}

static void process_rawdata_init(struct rawdata_s *data)
{
    struct ssh_session_s *session=data->session;
    struct ssh_receive_s *receive=&session->receive;
    struct payload_queue_s *p_queue=&receive->payload_queue;
    struct ssh_packet_s packet;

    getpacket:

    packet.sequence=p_queue->sequence_number;
    packet.error=0;
    p_queue->sequence_number++;

    packet.buffer=data->buffer;
    packet.len=get_uint32(data->buffer);
    packet.padding=(unsigned char) *(data->buffer+4);

    data->len=packet.len + 4; /* plus maclen */

    if (data->len > 35000) {

	logoutput_warning("process_rawdata_init: packet length %i too big", data->len);
	goto disconnect;

    } else if (data->len > data->size) {
	struct rawdata_queue_s *r_queue=&receive->rawdata_queue;
	struct timespec expire;
	struct rawdata_s *next=NULL;
	struct rawdata_s *prev=NULL;

	/* wait for more data to arrive
	    note the rawdata stays on the rawdata queue until it's completly processed */

	pthread_mutex_lock(&r_queue->mutex);

	next=data->next;

	/* resize buffer to required length */

	data=realloc(data, sizeof(struct rawdata_s) + data->len - 1);

	if (! data) {

	    /* not enough memory: disconnect */
	    /* repair the queue */

	    if (next) {

		r_queue->first=next;

	    } else {

		r_queue->last=NULL;
		r_queue->first=NULL;

	    }

	    pthread_mutex_unlock(&r_queue->mutex);
	    goto disconnect;

	}

	if (r_queue->last==r_queue->first) r_queue->last=data;
	r_queue->first=data;

	if (wait_additional_data(r_queue, data)==-1) {

	    logoutput_warning("process_rawdata_init: error waiting for full packet");
	    pthread_mutex_unlock(&r_queue->mutex);
	    goto disconnect;

	}

	pthread_mutex_unlock(&r_queue->mutex);

    }

    /* queue it as payload */

    queue_ssh_packet(session, &packet);

    /* more packets in one buffer ? */

    if (data->len < data->size) {

	/* resize the buffer */

	memmove(data->buffer, data->buffer + data->len, data->size - data->len);
	data->size-=data->len;

	goto getpacket;

    }

    return;

    error:

    logoutput_warning("process_rawdata_init: ignoring received data");

    disconnect:

    disconnect_ssh_session(session, 0, SSH_DISCONNECT_BY_APPLICATION);

}

/*
    read the first data from server
    this is the greeter
    take in account the second ssh message can be attached
*/

static void process_rawdata_greeter(struct rawdata_s *data)
{

    /* when receiving the first data switch immediatly the function to process the incoming data */

    if (read_server_greeter(data)==0) {
	struct ssh_session_s *session=data->session;

	/* send signal to wake up the waiting thread which has send the greeter
	    and wait's for the server's greeter */

	signal_reply_server(data->session);
	switch_process_rawdata_queue(session, "init");

    } else {

	logoutput_warning("process_rawdata_greeter: not able to read server greeter");
	return;

    }

    if (data->len < data->size) {
	struct ssh_receive_s *receive=&data->session->receive;
	struct rawdata_queue_s *queue=&receive->rawdata_queue;

	/* first packet included */

	memmove(data->buffer, (unsigned char *) (data->buffer + data->len), (size_t) (data->size - data->len));
	data->size-=data->len; /* pretend it's smaller */
	data->len=0;

	(* queue->process_rawdata)(data);

    }

}

/*
    process the queue of rawdata
    typically called within seperate thread
*/

static void process_queued_rawdata(void *ptr)
{
    struct ssh_session_s *session=(struct ssh_session_s *) ptr;
    struct rawdata_s *data=NULL;
    struct ssh_receive_s *receive=&session->receive;
    struct rawdata_queue_s *queue=&receive->rawdata_queue;
    void (* process_rawdata) (struct rawdata_s *data);

    readqueue:

    pthread_mutex_lock(&queue->mutex);

    /* here a wait loop with pthread_cond_wait for checking the condition the cryptoengine for
	decrypting is ready (especially after kexinit/newkeys)
	how does this condition look like? */

    process_rawdata=queue->process_rawdata;

    /* first process and leave it on the queue */

    data=queue->first;

    if (data) {

	pthread_mutex_unlock(&queue->mutex);

	/*
	    process the data 
	    what this does depends on the phase
	    - first data: greeter
	    - next data in init phase: read the packets (it's possible that there are more packets in one batch)
	    - next data in session phase: decrypt and check mac, and read packets
	*/

	(*process_rawdata)(data);

    } else {

	pthread_mutex_unlock(&queue->mutex);
	return;

    }

    /*
	when ready: take it of the queue and free it
	note that data may be reallocated: take the first of the queue again
    */

    pthread_mutex_lock(&queue->mutex);

    data=queue->first;

    if (data->next) {

	queue->first=data->next;

    } else {

	queue->first=NULL;
	queue->last=NULL;

    }

    pthread_mutex_unlock(&queue->mutex);
    free(data);

    goto readqueue;

}

static void start_queue_thread(struct ssh_session_s *session)
{
    unsigned int error=0;
    work_workerthread(NULL, 0, process_queued_rawdata, (void *) session, &error);
}


/* queue data read from the fd in the "raw data queue" and start a thread to process it (when it's the first)
*/

void queue_ssh_data(struct ssh_session_s *session, unsigned char *buffer, unsigned int len)
{
    struct rawdata_s *data=NULL;

    data=malloc(sizeof(struct rawdata_s) + len);

    if (data) {
	struct ssh_receive_s *receive=&session->receive;
	struct rawdata_queue_s *r_queue=&receive->rawdata_queue;

	memcpy(data->buffer, buffer, len);

	data->size=len;
	data->len=0;
	data->decrypted=0;
	data->session=session;
	data->next=NULL;

	pthread_mutex_lock(&r_queue->mutex);

	if ( r_queue->last) {

	    /* put it after last */

	    r_queue->last->next=data;
	    r_queue->last=data;

	    /* signal any waiting thread when first is incomplete */

	    pthread_cond_broadcast(&r_queue->cond);

	} else {

	    r_queue->last=data;
	    r_queue->first=data;

	    /* start a thread to process the received data */

	    start_queue_thread(session);

	}

	pthread_mutex_unlock(&r_queue->mutex);

    } else {
	unsigned int error=0;

	error=ENOMEM;
	logoutput_error("queue_ssh_data: error %i:%s", error, strerror(error));

	/* TODO: disconnect */

    }

}

static void ignore_ssh_data(struct ssh_session_s *session, unsigned char *buffer, unsigned int len)
{
}

void stop_receive_data(struct ssh_session_s *session)
{
    struct ssh_receive_s *receive=&session->receive;
    struct rawdata_queue_s *queue=&receive->rawdata_queue;

    queue->queue_ssh_data=ignore_ssh_data;
}

void switch_process_rawdata_queue(struct ssh_session_s *session, const char *phase)
{
    struct ssh_receive_s *receive=&session->receive;
    struct rawdata_queue_s *queue=&receive->rawdata_queue;

    pthread_mutex_lock(&queue->mutex);

    logoutput("switch_process_rawdata_queue: set phase %s", phase);

    if (strcmp(phase, "greeter")==0) {

	queue->process_rawdata=process_rawdata_greeter;

    } else if (strcmp(phase, "init")==0) {

	// queue->process_rawdata=process_rawdata_init;
	queue->process_rawdata=process_rawdata_session;

    } else if (strcmp(phase, "session")==0) {

	queue->process_rawdata=process_rawdata_session;

    } else if (strcmp(phase, "none")==0) {

	queue->queue_ssh_data=ignore_ssh_data;

    }

    pthread_mutex_unlock(&queue->mutex);

}

void init_receive_rawdata_queue(struct ssh_session_s *session)
{
    struct ssh_receive_s *receive=&session->receive;
    struct rawdata_queue_s *queue=&receive->rawdata_queue;

    queue->first=NULL;
    queue->last=NULL;

    pthread_mutex_init(&queue->mutex, NULL);
    pthread_cond_init(&queue->cond, NULL);

    queue->queue_ssh_data=queue_ssh_data;

    switch_process_rawdata_queue(session, "greeter");

}

void clean_receive_rawdata_queue(struct ssh_receive_s *receive)
{
    struct rawdata_queue_s *queue=&receive->rawdata_queue;

    if (queue->first) {
	struct rawdata_s *data=queue->first;

	while (data) {

	    queue->first=data->next;
	    free(data);
	    data=queue->first;

	}

    }

}

void free_receive_rawdata_queue(struct ssh_receive_s *receive)
{
    struct rawdata_queue_s *queue=&receive->rawdata_queue;

    pthread_mutex_destroy(&queue->mutex);
    pthread_cond_destroy(&queue->cond);

}
