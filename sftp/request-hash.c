/*
  2010, 2011, 2012, 2103, 2014, 2015 Stef Bon <stefbon@gmail.com>

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

#include "fuse-dentry.h"
#include "workspace-interface.h"
#include "fuse-interface.h"
#include "beventloop.h"
#include "beventloop-timer.h"

#include "ssh-common.h"
#include "common-protocol.h"
#include "common.h"
#include "fuse-sftp-fs-init.h"
#include "simple-list.h"

/*

    maintain a hash table to attach response/data from server to the sftp request id
    as defined in draft-ietf-secsh-filexfer this value is a uint32_t and part of the sftp message

    here a "request" is created everytime a message is send to the server for sftp requests
    this request is stored in hashtbale using the request id
    when a reply is coming from the server, the corresponding request in the hashtable is
    looked up, and the data is stored there, and the waiting thread is signalled

    17 June 2016
    ------------
    At this moment there is one hashtable per session. This is ok for now, but actually wrong.
    There has to be one hashtable per channel, and in theory there can be more channels per session.
    This is a TODO.

    2 August 2016
    -------------
    A hashtable per channel.
    Make the size of the hashtable a default defined here.

    28 November 2016
    ----------------
    Add a new status: FINISH
    and make the signal_sftp_received set this status

    08 January 2017
    ---------------
    Add the interrupted unique

*/

#define _REQUEST_STATUS_INIT			1
#define _REQUEST_STATUS_WAITING			2
#define _REQUEST_STATUS_RESPONSE		3
#define _REQUEST_STATUS_FINISH			4
#define _REQUEST_STATUS_TIMEOUT			5
#define _REQUEST_STATUS_INTERRUPT		6
#define _REQUEST_STATUS_ERROR			9

#define _HASHTABLE_SIZE_DEFAULT			64

struct hash_request_s {
    unsigned int		id;
    unsigned char		status;
    struct list_element_s	h_list;
    struct timespec		started;
    struct timespec		timeout;
    struct sftp_request_s	*sftp_r; /* the original call */
    unsigned char		(* fuse_request_interrupted)(struct hash_request_s *request);
};

static struct hash_request_s *get_containing_request_h(struct list_element_s *list)
{
    return (struct hash_request_s *)(((char *) list) - offsetof(struct hash_request_s, h_list));
}

/*
    lookup the request in the request group hash
    the request id is used
    the request is removed from the hash table when found
*/

static struct hash_request_s *lookup_request(struct sftp_send_hash_s *send_hash, unsigned int id)
{
    unsigned int hash=id % send_hash->tablesize;
    struct hash_request_s *request=NULL;
    struct list_header_s *table=(struct list_header_s *) send_hash->hashtable;
    struct list_element_s *list=NULL;

    //logoutput("lookup_request");

    list=get_list_head(&table[hash], 0);

    while (list) {

	request=get_containing_request_h(list);

	if (request->id==id) {

	    remove_list_element(list);
	    break;

	}

	list=get_next_element(list);
	request=NULL;

    }

    return request;

}

/* initialize the hash table per sftp subsystem */

static int init_request_group(struct sftp_send_hash_s *send_hash, unsigned int *error)
{

    send_hash->tablesize=_HASHTABLE_SIZE_DEFAULT;
    send_hash->hashtable=(void *) malloc(send_hash->tablesize * sizeof(struct list_header_s));

    if (send_hash->hashtable) {
	struct list_header_s *table=(struct list_header_s *) send_hash->hashtable;

	for (unsigned int i=0; i<send_hash->tablesize; i++) init_list_header(&table[i], SIMPLE_LIST_TYPE_EMPTY, NULL);
	return 0;

    }

    *error=ENOMEM;
    return -1;

}

static void free_request_group(struct sftp_send_hash_s *send_hash)
{

    if (send_hash->hashtable) {
	struct list_header_s *table=(struct list_header_s *) send_hash->hashtable;
	struct list_element_s *list=NULL;

	for (unsigned int i=0; i<send_hash->tablesize; i++) {

	    list=get_list_head(&table[i], SIMPLE_LIST_FLAG_REMOVE);

	    while (list) {
		struct hash_request_s *request=get_containing_request_h(list);

		free(request);
		list=get_list_head(&table[i], SIMPLE_LIST_FLAG_REMOVE);

	    }

	}

	free(table);
	send_hash->hashtable=NULL;

    }

}

static unsigned char f_request_is_interrupted_default(struct hash_request_s *request)
{
    struct fuse_request_s *f_request=request->sftp_r->fuse_request;
    return (* f_request->is_interrupted)(f_request);
}

static unsigned char f_request_is_interrupted_nonfuse(struct hash_request_s *request)
{
    return 0;
}

static void free_request_after_timeout(struct timerid_s *id, struct timespec *t)
{
    struct hash_request_s *r;
    struct sftp_send_hash_s *hash=(struct sftp_send_hash_s *) id->context;

    /* lookup sftp request is still there */

    pthread_mutex_lock(&hash->mutex);
    r=lookup_request(hash, id->id.unique);

    if (r) {

	/* test it's expired indeed */

	if (r->started.tv_sec > t->tv_sec + r->timeout.tv_sec || ((r->started.tv_sec == t->tv_sec + r->timeout.tv_sec) && (r->started.tv_nsec > t->tv_nsec + r->timeout.tv_nsec))) {

	    /* yes it is */

	    remove_list_element(&r->h_list);
	    free(r);

	}

    }

    pthread_mutex_unlock(&hash->mutex);

}

/* create and store in hashtable and queue the request to be looked up later when a response arrives */

static void *create_sftp_request(struct sftp_send_hash_s *send_hash, struct sftp_request_s *sftp_r, unsigned int *error)
{
    struct hash_request_s *r=malloc(sizeof(struct hash_request_s));

    if (r) {
	struct list_header_s *table=(struct list_header_s *) send_hash->hashtable;
	unsigned int hash=0;

	memset(r, 0, sizeof(struct hash_request_s));

	r->id=sftp_r->id;
	r->sftp_r=sftp_r;
	r->status=_REQUEST_STATUS_INIT;
	get_current_time(&r->started);
	init_list_element(&r->h_list, NULL);
	r->fuse_request_interrupted=f_request_is_interrupted_default;
	r->timeout.tv_sec=0;
	r->timeout.tv_nsec=0;

	pthread_mutex_lock(&send_hash->mutex);

	/* add to the hash table */

	hash=sftp_r->id % send_hash->tablesize;
	add_list_element_last(&table[hash], &r->h_list);
	r->status=_REQUEST_STATUS_WAITING;
	pthread_mutex_unlock(&send_hash->mutex);

    } else {

	*error=ENOMEM;

    }

    return (void *) r;

}

void *create_sftp_request_ctx(void *ptr, struct sftp_request_s *sftp_r, unsigned int *error)
{
    struct sftp_subsystem_s *sftp_subsystem=(struct sftp_subsystem_s *) ptr;
    return create_sftp_request(&sftp_subsystem->send_hash, sftp_r, error);
}

/* lookup the original sftp request using the hash table by looking it up using the id */

void *get_sftp_request(struct sftp_subsystem_s *sftp_subsystem, unsigned int id, struct sftp_request_s **sftp_r, unsigned int *error)
{
    struct sftp_send_hash_s *send_hash=&sftp_subsystem->send_hash;
    struct hash_request_s *request=NULL;
    unsigned char found=0;

    // logoutput("get_sftp_request");

    pthread_mutex_lock(&send_hash->mutex);
    request=lookup_request(send_hash, id);

    if (request) {

	if (request->status==_REQUEST_STATUS_WAITING) {

	    request->status=_REQUEST_STATUS_RESPONSE;
	    *sftp_r=request->sftp_r;
	    found=1;

	} else if (request->status==_REQUEST_STATUS_TIMEOUT) {

	    /* waiting thread has marked this request as expired */

	    *error=ETIMEDOUT;
	    free(request);
	    request=NULL;

	}

    } else {

	/* request not found... */

	*error=ENOENT;

    }

    pthread_mutex_unlock(&send_hash->mutex);
    return (void *) request;

}

/*
    signal the shared central mutex/cond
    called when a message is received to wake up any waiting request
*/

int signal_sftp_received_id(struct sftp_subsystem_s *sftp_subsystem, void *r)
{
    struct ssh_signal_s *signal=sftp_subsystem->channel.payload_queue.signal;
    struct hash_request_s *request=(struct hash_request_s *) r;
    int result=0;

    // logoutput("signal_sftp_received_id");

    pthread_mutex_lock(signal->mutex);

    if (request->status==_REQUEST_STATUS_RESPONSE) {

	// logoutput("signal_sftp_received_id: response");
	request->status=_REQUEST_STATUS_FINISH;
	pthread_cond_broadcast(signal->cond);

    } else {

	//logoutput("signal_sftp_received_id: non response");
	result=-1;

    }

    pthread_mutex_unlock(signal->mutex);
    return result;
}



/*
    wait for a response with a certain id
    a timeout is used
*/

static unsigned char wait_sftp_response(struct sftp_subsystem_s *sftp_subsystem, void *ptr, struct timespec *timeout, struct context_interface_s *interface, unsigned int *error)
{
    struct ssh_channel_s *channel=&sftp_subsystem->channel;
    struct ssh_signal_s *signal=channel->payload_queue.signal;
    struct hash_request_s *request=(struct hash_request_s *) ptr;
    struct timespec expire;
    int result=0;
    unsigned char success=0;

    // logoutput("wait_sftp_response");

    if (request->sftp_r->fuse_request==NULL) request->fuse_request_interrupted=f_request_is_interrupted_nonfuse;

    get_current_time(&expire);

    expire.tv_sec+=timeout->tv_sec;
    expire.tv_nsec+=timeout->tv_nsec;

    if (expire.tv_nsec > 1000000000) {

	expire.tv_nsec -= 1000000000;
	expire.tv_sec++;

    }

    request->timeout.tv_sec=timeout->tv_sec;
    request->timeout.tv_nsec=timeout->tv_nsec;

    pthread_mutex_lock(signal->mutex);

    while (request->status!=_REQUEST_STATUS_FINISH && (* request->fuse_request_interrupted)(request)==0) {

	result=pthread_cond_timedwait(signal->cond, signal->mutex, &expire);

	if (request->status==_REQUEST_STATUS_FINISH) {

	    free(request);
	    success=1;
	    break;

	} else if (request->sftp_r->sequence == signal->sequence_number_error) {

	    logoutput("wait_sftp_response: signal sequence error");

	    /* error on sequence number (not supported for example) */

	    free(request);
	    *error=signal->sequence_number_error;
	    break;

	} else {

	    if (result==ETIMEDOUT || (* request->fuse_request_interrupted)(request)) {

		/* signal from VFS/fuse-interface side:
		    - initiating fuse request is interrupted
		    - fuse interface / mount is disconnecting */

		if (request->status==_REQUEST_STATUS_RESPONSE) {
		    struct fuse_request_s *f_request=request->sftp_r->fuse_request;

		    /* data is already received for this request: let this continue */

		    if (f_request && (f_request->flags & FUSEDATA_FLAG_INTERRUPTED)) f_request->flags -= FUSEDATA_FLAG_INTERRUPTED;
		    break;

		} else if (request->status==_REQUEST_STATUS_WAITING) {
		    struct sftp_send_hash_s *send_hash=&sftp_subsystem->send_hash;
		    struct hash_head_s *table=(struct hash_head_s *) send_hash->hashtable;
		    unsigned int hash=request->id % send_hash->tablesize;

		    /* timeout or interrupted: remove from hash */

		    logoutput("wait_sftp_response: timeout/interrupted");
		    remove_list_element(&request->h_list);
		    free(request);

		}

		*error=(result==ETIMEDOUT) ? ETIMEDOUT : EINTR;
		break;

	    } else if ((channel->flags & CHANNEL_FLAG_OPEN)==0 || (channel->flags & CHANNEL_FLAG_NODATA)) {
		struct sftp_send_hash_s *send_hash=&sftp_subsystem->send_hash;
		struct hash_head_s *table=(struct hash_head_s *) send_hash->hashtable;
		unsigned int hash=request->id % send_hash->tablesize;

		/* signal from server/backend side:
		    channel closed and/or eof: remote (sub)system / process disconnected */

		logoutput("wait_sftp_response: channel closed/eof");

		remove_list_element(&request->h_list);
		(* interface->signal_context)(interface, "disconnect");
		free(request);
		*error=ENOTCONN;
		break;

	    }

	}

    }

    pthread_mutex_unlock(signal->mutex);
    return success;

}

unsigned char wait_sftp_response_ctx(struct context_interface_s *interface, void *r, struct timespec *timeout, unsigned int *error)
{
    struct sftp_subsystem_s *sftp_subsystem=(struct sftp_subsystem_s *) interface->ptr;
    return wait_sftp_response(sftp_subsystem, r, timeout, interface, error);
}

static unsigned char wait_sftp_service_complete(struct sftp_subsystem_s *sftp_subsystem, struct timespec *timeout, unsigned int *error)
{
    struct ssh_channel_s *channel=&sftp_subsystem->channel;
    struct ssh_signal_s *signal=channel->payload_queue.signal;
    struct timespec expire;
    int result=0;
    unsigned char success=0;

    logoutput("wait_sftp_service_complete");

    get_current_time(&expire);

    expire.tv_sec+=timeout->tv_sec;
    expire.tv_nsec+=timeout->tv_nsec;

    if (expire.tv_nsec > 1000000000) {

	expire.tv_nsec -= 1000000000;
	expire.tv_sec++;

    }

    pthread_mutex_lock(signal->mutex);

    while (1) {

	result=pthread_cond_timedwait(signal->cond, signal->mutex, &expire);

	if (channel->flags & CHANNEL_FLAG_OPEN) {

	    success=1;
	    break;

	} else if (channel->flags & (CHANNEL_FLAG_SERVER_CLOSE | CHANNEL_FLAG_SERVER_EOF)) {

	    *error=ENOTCONN;
	    break;

	} else {
	    struct fs_connection_s *connection=&channel->session->connection;

	    if (connection->status & FS_CONNECTION_FLAG_DISCONNECTED) {

		*error=(connection->error>0) ? connection->error : ENOTCONN;
		break;

	    } else if (channel->flags & (CHANNEL_FLAG_SERVER_CLOSE | CHANNEL_FLAG_SERVER_EOF)) {

		*error=ENOTCONN;
		break;

	    }

	}


    }

    pthread_mutex_unlock(signal->mutex);
    return success;

}

unsigned char wait_sftp_service_complete_ctx(struct context_interface_s *interface, struct timespec *timeout, unsigned int *error)
{
    struct sftp_subsystem_s *sftp_subsystem=(struct sftp_subsystem_s *) interface->ptr;
    return wait_sftp_service_complete(sftp_subsystem, timeout, error);
}

static unsigned char wait_sftp_response_simple(struct sftp_subsystem_s *sftp_subsystem, void *ptr, struct timespec *timeout, unsigned int *error)
{
    struct ssh_signal_s *signal=sftp_subsystem->channel.payload_queue.signal;
    struct hash_request_s *request=(struct hash_request_s *) ptr;
    struct timespec expire;
    int result=0;
    unsigned char success=0;

    get_current_time(&expire);

    expire.tv_sec+=timeout->tv_sec;
    expire.tv_nsec+=timeout->tv_nsec;

    if (expire.tv_nsec > 1000000000) {

	expire.tv_nsec -= 1000000000;
	expire.tv_sec++;

    }

    pthread_mutex_lock(signal->mutex);

    while (request->status!=_REQUEST_STATUS_FINISH) {

	result=pthread_cond_timedwait(signal->cond, signal->mutex, &expire);

	if (request->status==_REQUEST_STATUS_FINISH) {

	    free(request);
	    success=1;
	    break;

	} else if (request->sftp_r->sequence == signal->sequence_number_error) {

	    /* error on sequence number (not supported for example) */

	    free(request);
	    *error=signal->sequence_number_error;
	    break;

	} else if (result==ETIMEDOUT) {
	    struct sftp_send_hash_s *send_hash=&sftp_subsystem->send_hash;
	    struct hash_head_s *table=(struct hash_head_s *) send_hash->hashtable;
	    unsigned int hash=request->id % send_hash->tablesize;

	    /* no reply: remove from hash */

	    logoutput("wait_sftp_response_simple: timeout");
	    remove_list_element(&request->h_list);

	    free(request);
	    *error=ETIMEDOUT;
	    break;

	}

    }

    pthread_mutex_unlock(signal->mutex);
    return success;

}

unsigned char wait_sftp_response_simple_ctx(void *ptr, void *r, struct timespec *timeout, unsigned int *error)
{
    struct sftp_subsystem_s *sftp_subsystem=(struct sftp_subsystem_s *) ptr;
    return wait_sftp_response_simple(sftp_subsystem, r, timeout, error);
}

int init_send_hash(struct sftp_send_hash_s *send_hash, unsigned int *error)
{
    send_hash->sftp_request_id=0;
    send_hash->hashtable=NULL;
    send_hash->tablesize=0;
    pthread_mutex_init(&send_hash->mutex, NULL);
    return init_request_group(send_hash, error);
}

void free_send_hash(struct sftp_send_hash_s *send_hash)
{
    free_request_group(send_hash);

    if (send_hash->hashtable) {
	unsigned int hashvalue=0;
	struct list_header_s *table=(struct list_header_s *) send_hash->hashtable;

	while (hashvalue < send_hash->tablesize) {
	    struct list_element_s *list=NULL;

	    list=get_list_head(&table[hashvalue], SIMPLE_LIST_FLAG_REMOVE);

	    while (list) {
		struct hash_request_s *request=NULL;

		request=get_containing_request_h(list);
		free(request);
		list=get_list_head(&table[hashvalue], SIMPLE_LIST_FLAG_REMOVE);

	    }

	}

	free(send_hash->hashtable);
	send_hash->hashtable=NULL;

    }

    pthread_mutex_destroy(&send_hash->mutex);
}
