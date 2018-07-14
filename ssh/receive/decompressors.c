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

#include "logging.h"
#include "main.h"
#include "utils.h"

#include "ssh-common.h"
#include "ssh-utils.h"
#include "ssh-receive.h"

static char fallback_buffer[sizeof(struct ssh_decompressor_s)];
static struct ssh_decompressor_s *fallback=(struct ssh_decompressor_s *) fallback_buffer;

struct waiter_list_s {
    struct list_element_s 		list;
    pthread_t				thread;
};

struct ssh_decompressor_s *get_decompressor_container(struct list_element_s *list)
{
    return (struct ssh_decompressor_s *) (((char *) list) - offsetof(struct ssh_decompressor_s, list));
}

static int decompress_error(struct ssh_decompressor_s *d, struct ssh_packet_s *packet, struct ssh_payload_s **payload, unsigned int *error)
{
    *error=ENOMEM;
    return -1;
}

static void dummy_call(struct ssh_decompressor_s *d)
{
}

static void init_decompressor(struct ssh_decompressor_s *decompressor, struct ssh_decompress_s *decompress, unsigned int size)
{
    memset(decompressor, 0, sizeof(struct ssh_decompressor_s) + size);
    decompressor->decompress=decompress;
    get_current_time(&decompressor->created);
    decompressor->list.next=NULL;
    decompressor->list.prev=NULL;
    decompressor->size=size;

    decompressor->clear=dummy_call;
    decompressor->queue=dummy_call;
    decompressor->decompress_packet=decompress_error;

}

static struct ssh_decompressor_s *create_decompressor(struct ssh_decompress_s *decompress)
{
    struct decompress_ops_s *ops=decompress->ops;
    unsigned int size=(* ops->get_handle_size)(decompress);
    struct ssh_decompressor_s *decompressor=malloc(sizeof(struct ssh_decompressor_s) + size);

    if (decompressor==NULL) return fallback;
    init_decompressor(decompressor, decompress, size);
    decompressor->queue=queue_decompressor;

    if ((* ops->init_decompressor)(decompressor)==0) return decompressor;

    free(decompressor);
    return NULL;

}

/* get a decompressor from the decompressors list */

struct ssh_decompressor_s *get_decompressor(struct ssh_receive_s *receive, unsigned int *error)
{
    struct ssh_decompress_s *decompress=&receive->decompress;
    struct ssh_decompressor_s *decompressor=NULL;
    struct list_element_s *list=NULL;
    struct waiter_list_s waiter;

    waiter.list.prev=NULL;
    waiter.list.next=NULL;
    waiter.thread=pthread_self();

    pthread_mutex_lock(&receive->mutex);

    if (decompress->waiting==0) {

	/* no other thread */

	decompress->waiters.head=&waiter.list;
	decompress->waiters.tail=&waiter.list;
	decompress->waiting=1;

    } else {

	add_list_element_last(&decompress->waiters.head, &decompress->waiters.tail, &waiter.list);
	decompress->waiting++;

	/* wait to become the first */

	while (decompress->waiters.head != &waiter.list) {
	    int result=0;

	    result=pthread_cond_wait(&receive->cond, &receive->mutex);

	    /* already the first ? */

	    if (decompress->waiters.head == &waiter.list) {

		break;

	    } else if (result>0) {

		*error=result;
		goto finish;

	    }

	}

    }

    /* wait for a decompressor to become available */

    while (decompress->decompressors.head==NULL && decompress->count == decompress->max_count && decompress->max_count>0) {
	int result=0;

	result=pthread_cond_wait(&receive->cond, &receive->mutex);

	if (decompress->decompressors.head || decompress->count < decompress->max_count) {

	    break;

	} else if (result>0) {

	    *error=result;
	    goto finish;

	} else if (receive->flags & (SSH_RECEIVE_FLAG_DISCONNECT | SSH_RECEIVE_FLAG_ERROR)) {

	    *error=EIO;
	    goto finish;

	}

    }

    if (decompress->decompressors.head) {
	struct list_element_s *list=get_list_head(&decompress->decompressors.head, &decompress->decompressors.tail);

	decompressor=get_decompressor_container(list);

    } else if ((decompress->count < decompress->max_count) || decompress->max_count==0) {

	decompressor=create_decompressor(decompress);

	if (decompressor==NULL) {

	    *error=ENOMEM;

	} else {

	    decompress->count++;

	}

    }

    finish:

    // logoutput("get_decompressor: finish (%li.%li - %li.%li)", decompressor->created.tv_sec, decompressor->created.tv_nsec, receive->newkeys.tv_sec, receive->newkeys.tv_nsec);

    remove_list_element(&decompress->waiters.head, &decompress->waiters.tail, &waiter.list);
    decompress->waiting--;
    pthread_cond_broadcast(&receive->cond);
    pthread_mutex_unlock(&receive->mutex);
    return decompressor;

}

void queue_decompressor(struct ssh_decompressor_s *decompressor)
{
    struct ssh_decompress_s *decompress=decompressor->decompress;
    struct ssh_receive_s *receive=(struct ssh_receive_s *) (((char *) decompress) - offsetof(struct ssh_receive_s, decompress));

    pthread_mutex_lock(&receive->mutex);

    if (decompressor->created.tv_sec > receive->newkeys.tv_sec ||
	(decompressor->created.tv_sec == receive->newkeys.tv_sec && decompressor->created.tv_nsec >= receive->newkeys.tv_nsec)) {

	add_list_element_last(&decompress->decompressors.head, &decompress->decompressors.tail, &decompressor->list);

    } else {

	/* dealing with an "old" decryptor from before newkeys:
	    do not queue it but clear and free it  */

	(* decompressor->clear)(decompressor);
	free(decompressor);
	decompress->count--;

    }

    pthread_cond_broadcast(&receive->cond);
    pthread_mutex_unlock(&receive->mutex);

}

void remove_decompressors(struct ssh_decompress_s *decompress)
{
    struct ssh_decompressor_s *decompressor=NULL;
    struct list_element_s *list=NULL;

    list=get_list_head(&decompress->decompressors.head, &decompress->decompressors.tail);

    while (list) {

	decompressor=get_decompressor_container(list);
	(* decompressor->clear)(decompressor);
	free(decompressor);
	decompress->count--;
	list=get_list_head(&decompress->decompressors.head, &decompress->decompressors.tail);

    }

}

void init_decompressors_once()
{
    init_decompressor(fallback, NULL, 0);
}
