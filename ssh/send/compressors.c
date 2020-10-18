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
#include "ssh-send.h"

static char fallback_buffer[sizeof(struct ssh_compressor_s)];
static struct ssh_compressor_s *fallback=(struct ssh_compressor_s *) fallback_buffer;

struct ssh_compressor_s *get_compressor_container(struct list_element_s *list)
{
    return (struct ssh_compressor_s *) (((char *) list) - offsetof(struct ssh_compressor_s, list));
}

static int compress_error(struct ssh_compressor_s *c, struct ssh_payload_s **payload, unsigned int *error)
{
    *error=ENOMEM;
    return -1;
}

static void dummy_call(struct ssh_compressor_s *c)
{
}

static void init_compressor(struct ssh_compressor_s *compressor, struct ssh_compress_s *compress, unsigned int size)
{
    memset(compressor, 0, sizeof(struct ssh_compressor_s) + size);
    compressor->compress=compress;
    get_current_time(&compressor->created);
    compressor->nr=(compress) ? compress->count : 0;
    init_list_element(&compressor->list, NULL);
    compressor->size=size;
    compressor->clear=dummy_call;
    compressor->queue=dummy_call;
    compressor->compress_payload=compress_error;
}

static struct ssh_compressor_s *create_compressor(struct ssh_compress_s *compress)
{
    struct compress_ops_s *ops=compress->ops;
    unsigned int size=(* ops->get_handle_size)(compress);
    struct ssh_compressor_s *compressor=malloc(sizeof(struct ssh_compressor_s) + size);

    if (compressor==NULL) goto fallback;
    init_compressor(compressor, compress, size);
    compressor->queue=queue_compressor;
    if ((* ops->init_compressor)(compressor)==0) return compressor;

    free(compressor);

    fallback:

    return fallback;

}

/* get a compressor from the compressors list
    - a compressor does not have to wait until the compressor of the previous package has finished */

struct ssh_compressor_s *get_compressor(struct ssh_send_s *send, unsigned int *error)
{
    struct ssh_compress_s *compress=&send->compress;
    struct ssh_compressor_s *compressor=fallback;
    struct list_header_s *header=&compress->header;

    pthread_mutex_lock(&send->mutex);

    /* wait for a decompressor to become available */

    while (header->count==0 && compress->count == compress->max_count && compress->max_count>0) {

	int result=pthread_cond_wait(&send->cond, &send->mutex);

	if (header->count>0 || compress->count < compress->max_count) {

	    break;

	} else if (result>0 || (send->flags & (SSH_SEND_FLAG_DISCONNECT | SSH_SEND_FLAG_ERROR))) {

	    *error=(result>0) ? result : EIO;
	    goto finish;

	}

    }

    if (header->count>0) {
	struct list_element_s *list=get_list_head(header, SIMPLE_LIST_FLAG_REMOVE);

	compressor=get_compressor_container(list);

    } else if ((compress->count < compress->max_count) || compress->max_count==0) {

	compressor=create_compressor(compress);
	compress->count++;

    }

    finish:

    // logoutput("get_compressor: finish");

    // logoutput("get_compressor (nr %i count %i)", (compressor) ? compressor->nr : -1, compress->count);
    // logoutput("get_compressor: finish (%li.%li - %li.%li)", compressor->created.tv_sec, compressor->created.tv_nsec, send->newkeys.tv_sec, send->newkeys.tv_nsec);

    pthread_mutex_unlock(&send->mutex);
    return compressor;

}

void queue_compressor(struct ssh_compressor_s *compressor)
{
    struct ssh_compress_s *compress=compressor->compress;
    struct ssh_send_s *send=(struct ssh_send_s *) (((char *) compress) - offsetof(struct ssh_send_s, compress));
    struct list_header_s *header=&compress->header;

    pthread_mutex_lock(&send->mutex);

    if (compressor->created.tv_sec > send->newkeys.tv_sec ||
	(compressor->created.tv_sec == send->newkeys.tv_sec && compressor->created.tv_nsec >= send->newkeys.tv_nsec)) {

	add_list_element_last(header, &compressor->list);
	pthread_cond_broadcast(&send->cond);

    } else {

	/* dealing with an "old" decryptor from before newkeys:
	    do not queue it but clear and free it  */

	(* compressor->clear)(compressor);
	free(compressor);
	compress->count--;

    }

    pthread_mutex_unlock(&send->mutex);

}

void remove_compressors(struct ssh_compress_s *compress)
{
    struct list_element_s *list=NULL;
    struct list_header_s *header=&compress->header;

    doremove:

    list=get_list_head(header, SIMPLE_LIST_FLAG_REMOVE);

    if (list) {
	struct ssh_compressor_s *compressor=get_compressor_container(list);
	(* compressor->clear)(compressor);
	free(compressor);
	compress->count--;
	goto doremove;

    }

}

void init_compressors_once()
{
    init_compressor(fallback, NULL, 0);
}
