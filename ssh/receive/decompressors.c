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

#include "simple-locking.h"

static char fallback_buffer[sizeof(struct ssh_decompressor_s)];
static struct ssh_decompressor_s *fallback=(struct ssh_decompressor_s *) fallback_buffer;

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
    decompressor->nr=(decompress) ? decompress->count : 0;
    init_list_element(&decompressor->list, NULL);
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
    struct list_header_s *header=&decompress->header;

    pthread_mutex_lock(&receive->mutex);

    /* wait for a decompressor to become available */

    while (header->count==0 && decompress->count == decompress->max_count && decompress->max_count>0) {
	int result=0;

	result=pthread_cond_wait(&receive->cond, &receive->mutex);

	if (header->count>0 || decompress->count < decompress->max_count) {

	    break;

	} else if (result>0 || (receive->status & SSH_RECEIVE_STATUS_DISCONNECT)) {

	    *error=(result>0) ? result : EIO;
	    goto finish;

	}

    }

    if (header->count>0) {
	struct list_element_s *list=get_list_head(header, SIMPLE_LIST_FLAG_REMOVE);

	decompressor=get_decompressor_container(list);

    } else if ((decompress->count < decompress->max_count) || decompress->max_count==0) {

	decompressor=create_decompressor(decompress);
	decompress->count++;

    }

    finish:

    pthread_mutex_unlock(&receive->mutex);
    return decompressor;

}

void queue_decompressor(struct ssh_decompressor_s *decompressor)
{
    struct ssh_decompress_s *decompress=decompressor->decompress;
    struct ssh_receive_s *receive=(struct ssh_receive_s *) (((char *) decompress) - offsetof(struct ssh_receive_s, decompress));
    struct list_header_s *header=&decompress->header;

    pthread_mutex_lock(&receive->mutex);

    if (decompressor->created.tv_sec > receive->newkeys.tv_sec ||
	(decompressor->created.tv_sec == receive->newkeys.tv_sec && decompressor->created.tv_nsec >= receive->newkeys.tv_nsec)) {

	add_list_element_last(header, &decompressor->list);
	pthread_cond_broadcast(&receive->cond);

    } else {

	/* dealing with an "old" decryptor from before newkeys:
	    do not queue it but clear and free it  */

	(* decompressor->clear)(decompressor);
	free(decompressor);
	decompress->count--;

    }

    pthread_mutex_unlock(&receive->mutex);

}

void remove_decompressors(struct ssh_decompress_s *decompress)
{
    struct list_element_s *list=NULL;
    struct list_header_s *header=&decompress->header;

    while ((list=get_list_head(header, SIMPLE_LIST_FLAG_REMOVE))) {
	struct ssh_decompressor_s *decompressor=get_decompressor_container(list);
	(* decompressor->clear)(decompressor);
	free(decompressor);
	decompress->count--;

    }

}

void init_decompressors_once()
{
    init_decompressor(fallback, NULL, 0);
}
