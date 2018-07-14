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

static char fallback_buffer[sizeof(struct ssh_decryptor_s)];
static struct ssh_decryptor_s *fallback=(struct ssh_decryptor_s *) fallback_buffer;

struct waiter_list_s {
    struct list_element_s 		list;
    pthread_t				thread;
};

struct ssh_decryptor_s *get_decryptor_container(struct list_element_s *list)
{
    return (struct ssh_decryptor_s *) (((char *) list) - offsetof(struct ssh_decryptor_s, list));
}

static int verify_hmac_error(struct ssh_decryptor_s *d, struct ssh_packet_s *packet)
{
    packet->error=EIO;
    return -1;
}

static int decrypt_length_error(struct ssh_decryptor_s *d, struct ssh_packet_s *packet, char *b, unsigned int l)
{
    packet->error=EIO;
    return -1;
}

static int decrypt_packet_error(struct ssh_decryptor_s *d, struct ssh_packet_s *packet)
{
    packet->error=EIO;
    return -1;
}

static void dummy_decryptor(struct ssh_decryptor_s *d)
{
}

static void init_decryptor(struct ssh_decryptor_s *decryptor, struct ssh_decrypt_s *decrypt, unsigned int size)
{
    memset(decryptor, 0, sizeof(struct ssh_decryptor_s) + size);
    decryptor->decrypt=decrypt;
    get_current_time(&decryptor->created);
    decryptor->nr=(decrypt) ? decrypt->count : 0;
    decryptor->list.next=NULL;
    decryptor->list.prev=NULL;
    decryptor->size=size;

    decryptor->verify_hmac_pre=verify_hmac_error;
    decryptor->decrypt_length=decrypt_length_error;
    decryptor->decrypt_packet=decrypt_packet_error;
    decryptor->verify_hmac_post=verify_hmac_error;
    decryptor->clear=dummy_decryptor;
    decryptor->queue=dummy_decryptor;
}

static struct ssh_decryptor_s *create_decryptor(struct ssh_decrypt_s *decrypt)
{
    struct decrypt_ops_s *ops=decrypt->ops;
    unsigned int size=(* ops->get_handle_size)(decrypt);
    struct ssh_decryptor_s *decryptor=malloc(sizeof(struct ssh_decryptor_s) + size);

    if (decryptor==NULL) return fallback;
    init_decryptor(decryptor, decrypt, size);
    decryptor->queue=queue_decryptor;
    if ((* ops->init_decryptor)(decryptor)==0) {

	decrypt->count++;
	return decryptor;

    }

    free(decryptor);
    return fallback;

}

/* get a decryptor from the decryptors list
    this is the function for the common case: not during kexinit-newkeys
    */

struct ssh_decryptor_s *get_decryptor(struct ssh_receive_s *receive, unsigned int *error)
{
    struct ssh_decrypt_s *decrypt=&receive->decrypt;
    struct ssh_decryptor_s *decryptor=NULL;
    struct waiter_list_s waiter;

    waiter.list.prev=NULL;
    waiter.list.next=NULL;
    waiter.thread=pthread_self();

    pthread_mutex_lock(&receive->mutex);

    if (decrypt->waiting==0) {

	/* no other thread */

	decrypt->waiters.head=&waiter.list;
	decrypt->waiters.tail=&waiter.list;
	decrypt->waiting=1;

    } else {

	add_list_element_last(&decrypt->waiters.head, &decrypt->waiters.tail, &waiter.list);
	decrypt->waiting++;

	/* wait to become the first */

	while (decrypt->waiters.head != &waiter.list) {
	    int result=0;

	    result=pthread_cond_wait(&receive->cond, &receive->mutex);

	    /* already the first ? */

	    if (decrypt->waiters.head == &waiter.list) {

		break;

	    } else if (result>0) {

		decryptor=fallback;
		goto finish;

	    }

	}

    }

    /* wait for a decryptor to become available */

    while (decrypt->decryptors.head==NULL && decrypt->count == decrypt->max_count && decrypt->max_count>0) {
	int result=0;

	result=pthread_cond_wait(&receive->cond, &receive->mutex);

	if (decrypt->decryptors.head || decrypt->count < decrypt->max_count) {

	    break;

	} else if (result>0) {

	    decryptor=fallback;
	    goto finish;

	} else if (receive->flags & (SSH_RECEIVE_FLAG_DISCONNECT | SSH_RECEIVE_FLAG_ERROR)) {

	    decryptor=fallback;
	    goto finish;

	}

    }

    if (decrypt->decryptors.head) {
	struct list_element_s *list=get_list_head(&decrypt->decryptors.head, &decrypt->decryptors.tail);

	decryptor=get_decryptor_container(list);

    } else if (decrypt->count < decrypt->max_count || decrypt->max_count==0) {

	decryptor=create_decryptor(decrypt);

    }

    finish:

    logoutput("get_decryptor (nr %i count %i)", (decryptor) ? decryptor->nr : -1, decrypt->count);

    // logoutput("get_decryptor: finish (%li.%li - %li.%li)", decryptor->created.tv_sec, decryptor->created.tv_nsec, receive->newkeys.tv_sec, receive->newkeys.tv_nsec);

    remove_list_element(&decrypt->waiters.head, &decrypt->waiters.tail, &waiter.list);
    decrypt->waiting--;
    pthread_cond_broadcast(&receive->cond);
    pthread_mutex_unlock(&receive->mutex);
    return decryptor;

}

void queue_decryptor(struct ssh_decryptor_s *decryptor)
{
    struct ssh_decrypt_s *decrypt=decryptor->decrypt;
    struct ssh_receive_s *receive=(struct ssh_receive_s *) (((char *) decrypt) - offsetof(struct ssh_receive_s, decrypt));

    pthread_mutex_lock(&receive->mutex);

    if (decryptor->created.tv_sec > receive->newkeys.tv_sec ||
	(decryptor->created.tv_sec == receive->newkeys.tv_sec && decryptor->created.tv_nsec >= receive->newkeys.tv_nsec)) {

	add_list_element_last(&decrypt->decryptors.head, &decrypt->decryptors.tail, &decryptor->list);

    } else {

	/* dealing with an "old" decryptor from before newkeys:
	    do not queue it but clear and free it  */

	(* decryptor->clear)(decryptor);
	free(decryptor);
	decrypt->count--;

    }

    pthread_cond_broadcast(&receive->cond);
    pthread_mutex_unlock(&receive->mutex);

}

void remove_decryptors(struct ssh_decrypt_s *decrypt)
{
    struct ssh_decryptor_s *decryptor=NULL;
    struct list_element_s *list=NULL;

    list=get_list_head(&decrypt->decryptors.head, &decrypt->decryptors.tail);

    while (list) {

	decryptor=get_decryptor_container(list);
	(* decryptor->clear)(decryptor);
	free(decryptor);
	decrypt->count--;
	list=get_list_head(&decrypt->decryptors.head, &decrypt->decryptors.tail);

    }

}

void init_decryptors_once()
{
    init_decryptor(fallback, NULL, 0);
}
