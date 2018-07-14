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

static char fallback_buffer[sizeof(struct ssh_encryptor_s)];
static struct ssh_encryptor_s *fallback=(struct ssh_encryptor_s *) fallback_buffer;

struct waiter_list_s {
    struct list_element_s 		list;
    pthread_t				thread;
};

struct ssh_encryptor_s *get_encryptor_container(struct list_element_s *list)
{
    return (struct ssh_encryptor_s *) (((char *) list) - offsetof(struct ssh_encryptor_s, list));
}

static int write_hmac_error(struct ssh_encryptor_s *e, struct ssh_packet_s *packet)
{
    packet->error=EIO;
    return -1;
}

static int encrypt_packet_error(struct ssh_encryptor_s *e, struct ssh_packet_s *packet)
{
    packet->error=EIO;
    return -1;
}
static unsigned char get_message_padding_error(struct ssh_encryptor_s *e, unsigned int l)
{
    return 0;
}
static void dummy_encryptor(struct ssh_encryptor_s *e)
{
}

static void init_encryptor(struct ssh_encryptor_s *encryptor, struct ssh_encrypt_s *encrypt, unsigned int size)
{

    memset(encryptor, 0, sizeof(struct ssh_encryptor_s) + size);
    encryptor->encrypt=encrypt;
    get_current_time(&encryptor->created);
    encryptor->nr=(encrypt) ? encrypt->count : 0;
    encryptor->list.next=NULL;
    encryptor->list.prev=NULL;
    encryptor->size=size;
    encryptor->cipher_blocksize=8;
    encryptor->cipher_headersize=8;
    encryptor->hmac_maclen=0;

    encryptor->write_hmac_pre=write_hmac_error;
    encryptor->write_hmac_post=write_hmac_error;
    encryptor->encrypt_packet=encrypt_packet_error;
    encryptor->get_message_padding=get_message_padding_error;
    encryptor->clear=dummy_encryptor;
    encryptor->queue=dummy_encryptor;

}

static struct ssh_encryptor_s *create_encryptor(struct ssh_encrypt_s *encrypt)
{
    struct encrypt_ops_s *ops=encrypt->ops;
    unsigned int size=(* ops->get_handle_size)(encrypt);
    struct ssh_encryptor_s *encryptor=malloc(sizeof(struct ssh_encryptor_s) + size);

    logoutput("create_encryptor");

    if (encryptor==NULL) return fallback;
    init_encryptor(encryptor, encrypt, size);
    encryptor->queue=queue_encryptor;
    if ((* ops->init_encryptor)(encryptor)==0) {

	encrypt->count++;
	return encryptor;

    }

    free(encryptor);
    return fallback;

}

/* get a decryptor from the decryptors list
    this is the function for the common case: not during kexinit-newkeys
    */

struct ssh_encryptor_s *get_encryptor(struct ssh_send_s *send, unsigned int *error)
{
    struct ssh_encrypt_s *encrypt=&send->encrypt;
    struct ssh_encryptor_s *encryptor=NULL;
    struct waiter_list_s waiter;

    waiter.list.prev=NULL;
    waiter.list.next=NULL;
    waiter.thread=pthread_self();

    pthread_mutex_lock(&send->mutex);

    if (encrypt->waiting==0) {

	/* no other thread */

	encrypt->waiters.head=&waiter.list;
	encrypt->waiters.tail=&waiter.list;
	encrypt->waiting=1;

    } else {

	add_list_element_last(&encrypt->waiters.head, &encrypt->waiters.tail, &waiter.list);
	encrypt->waiting++;

	/* wait to become the first */

	while (encrypt->waiters.head != &waiter.list) {
	    int result=0;

	    result=pthread_cond_wait(&send->cond, &send->mutex);

	    /* already the first ? */

	    if (encrypt->waiters.head == &waiter.list) {

		break;

	    } else if (result>0) {

		encryptor=fallback;
		goto finish;

	    }

	}

    }

    /* wait for a encryptor to become available */

    while (encrypt->encryptors.head==NULL && encrypt->count == encrypt->max_count && encrypt->max_count>0) {
	int result=0;

	result=pthread_cond_wait(&send->cond, &send->mutex);

	if (encrypt->encryptors.head || encrypt->count < encrypt->max_count) {

	    break;

	} else if (result>0) {

	    encryptor=fallback;
	    goto finish;

	} else if (send->flags & (SSH_SEND_FLAG_DISCONNECT | SSH_SEND_FLAG_ERROR)) {

	    encryptor=fallback;
	    goto finish;

	}

    }

    if (encrypt->encryptors.head) {
	struct list_element_s *list=get_list_head(&encrypt->encryptors.head, &encrypt->encryptors.tail);

	encryptor=get_encryptor_container(list);

    } else if (encrypt->count < encrypt->max_count || encrypt->max_count==0) {

	encryptor=create_encryptor(encrypt);

    }

    finish:

    logoutput("get_encryptor (nr %i count %i)", (encryptor) ? encryptor->nr : -1, encrypt->count);

    // logoutput("get_encryptor: finish (%li.%li - %li.%li)", encryptor->created.tv_sec, encryptor->created.tv_nsec, send->newkeys.tv_sec, send->newkeys.tv_nsec);

    remove_list_element(&encrypt->waiters.head, &encrypt->waiters.tail, &waiter.list);
    encrypt->waiting--;
    pthread_cond_broadcast(&send->cond);
    pthread_mutex_unlock(&send->mutex);
    return encryptor;

}

void queue_encryptor(struct ssh_encryptor_s *encryptor)
{
    struct ssh_encrypt_s *encrypt=encryptor->encrypt;
    struct ssh_send_s *send=(struct ssh_send_s *) (((char *) encrypt) - offsetof(struct ssh_send_s, encrypt));

    pthread_mutex_lock(&send->mutex);

    if (encryptor->created.tv_sec > send->newkeys.tv_sec ||
	(encryptor->created.tv_sec == send->newkeys.tv_sec && encryptor->created.tv_nsec >= send->newkeys.tv_nsec)) {

	add_list_element_last(&encrypt->encryptors.head, &encrypt->encryptors.tail, &encryptor->list);

    } else {

	/* dealing with an "old" encryptor from before newkeys:
	    do not queue it but clear and free it  */

	(* encryptor->clear)(encryptor);
	free(encryptor);
	encrypt->count--;

    }

    pthread_cond_broadcast(&send->cond);
    pthread_mutex_unlock(&send->mutex);

}

void remove_encryptors(struct ssh_encrypt_s *encrypt)
{
    struct ssh_encryptor_s *encryptor=NULL;
    struct list_element_s *list=NULL;

    list=get_list_head(&encrypt->encryptors.head, &encrypt->encryptors.tail);

    while (list) {

	encryptor=get_encryptor_container(list);
	(* encryptor->clear)(encryptor);
	free(encryptor);
	encrypt->count--;
	list=get_list_head(&encrypt->encryptors.head, &encrypt->encryptors.tail);

    }

}

void init_encryptors_once()
{
    init_encryptor(fallback, NULL, 0);
}
