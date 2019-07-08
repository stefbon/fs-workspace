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

#include "logging.h"
#include "main.h"
#include "workerthreads.h"

#include "utils.h"

#include "ssh-common.h"
#include "ssh-common-protocol.h"
#include "ssh-receive.h"
#include "ssh-utils.h"
#include "ssh-send.h"

static receive_msg_cb_t ssh_msg_cb[256];

static void msg_not_supported(struct ssh_session_s *session, struct ssh_payload_s *payload)
{
    unsigned int seq=payload->sequence;
    logoutput("msg_not_supported: received %i", payload->type);
    free_payload(&payload);

    if (send_unimplemented_message(session, seq)==0) {

	logoutput("msg_not_supported: send MSG_UNIMPLEMENTED for seq %i", seq);

    } else {

	logoutput("msg_not_supported: failed to send MSG_UNIMPLEMENTED for seq %i", seq);

    }

}

void register_msg_cb(unsigned char type, receive_msg_cb_t cb)
{
    ssh_msg_cb[type]=cb;
}

void process_cb_ssh_payload(struct ssh_session_s *session, struct ssh_payload_s *payload)
{
    logoutput("process_cb_ssh_payload (type=%i)", payload->type);
    (* ssh_msg_cb[payload->type]) (session, payload);
}

static void release_read_buffer_default(struct ssh_receive_s *receive)
{
    receive->threadid=0;

    // logoutput("release_read_buffer_default");

    if (receive->read>0) {
	struct ssh_session_s *session=(struct ssh_session_s *)(((char *) receive) - offsetof(struct ssh_session_s, receive));

	logoutput("release_read_buffer_default: read ssh buffer again");

	read_ssh_buffer(session);

    }

    pthread_cond_broadcast(&receive->cond);

}

static void release_read_buffer_ignore(struct ssh_receive_s *receive)
{
}

static void release_read_buffer_default_withlock(struct ssh_receive_s *receive)
{
    pthread_mutex_lock(&receive->mutex);

    // logoutput("release_read_buffer_default_withlock");

    receive->threadid=0;

    if (receive->read>0) {
	struct ssh_session_s *session=(struct ssh_session_s *)(((char *) receive) - offsetof(struct ssh_session_s, receive));

	logoutput("release_read_buffer_default_withlock: %i bytes in read buffer, start a thread to read", receive->read);
	read_ssh_buffer(session); /* start another thread */

    }

    /* check for situation kexinit phase has ended: reset to default behaviour */

    if ((receive->flags & SSH_RECEIVE_FLAG_KEXINIT)==0) {

	receive->release_read_buffer_early=release_read_buffer_default;
	receive->release_read_buffer_late=release_read_buffer_ignore;

    }
    pthread_cond_broadcast(&receive->cond);
    pthread_mutex_unlock(&receive->mutex);
}

void set_receive_behaviour(struct ssh_receive_s *receive, const char *what)
{
    logoutput("set_receive_behaviour: %s", what);

    if (strcmp(what, "kexinit")==0) {

	/* after receiving the kexinit message parallel processing of messages is disabled
	    the read buffer is released **after** a message is processed
	    (the default is that the read buffer is released after reading the header) */

	receive->release_read_buffer_early=release_read_buffer_ignore;
	receive->release_read_buffer_late=release_read_buffer_default_withlock;
	receive->flags |= SSH_RECEIVE_FLAG_KEXINIT;
	if (receive->flags & SSH_RECEIVE_FLAG_NEWKEYS) receive->flags-=SSH_RECEIVE_FLAG_NEWKEYS;

    } else if (strcmp(what, "default")==0) {

	/* default behaviour:
	    - release the read buffer after reading the message header (after copying all relevant data to another buffer)
	*/

	receive->flags |= SSH_RECEIVE_FLAG_NEWKEYS;
	if (receive->flags & SSH_RECEIVE_FLAG_KEXINIT) receive->flags -= SSH_RECEIVE_FLAG_KEXINIT;
	// receive->release_read_buffer_early=release_read_buffer_default;
	// receive->release_read_buffer_late=release_read_buffer_ignore;

    } else if (strcmp(what, "disconnect")==0) {

	receive->flags |= SSH_RECEIVE_FLAG_DISCONNECT;
	receive->release_read_buffer_early=release_read_buffer_default;
	receive->release_read_buffer_late=release_read_buffer_ignore;

    }

}

void start_receive_kexinit(struct ssh_receive_s *receive)
{
    pthread_mutex_lock(&receive->mutex);
    set_receive_behaviour(receive, "kexinit");
    pthread_cond_broadcast(&receive->cond);
    pthread_mutex_unlock(&receive->mutex);
}

void finish_receive_newkeys(struct ssh_receive_s *receive)
{
    pthread_mutex_lock(&receive->mutex);
    set_receive_behaviour(receive, "default");
    pthread_cond_broadcast(&receive->cond);
    pthread_mutex_unlock(&receive->mutex);
}

void signal_receive_disconnect(struct ssh_receive_s *receive)
{
    struct ssh_signal_s *signal=&receive->signal;

    pthread_mutex_lock(&receive->mutex);
    set_receive_behaviour(receive, "disconnect");
    pthread_cond_broadcast(&receive->cond);
    pthread_mutex_unlock(&receive->mutex);

    /* signal any waiting thread for a payload (this is done via signal) */

    pthread_mutex_lock(signal->mutex);
    pthread_cond_broadcast(signal->cond);
    pthread_mutex_unlock(signal->mutex);

}

int wait_for_newkeys_to_complete(struct ssh_receive_s *receive)
{
    int result=-1;

    pthread_mutex_lock(&receive->mutex);

    while ((receive->flags & SSH_RECEIVE_FLAG_NEWKEYS)==0) {

	pthread_cond_wait(&receive->cond, &receive->mutex);

	if (receive->flags & SSH_RECEIVE_FLAG_NEWKEYS) {

	    result=0;
	    break;

	} else if (receive->flags & (SSH_RECEIVE_FLAG_ERROR | SSH_RECEIVE_FLAG_DISCONNECT)) {

	    break;

	}

    }

    pthread_mutex_unlock(&receive->mutex);

    return result;

}

int init_receive(struct ssh_session_s *session, pthread_mutex_t *mutex, pthread_cond_t *cond, unsigned int *error)
{
    struct ssh_receive_s *receive=&session->receive;
    struct ssh_decrypt_s *decrypt=&receive->decrypt;
    struct ssh_decompress_s *decompress=&receive->decompress;

    logoutput("init_receive");

    memset(receive, 0, sizeof(struct ssh_receive_s));

    /* central signal used by channels and other queues
	the cond and mutex are shared with fuse
	threads can thus not only be signalled when a reply
	from the server arrives but also when the original request
	is interrupted by fuse/user */

    receive->signal.flags=0;
    receive->signal.sequence_number_error=0;
    receive->signal.error=0;

    if (mutex && cond) {

	receive->signal.mutex=mutex;
	receive->signal.cond=cond;

    } else {

	receive->signal.mutex=malloc(sizeof(pthread_mutex_t));
	receive->signal.cond=malloc(sizeof(pthread_cond_t));

	if (receive->signal.mutex && receive->signal.cond) {

	    receive->signal.flags|=SSH_SIGNAL_FLAG_ALLOCATED;

	    pthread_mutex_init(receive->signal.mutex, NULL);
	    pthread_cond_init(receive->signal.cond, NULL);

	} else {

	    if (receive->signal.mutex) {

		free(receive->signal.mutex);
		receive->signal.mutex=NULL;

	    }

	    if (receive->signal.cond) {

		free(receive->signal.cond);
		receive->signal.cond=NULL;

	    }

	}

    }

    pthread_mutex_init(&receive->mutex, NULL);
    pthread_cond_init(&receive->cond, NULL);
    receive->threadid=0;
    receive->threadstatus=0;
    receive->sequence_number=0;

    /* the maximum size for the buffer RFC4253 6.1 Maximum Packet Length */

    receive->size=35000;
    receive->read=0;
    receive->buffer=malloc(receive->size);

    if (receive->buffer) {

	memset(receive->buffer, '\0', receive->size);
	*error=0;

    } else {

	receive->size=0;
	*error=ENOMEM;
	return -1;

    }

    switch_read_ssh_buffer(session, "greeter");

    receive->process_ssh_packet=process_ssh_packet_nodecompress;
    receive->release_read_buffer_early=release_read_buffer_default;
    receive->release_read_buffer_late=release_read_buffer_ignore;

    receive->newkeys.tv_sec=0;
    receive->newkeys.tv_nsec=0;

    /* decrypt */

    decrypt->flags=0;
    memset(decrypt->ciphername, '\0', sizeof(decrypt->ciphername));
    memset(decrypt->hmacname, '\0', sizeof(decrypt->hmacname));
    init_list_header(&decrypt->waiters.cryptors, SIMPLE_LIST_TYPE_EMPTY, NULL);
    decrypt->count=0;
    decrypt->max_count=0;
    init_list_header(&decrypt->waiters.threads, SIMPLE_LIST_TYPE_EMPTY, NULL);
    pthread_mutex_init(&decrypt->waiters.mutex, NULL);
    pthread_cond_init(&decrypt->waiters.cond, NULL);
    decrypt->ops=NULL;

    init_ssh_string(&decrypt->cipher_key);
    init_ssh_string(&decrypt->cipher_iv);
    init_ssh_string(&decrypt->hmac_key);

    set_decrypt_generic(decrypt);
    strcpy(decrypt->ciphername, "none");
    strcpy(decrypt->hmacname, "none");

    /* decompress */

    decompress->flags=0;
    memset(decompress->name, '\0', sizeof(decompress->name));
    init_list_header(&decompress->waiters.cryptors, SIMPLE_LIST_TYPE_EMPTY, NULL);
    decompress->count=0;
    decompress->max_count=0;
    init_list_header(&decompress->waiters.threads, SIMPLE_LIST_TYPE_EMPTY, NULL);
    pthread_mutex_init(&decompress->waiters.mutex, NULL);
    pthread_cond_init(&decompress->waiters.cond, NULL);
    decompress->ops=NULL;

    set_decompress_none(session);

    return 0;

    error:

    if (receive->signal.flags & SSH_SIGNAL_FLAG_ALLOCATED) {

	if (receive->signal.mutex) {

	    pthread_mutex_destroy(receive->signal.mutex);
	    free(receive->signal.mutex);
	    receive->signal.mutex=NULL;

	}

	if (receive->signal.cond) {

	    pthread_mutex_destroy(receive->signal.mutex);
	    free(receive->signal.cond);
	    receive->signal.cond=NULL;

	}

    }

    pthread_mutex_destroy(&receive->mutex);
    pthread_cond_destroy(&receive->cond);

    if (receive->buffer) {

	free(receive->buffer);
	receive->buffer=NULL;

    }

    pthread_mutex_destroy(&decompress->waiters.mutex);
    pthread_cond_destroy(&decompress->waiters.cond);

    pthread_mutex_destroy(&decrypt->waiters.mutex);
    pthread_cond_destroy(&decrypt->waiters.cond);

    return -1;

}

void free_receive(struct ssh_session_s *session)
{
    struct ssh_receive_s *receive=&session->receive;
    struct ssh_decrypt_s *decrypt=&receive->decrypt;
    struct ssh_decompress_s *decompress=&receive->decompress;

    if (receive->signal.flags & SSH_SIGNAL_FLAG_ALLOCATED) {

	if (receive->signal.mutex) {

	    pthread_mutex_destroy(receive->signal.mutex);
	    free(receive->signal.mutex);
	    receive->signal.mutex=NULL;

	}

	if (receive->signal.cond) {

	    pthread_mutex_destroy(receive->signal.mutex);
	    free(receive->signal.cond);
	    receive->signal.cond=NULL;

	}

    }

    pthread_mutex_destroy(&receive->mutex);
    pthread_cond_destroy(&receive->cond);

    if (receive->buffer) {

	free(receive->buffer);
	receive->buffer=NULL;

    }

    receive->size=0;
    remove_decryptors(decrypt);
    remove_decompressors(decompress);

    pthread_mutex_destroy(&decompress->waiters.mutex);
    pthread_cond_destroy(&decompress->waiters.cond);

    pthread_mutex_destroy(&decrypt->waiters.mutex);
    pthread_cond_destroy(&decrypt->waiters.cond);

}

void init_receive_once()
{

    for (int i=0; i<256; i++) ssh_msg_cb[i]=msg_not_supported;
    register_transport_cb();
    register_channel_cb();
    register_userauth_cb();

    init_decrypt_generic();
    init_decrypt_chacha20_poly1305_openssh_com();
    init_decompress_none();

    init_decryptors_once();
    init_decompressors_once();

}
