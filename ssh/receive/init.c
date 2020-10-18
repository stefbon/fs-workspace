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
#include "ssh-connections.h"
#include "ssh-receive.h"
#include "ssh-utils.h"
#include "ssh-send.h"

static receive_msg_cb_t ssh_msg_cb[256];

static void msg_not_supported(struct ssh_connection_s *connection, struct ssh_payload_s *payload)
{
    unsigned int seq=payload->sequence;
    logoutput("msg_not_supported: received %i", payload->type);
    free_payload(&payload);

    if (send_unimplemented_message(connection, seq)==0) {

	logoutput("msg_not_supported: send MSG_UNIMPLEMENTED for seq %i", seq);

    } else {

	logoutput("msg_not_supported: failed to send MSG_UNIMPLEMENTED for seq %i", seq);

    }

}

void register_msg_cb(unsigned char type, receive_msg_cb_t cb)
{
    ssh_msg_cb[type]=cb;
}

void process_cb_ssh_payload(struct ssh_connection_s *connection, struct ssh_payload_s *payload)
{
    // logoutput("process_cb_ssh_payload (type=%i)", payload->type);
    (* ssh_msg_cb[payload->type]) (connection, payload);
}

int init_ssh_connection_receive(struct ssh_connection_s *connection, unsigned int *error)
{
    struct ssh_session_s *session=get_ssh_connection_session(connection);
    struct ssh_receive_s *receive=&connection->receive;
    struct ssh_decrypt_s *decrypt=&receive->decrypt;
    struct ssh_decompress_s *decompress=&receive->decompress;

    logoutput("init_ssh_connection_receive");

    memset(receive, 0, sizeof(struct ssh_receive_s));

    /* central signal used by channels and other queues
	the cond and mutex are shared with fuse
	threads can thus not only be signalled when a reply
	from the server arrives but also when the original request
	is interrupted by fuse/user */

    receive->signal.flags=0;
    receive->signal.sequence_number_error=0;
    receive->signal.error=0;
    receive->signal.mutex=session->connections.mutex;
    receive->signal.cond=session->connections.cond;

    receive->status=0;
    pthread_mutex_init(&receive->mutex, NULL);
    pthread_cond_init(&receive->cond, NULL);
    receive->threads=0;
    receive->sequence_number=0;

    /* the maximum size for the buffer RFC4253 6.1 Maximum Packet Length */

    receive->size=session->config.max_receive_size;
    receive->read=0;
    receive->buffer=malloc(receive->size);

    if (receive->buffer) {

	memset(receive->buffer, '\0', receive->size);
	*error=0;

    } else {

	logoutput("init_ssh_connection_receive: error allocating buffer (%i bytes)", receive->size);
	receive->size=0;
	*error=ENOMEM;
	goto error;

    }

    set_ssh_receive_behaviour(connection, "greeter");
    receive->process_ssh_packet=process_ssh_packet_nodecompress;
    receive->newkeys.tv_sec=0;
    receive->newkeys.tv_nsec=0;

    /* decrypt */

    decrypt->flags=0;
    memset(decrypt->ciphername, '\0', sizeof(decrypt->ciphername));
    memset(decrypt->hmacname, '\0', sizeof(decrypt->hmacname));
    init_list_header(&decrypt->header, SIMPLE_LIST_TYPE_EMPTY, NULL);
    decrypt->count=0;
    decrypt->max_count=0;
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
    init_list_header(&decompress->header, SIMPLE_LIST_TYPE_EMPTY, NULL);
    decompress->count=0;
    decompress->max_count=0;
    decompress->ops=NULL;
    set_decompress_none(connection);

    return 0;

    error:

    pthread_mutex_destroy(&receive->mutex);
    pthread_cond_destroy(&receive->cond);

    if (receive->buffer) {

	free(receive->buffer);
	receive->buffer=NULL;

    }

    return -1;

}

void free_ssh_connection_receive(struct ssh_connection_s *connection)
{
    struct ssh_receive_s *receive=&connection->receive;
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

}

void init_ssh_receive_once()
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
