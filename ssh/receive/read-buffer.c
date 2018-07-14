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
#include "ssh-connection.h"

void process_ssh_packet_nodecompress(struct ssh_session_s *session, struct ssh_packet_s *packet)
{
    struct ssh_payload_s *payload=NULL;
    unsigned int len = packet->len - 1 - packet->padding;

    payload=malloc(sizeof(struct ssh_payload_s) + len);

    if (payload) {

	payload->flags=SSH_PAYLOAD_FLAG_ALLOCATED;
	payload->len=len;
	payload->sequence=packet->sequence;
	payload->next=NULL;
	payload->prev=NULL;
	memcpy(payload->buffer, &packet->buffer[5], len);
	payload->type=(unsigned char) payload->buffer[0];
	set_alloc_payload_dynamic(payload);

	process_cb_ssh_payload(session, payload);
	return;

    }

    disconnect_ssh_session(session, 0, SSH_DISCONNECT_BY_APPLICATION);

}

void process_ssh_packet_decompress(struct ssh_session_s *session, struct ssh_packet_s *packet)
{
    unsigned int error=0;
    struct ssh_decompressor_s *decompressor=get_decompressor(&session->receive, &error);
    struct ssh_payload_s *payload=NULL;

    if ((* decompressor->decompress_packet)(decompressor, packet, &payload, &error)==0) {

	payload->type=(unsigned char) payload->buffer[0];
	(* decompressor->queue)(decompressor);
	process_cb_ssh_payload(session, payload);
	return;

    }

    (* decompressor->queue)(decompressor);
    if (error==0) error=EIO;
    disconnect_ssh_session(session, 0, SSH_DISCONNECT_BY_APPLICATION);

}

/* read data from buffer, decrypt, check mac, and process the packet
    it does this by getting a decryptor; depending the cipher it's possible that more decryptor are in "flight"
*/

void read_ssh_buffer_packet(void *ptr)
{
    struct ssh_session_s *session=(struct ssh_session_s *) ptr;
    struct ssh_receive_s *receive=&session->receive;
    struct ssh_decrypt_s *decrypt=&receive->decrypt;
    struct ssh_packet_s packet;
    unsigned int error=0;
    struct ssh_decryptor_s *decryptor=get_decryptor(receive, &error);
    unsigned int cipher_headersize=decryptor->cipher_headersize;
    char cipher_header[cipher_headersize];

    logoutput("read_ssh_buffer_packet: thread %i receive->threadid %i read %i", gettid(), receive->threadid, receive->read);

    getpacket:

    pthread_mutex_lock(&receive->mutex);

    if (receive->threadid==0 && receive->read>0) {

	receive->threadid=pthread_self();

	while (receive->read < cipher_headersize) {

	    pthread_cond_wait(&receive->cond, &receive->mutex);

	    if (receive->read >= cipher_headersize) {

		break;

	    } else if (receive->flags & (SSH_RECEIVE_FLAG_ERROR | SSH_RECEIVE_FLAG_DISCONNECT)) {

		pthread_mutex_unlock(&receive->mutex);
		goto disconnect;

	    }

	}

    } else {

	pthread_mutex_unlock(&receive->mutex);
	queue_decryptor(decryptor);
	return;

    }

    pthread_mutex_unlock(&receive->mutex);

    packet.len=0;
    packet.size=0;
    packet.padding=0;
    packet.error=0;
    packet.sequence=receive->sequence_number;
    packet.type=0;
    packet.decrypted=0;
    packet.buffer=receive->buffer;

    receive->sequence_number++; /* move this ? */

    /* decrypt first block to know the packet length
	don't decrypt inplace cause it's possible that hmac is verified over the encrypted text
	in stead store the decrypted header in a seperate buffer
	and copy that buffer later back when the whole packet is decrypted */

    if ((* decryptor->decrypt_length)(decryptor, &packet, cipher_header, cipher_headersize)==0) {

	packet.len=get_uint32(cipher_header);
	packet.size=packet.len + 4 + decryptor->hmac_maclen; /* total number of bytes to expect */

	if (packet.size > receive->size) {

	    logoutput_warning("read_ssh_buffer_packet: packet length %i too big (max %i)", packet.size, receive->size);
	    goto disconnect;

	} else {
	    char data[packet.size];

	    pthread_mutex_lock(&receive->mutex);

	    if (packet.size > receive->read) {

		/* length of the packet is bigger than size of received data
		    wait for data to arrive: signalled when data is received */

		logoutput("read_ssh_buffer_packet: packet length %i, received %i", packet.size, receive->read);

		while (receive->read < packet.size) {

		    /* here some expire timeout ? */

		    pthread_cond_wait(&receive->cond, &receive->mutex);

		    if (receive->read >= packet.size) {

			break;

		    } else if (receive->flags & (SSH_RECEIVE_FLAG_ERROR | SSH_RECEIVE_FLAG_DISCONNECT)) {

			pthread_mutex_unlock(&receive->mutex);
			goto disconnect;

		    }

		}

	    }

	    /* copy encrypted data and mac to packet and reset receive read */

	    memcpy(data, receive->buffer, packet.size);

	    if (receive->read == packet.size) {

		receive->read=0;

	    } else {

		/* does this happen? */

		memmove(receive->buffer, (char *) (receive->buffer + packet.size), (receive->read - packet.size));
		receive->read-=packet.size;

		logoutput("read_ssh_buffer_packet: still bytes in buffer (%i)", receive->read);

	    }

	    (* receive->release_read_buffer_early)(receive);
	    pthread_mutex_unlock(&receive->mutex);
	    packet.buffer=data;

	    logoutput("read_ssh_buffer_packet: packet length %i size %i", packet.len, packet.size);

	    /* do mac/tag checking when "before decrypting" is used: use the unecrypted data */

	    if ((* decryptor->verify_hmac_pre)(decryptor, &packet)==0) {

		memcpy(data, cipher_header, cipher_headersize);

		/* decrypt rest */

		if ((* decryptor->decrypt_packet)(decryptor, &packet)==0) {

		    packet.padding=(unsigned char) *(packet.buffer + 4);

		    /* do mac checking when "after decrypting" is used */

		    if ((* decryptor->verify_hmac_post)(decryptor, &packet)==0) {

			queue_decryptor(decryptor);
			decryptor=NULL;

			(* receive->process_ssh_packet)(session, &packet);
			(* receive->release_read_buffer_late)(receive);

		    } else {

			logoutput_warning("read_ssh_buffer_packet: error verify mac post");
			goto disconnect;

		    }

		} else {

		    logoutput_warning("read_ssh_buffer_packet: error decrypt packet");
		    goto disconnect;

		}

	    } else {

		logoutput_warning("read_ssh_buffer_packet: error verify mac pre");
		goto disconnect;

	    }

	}

    } else {

	logoutput_warning("read_ssh_buffer_packet: error decrypt header");
	goto disconnect;

    }

    if (decryptor) queue_decryptor(decryptor);
    return;

    disconnect:

    if (decryptor) queue_decryptor(decryptor);
    logoutput_warning("read_ssh_buffer_packet: ignoring received data");
    disconnect_ssh_session(session, 0, SSH_DISCONNECT_BY_APPLICATION);

}

/*
    read the first data from server
    this is the greeter
    take in account the second ssh message can be attached
*/

void read_ssh_buffer_greeter(void *ptr)
{
    struct ssh_session_s *session=(struct ssh_session_s *) ptr;
    struct ssh_receive_s *receive=&session->receive;

    pthread_mutex_lock(&receive->mutex);

    if (receive->threadid==0) {

	receive->threadid=pthread_self();

    } else {

	pthread_mutex_unlock(&receive->mutex);
	return;

    }

    pthread_mutex_unlock(&receive->mutex);

    /* when receiving the first data switch immediatly the function to process the incoming data */

    if (read_server_greeter(session)==-1) {
	struct sessionphase_s sessionphase;

	copy_sessionphase(session, &sessionphase);
	sessionphase.status|=SESSION_STATUS_GENERIC_FAILED;
	change_status_sessionphase(session, &sessionphase);

	logoutput_warning("read_ssh_buffer_greeter: not able to read server greeter");
	return;

    } else {
	struct sessionphase_s sessionphase;

	copy_sessionphase(session, &sessionphase);
	sessionphase.status|=SESSION_STATUS_GREETER_S2C;
	change_status_sessionphase(session, &sessionphase);

    }

    switch_read_ssh_buffer(session, "setup");

    /* first packet included? */

    pthread_mutex_lock(&receive->mutex);

    if (receive->read>0) {

	(* receive->read_ssh_buffer)((void *) session);

    } else {

	receive->threadid=0;

    }

    pthread_mutex_unlock(&receive->mutex);

}

void read_ssh_buffer_none(void *ptr)
{
    struct ssh_session_s *session=(struct ssh_session_s *) ptr;
    struct ssh_receive_s *receive=&session->receive;

    pthread_mutex_lock(&receive->mutex);
    receive->read=0;
    pthread_mutex_unlock(&receive->mutex);

}

void read_ssh_buffer(struct ssh_session_s *session)
{
    unsigned int error=0;
    struct ssh_receive_s *receive=&session->receive;

    logoutput("read_ssh_buffer: threadid %i", gettid());

    work_workerthread(NULL, 0, receive->read_ssh_buffer, (void *) session, &error);
}

void switch_read_ssh_buffer(struct ssh_session_s *session, const char *phase)
{
    struct ssh_receive_s *receive=&session->receive;

    logoutput("switch_read_ssh_buffer: set phase %s", phase);

    pthread_mutex_lock(&receive->mutex);

    if (strcmp(phase, "greeter")==0) {

	receive->read_ssh_buffer=read_ssh_buffer_greeter;

    } else if (strcmp(phase, "setup")==0) {

	receive->read_ssh_buffer=read_ssh_buffer_packet;
	receive->process_ssh_packet=process_ssh_packet_decompress;

    } else if (strcmp(phase, "none")==0) {

	receive->read_ssh_buffer=read_ssh_buffer_none;

    }

    pthread_mutex_unlock(&receive->mutex);

}
