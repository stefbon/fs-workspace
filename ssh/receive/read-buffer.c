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
#include "ssh-connections.h"

void process_ssh_packet_nodecompress(struct ssh_connection_s *connection, struct ssh_packet_s *packet)
{
    struct ssh_payload_s *payload=NULL;
    unsigned int len = packet->len - 1 - packet->padding;

    logoutput("process_ssh_packet_nodecompress: type %i", packet->buffer[5]);

    payload=malloc(sizeof(struct ssh_payload_s) + len);

    if (payload) {

	memset(payload, '\0', sizeof(struct ssh_payload_s) + len);

	payload->flags=SSH_PAYLOAD_FLAG_ALLOCATED;
	payload->len=len;
	payload->sequence=packet->sequence;
	init_list_element(&payload->list, NULL);
	memcpy(payload->buffer, &packet->buffer[5], len);
	payload->type=(unsigned char) payload->buffer[0];
	set_alloc_payload_dynamic(payload);
	process_cb_ssh_payload(connection, payload);

	return;

    }

    disconnect_ssh_connection(connection);

}

void process_ssh_packet_decompress(struct ssh_connection_s *connection, struct ssh_packet_s *packet)
{
    unsigned int error=0;
    struct ssh_decompressor_s *decompressor=get_decompressor(&connection->receive, &error);
    struct ssh_payload_s *payload=NULL;

    if ((* decompressor->decompress_packet)(decompressor, packet, &payload, &error)==0) {

	payload->type=(unsigned char) payload->buffer[0];
	(* decompressor->queue)(decompressor);
	process_cb_ssh_payload(connection, payload);
	return;

    }

    (* decompressor->queue)(decompressor);
    if (error==0) error=EIO;
    disconnect_ssh_connection(connection);

}

/* read data from buffer, decrypt, check mac, and process the packet
    it does this by getting a decryptor; depending the cipher it's possible that more decryptor are in "flight"
*/

static void read_ssh_buffer_packet(void *ptr)
{
    struct ssh_connection_s *connection=(struct ssh_connection_s *) ptr;
    struct ssh_receive_s *receive=&connection->receive;
    struct ssh_decrypt_s *decrypt=&receive->decrypt;
    struct ssh_packet_s packet;
    unsigned int error=0;
    struct ssh_decryptor_s *decryptor=NULL;
    unsigned int cipher_headersize=0;
    char cipher_header[32]; /* 32 is a safe bet, the actual header size is less than that */

    logoutput("read_ssh_buffer_packet: thread %i read %i", gettid(), receive->read);

    pthread_mutex_lock(&receive->mutex);

    if (receive->read==0 || (receive->status & SSH_RECEIVE_STATUS_WAIT) || receive->threads>1) {

	pthread_mutex_unlock(&receive->mutex);
	return;

    }

    decryptor=get_decryptor_unlock(receive, &error);
    cipher_headersize=decryptor->cipher_headersize;
    receive->status|=((receive->read < cipher_headersize) ? SSH_RECEIVE_STATUS_WAITING1 : 0);
    receive->threads++;

    /* enough data in buffer and is the buffer free to process a packet ? */

    while (receive->status & (SSH_RECEIVE_STATUS_WAITING1 | SSH_RECEIVE_STATUS_PACKET)) {

	int result=pthread_cond_wait(&receive->cond, &receive->mutex);

	if (receive->read >= cipher_headersize && (receive->status & SSH_RECEIVE_STATUS_WAITING1)) {

	    receive->status -= SSH_RECEIVE_STATUS_WAITING1;

	} else if (receive->read==0) {

	    if (receive->status & SSH_RECEIVE_STATUS_WAITING1) receive->status -= SSH_RECEIVE_STATUS_WAITING1;
	    receive->threads--;
	    pthread_mutex_unlock(&receive->mutex);
	    goto finish;

	} else if (result>0 || (receive->status & SSH_RECEIVE_STATUS_DISCONNECT)) {

	    pthread_mutex_unlock(&receive->mutex);
	    goto disconnect;

	}

    }

    /* there is no other thread creating and reading a packet from the buffer */

    receive->status |= SSH_RECEIVE_STATUS_PACKET;
    pthread_mutex_unlock(&receive->mutex);

    readpacket:

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

	    logoutput_warning("read_ssh_buffer_packet: tid %i packet size %i too big (max %i)", gettid(), packet.size, receive->size);
	    pthread_mutex_lock(&receive->mutex);
	    receive->status -= SSH_RECEIVE_STATUS_PACKET;
	    receive->threads--;
	    goto disconnect;

	} else {
	    char data[packet.size];

	    pthread_mutex_lock(&receive->mutex);

	    logoutput("read_ssh_buffer_packet: tid %i packet size %i, received %i", gettid(), packet.size, receive->read);

	    while (receive->read < packet.size) {

		/* length of the packet is bigger than size of received data
		    wait for data to arrive: signalled when data is received */

		receive->status |= SSH_RECEIVE_STATUS_WAITING2;

		int result=pthread_cond_wait(&receive->cond, &receive->mutex);

		if (receive->read >= packet.size) {

		    receive->status -= SSH_RECEIVE_STATUS_WAITING2;
		    break;

		} else if (result>0 || (receive->status & SSH_RECEIVE_STATUS_DISCONNECT)) {

		    receive->status -= (SSH_RECEIVE_STATUS_PACKET | SSH_RECEIVE_STATUS_WAITING2);
		    receive->threads--;
		    pthread_mutex_unlock(&receive->mutex);
		    goto disconnect;

		}

	    }

	    /* copy encrypted data and mac to packet data and reset receive read cause ready with buffer   */

	    memcpy(data, receive->buffer, packet.size);
	    receive->read-=packet.size;
	    receive->status -= SSH_RECEIVE_STATUS_PACKET;
	    receive->threads--;

	    if (receive->read > 0) {

		/* stil data in buffer */

		logoutput("read_ssh_buffer_packet: tid %i still %i bytes in buffer", gettid(), receive->read);

		memmove(receive->buffer, (char *) (receive->buffer + packet.size), receive->read);

		if ((receive->status & SSH_RECEIVE_STATUS_SERIAL)==0) {

		    if (receive->threads==0) {

			read_ssh_connection_buffer(connection);

		    } else {

			pthread_cond_broadcast(&receive->cond);

		    }

		}

	    }

	    pthread_mutex_unlock(&receive->mutex);
	    packet.buffer=data;

	    /* do mac/tag checking when "before decrypting" is used: use the encrypted data
		in other cases ("do mac checking after decryption") this does nothing */

	    if ((* decryptor->verify_hmac_pre)(decryptor, &packet)==0) {

		memcpy(data, cipher_header, cipher_headersize);

		/* decrypt rest */

		if ((* decryptor->decrypt_packet)(decryptor, &packet)==0) {

		    packet.padding=(unsigned char) *(packet.buffer + 4);

		    /* do mac checking when "after decryption" is used */

		    if ((* decryptor->verify_hmac_post)(decryptor, &packet)==0) {

			/* ready with descryptor */
			(* decryptor->queue)(decryptor);
			decryptor=NULL;

			(* receive->process_ssh_packet)(connection, &packet);

			pthread_mutex_lock(&receive->mutex);

			if (receive->status & SSH_RECEIVE_STATUS_SERIAL) {
			    struct timespec expire;

			    get_ssh_connection_expire_init(connection, &expire);

			    /* after receiving the newkeys message wait for the kexinit phase to end:
				that's when the new keys are ready to be used */

			    while ((receive->status & SSH_RECEIVE_STATUS_NEWKEYS) && (receive->status & SSH_RECEIVE_STATUS_KEXINIT)) {

				/* wait for the calculation of the new keys before proceed */

				int result=pthread_cond_timedwait(&receive->cond, &receive->mutex, &expire);

				if ((receive->status & SSH_RECEIVE_STATUS_DISCONNECT) || result==ETIMEDOUT) {

				    pthread_mutex_unlock(&receive->mutex);
				    goto disconnect;

				}

			    }

			}

			if (receive->read>0) {

			    if (receive->threads==0) {

				read_ssh_connection_buffer(connection);

			    } else {

				pthread_cond_broadcast(&receive->cond);

			    }

			}

			pthread_mutex_unlock(&receive->mutex);

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

    finish:

    if (decryptor) (* decryptor->queue)(decryptor);
    return;

    disconnect:

    if (decryptor) (* decryptor->queue)(decryptor);
    logoutput_warning("read_ssh_buffer_packet: ignoring received data");
    disconnect_ssh_connection(connection);

}

static int setup_cb_greeter_finished(struct ssh_connection_s *connection, void *data)
{
    /* after greeter (=text) switch the reading of the buffer expecting packets */
    set_ssh_receive_behaviour(connection, "session");
    return 0;
}

/*
    read the first data from server
    this is the greeter
    take in account the second ssh message can be attached
*/

static void read_ssh_buffer_greeter(void *ptr)
{
    struct ssh_connection_s *connection=(struct ssh_connection_s *) ptr;
    struct ssh_receive_s *receive=&connection->receive;
    struct ssh_setup_s *setup=&connection->setup;
    int result=0;

    pthread_mutex_lock(&receive->mutex);

    if (receive->threads>0) {

	pthread_mutex_unlock(&receive->mutex);
	return;

    }

    receive->threads=1;
    receive->status|=SSH_RECEIVE_STATUS_PACKET;
    pthread_mutex_unlock(&receive->mutex);

    /* when receiving the first data switch immediatly the function to process the incoming data */

    result=read_server_greeter(connection);
    if (result==0) change_ssh_connection_setup(connection, "transport", SSH_TRANSPORT_TYPE_GREETER, SSH_GREETER_FLAG_S2C, 0, setup_cb_greeter_finished, NULL);

    /* first packet included? */

    pthread_mutex_lock(&receive->mutex);

    receive->threads=0;
    receive->status-=SSH_RECEIVE_STATUS_PACKET;
    if (result==0 && receive->read>0) read_ssh_connection_buffer(connection);

    pthread_mutex_unlock(&receive->mutex);

    if (result==-1) logoutput("read_ssh_buffer_greeter: failed to read server greeter");

    return;

}

static void read_ssh_buffer_none(void *ptr)
{
    struct ssh_connection_s *connection=(struct ssh_connection_s *) ptr;
    struct ssh_receive_s *receive=&connection->receive;

    pthread_mutex_lock(&receive->mutex);
    receive->read=0;
    pthread_mutex_unlock(&receive->mutex);

}

void read_ssh_connection_buffer(struct ssh_connection_s *connection)
{
    unsigned int error=0;
    struct ssh_receive_s *receive=&connection->receive;
    work_workerthread(NULL, 0, receive->read_ssh_buffer, (void *) connection, &error);
}

void set_ssh_receive_behaviour(struct ssh_connection_s *connection, const char *phase)
{
    struct ssh_receive_s *receive=&connection->receive;

    logoutput("set_ssh_receive_behaviour: set phase %s", phase);

    pthread_mutex_lock(&receive->mutex);

    if (strcmp(phase, "init")==0) {

	receive->status=SSH_RECEIVE_STATUS_INIT;

    } else if (strcmp(phase, "greeter")==0) {

	receive->read_ssh_buffer=read_ssh_buffer_greeter;

    } else if (strcmp(phase, "session")==0) {

	receive->read_ssh_buffer=read_ssh_buffer_packet;
	receive->process_ssh_packet=process_ssh_packet_nodecompress;

    } else if (strcmp(phase, "kexinit")==0) {

	/* when doing kex go into serial mode */

	receive->status |= SSH_RECEIVE_STATUS_SERIAL;
	receive->status |= SSH_RECEIVE_STATUS_KEXINIT;
	if (receive->status & SSH_RECEIVE_STATUS_NEWKEYS) receive->status -= SSH_RECEIVE_STATUS_NEWKEYS;

    } else if (strcmp(phase, "newkeys")==0) {

	receive->status |= SSH_RECEIVE_STATUS_NEWKEYS;
	get_current_time(&receive->newkeys);

    } else if (strcmp(phase, "kexfinish")==0) {

	if (receive->status & SSH_RECEIVE_STATUS_KEXINIT) receive->status -= SSH_RECEIVE_STATUS_KEXINIT;
	if (receive->status & SSH_RECEIVE_STATUS_SERIAL) receive->status -= SSH_RECEIVE_STATUS_SERIAL;

    } else if (strcmp(phase, "none")==0) {

	receive->read_ssh_buffer=read_ssh_buffer_none;

    } else if (strcmp(phase, "error")==0) {

	receive->status|=SSH_RECEIVE_STATUS_ERROR;

    } else if (strcmp(phase, "disconnect")==0) {

	receive->status|=SSH_RECEIVE_STATUS_DISCONNECT;

    }

    pthread_cond_broadcast(&receive->cond);
    pthread_mutex_unlock(&receive->mutex);

}
