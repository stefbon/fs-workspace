/*
  2016, 2017, 2018 Stef Bon <stefbon@gmail.com>

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

#include "main.h"
#include "logging.h"

#include "utils.h"

#include "ssh-common.h"
#include "ssh-utils.h"
#include "ssh-send.h"

static int queue_sender_default(struct ssh_send_s *send, struct ssh_sender_s *sender, unsigned int *error)
{
    /* add at tail of senders list default: more senders are allowed */
    pthread_mutex_lock(&send->mutex);
    add_list_element_last(&send->senders.head, &send->senders.tail, &sender->list);
    send->sending++;
    sender->sequence=send->sequence_number;
    sender->listed=1;
    send->sequence_number++;
    pthread_cond_broadcast(&send->cond);
    pthread_mutex_unlock(&send->mutex);

    return 0;
}

static int queue_sender_serial(struct ssh_send_s *send, struct ssh_sender_s *sender, unsigned int *error)
{
    int success=0;

    /* add at tail of senders list serialized: only one sender is allowed */

    pthread_mutex_lock(&send->mutex);

    while (send->sending>0) {

	int result=pthread_cond_wait(&send->cond, &send->mutex);

	if (send->sending==0) {

	    break;

	} else if (send->flags & (SSH_SEND_FLAG_DISCONNECT | SSH_SEND_FLAG_ERROR)) {

	    *error=EIO;
	    success=-1;
	    goto out;

	} else if (result>0) {

	    *error=result;
	    success=-1;
	    goto out;

	}

    }

    send->senders.head=&sender->list;
    send->senders.tail=&sender->list;
    send->sending=1;
    sender->sequence=send->sequence_number;
    sender->listed=1;
    send->sequence_number++;

    out:

    pthread_cond_broadcast(&send->cond);
    pthread_mutex_unlock(&send->mutex);

    return success;
}

static int queue_sender_disconnected(struct ssh_send_s *send, struct ssh_sender_s *sender, unsigned int *error)
{
    *error=ENOTCONN;
    return -1;
}

void set_send_behaviour(struct ssh_send_s *send, const char *what)
{

    logoutput("set_send_behaviour: %s", what);

    if (strcmp(what, "default")==0) {

	send->queue_sender=queue_sender_default;
	if (send->flags & SSH_SEND_FLAG_KEXINIT) send->flags -= SSH_SEND_FLAG_KEXINIT;
	send->flags|=SSH_SEND_FLAG_NEWKEYS;

    } else if (strcmp(what, "kexinit")==0) {

	send->queue_sender=queue_sender_serial;
	if (send->flags & SSH_SEND_FLAG_NEWKEYS) send->flags -= SSH_SEND_FLAG_NEWKEYS;
	send->flags|=SSH_SEND_FLAG_KEXINIT;

    } else if (strcmp(what, "disconnect")==0) {

	send->queue_sender=queue_sender_disconnected;
	send->flags|=SSH_SEND_FLAG_DISCONNECT;

    }

}

void finish_send_newkeys(struct ssh_send_s *send)
{
    set_send_behaviour(send, "default");
}

void signal_send_disconnect(struct ssh_send_s *send)
{
    pthread_mutex_lock(&send->mutex);
    set_send_behaviour(send, "disconnect");
    pthread_cond_broadcast(&send->cond);
    pthread_mutex_unlock(&send->mutex);
}

/*
	create a complete ssh packet (RFC4253)
	global a packet looks like:
	- uint32	packet_length 			length of packet in bytes, not including 'mac' and the field packet_length self
	- byte		padding_length			length of the padding in bytes
	- byte[n1]	payload0			n1 = packet_length - padding_length - 1
	- byte[n2]	padding				n2 = padding_length
	- byte[m]	mac				m = mac_length

	extra: size(uint32) + 1 + n1 + n2 = multiple  of blocksize of cipher (=8 when no cipher is used)
	so adjust n2 (=padding_length) to follow this rule
	and n2>=4
*/

static int _write_ssh_packet(struct ssh_session_s *session, struct ssh_payload_s *payload, void (* post_send)(struct ssh_session_s *s, int written), unsigned int *seq)
{
    struct ssh_send_s *send=&session->send;
    struct ssh_sender_s sender;
    unsigned int error=0;
    int written=-1;

    // logoutput("_write_ssh_packet");

    sender.list.next=NULL;
    sender.list.prev=NULL;
    sender.sequence=0;
    sender.listed=0;

    if ((* send->queue_sender)(send, &sender, &error)==0) {
	struct ssh_compressor_s *compressor=NULL;
	unsigned char type=payload->type;

	*seq=sender.sequence;
	compressor=get_compressor(send, &error);

	if ((*compressor->compress_payload)(compressor, &payload, &error)==0) {
	    struct ssh_encryptor_s *encryptor=get_encryptor(send, &error);
	    unsigned char padding=(* encryptor->get_message_padding)(encryptor, payload->len + 5);
	    unsigned int len = 5 + payload->len + padding; /* field length (4 bytes) plus padding field (1 byte) plus payload plus the padding */
	    unsigned int size = len + encryptor->hmac_maclen; /* total size of message */
	    char buffer[size];
	    struct ssh_packet_s packet;
	    char *pos=NULL;

	    // logoutput("_write_ssh_packet: C (len=%i size=%i)", len, size);

	    packet.len 		= len;
	    packet.size 	= size;
	    packet.padding	= padding;
	    packet.sequence	= sender.sequence;
	    packet.error	= 0;
	    packet.type		= type;
	    packet.decrypted	= 0;
	    packet.buffer	= buffer;

	    /* store the packet len (minus the first field (=4 bytes)) */

	    pos=packet.buffer;
	    store_uint32(pos, packet.len - 4);
	    pos+=4;

	    /* store the number of padding */

	    *(pos) = packet.padding;
	    pos++;

	    /* the ssh payload */

	    memcpy(pos, payload->buffer, payload->len);
	    pos+=payload->len;

	    /* fill the padding bytes */

	    pos += fill_random(pos, packet.padding);

	    /* determine the mac of the unencrypted message (when mac before encryption is used)
		before encryption is the default according to RFC4253 6.4 Data Integrity */

	    if ((* encryptor->write_hmac_pre)(encryptor, &packet)==0) {

		if ((* encryptor->encrypt_packet)(encryptor, &packet)==0) {

		    /* determine the mac of the encrypted message (when mac after encryption is used)
			after encryption is used by chacha20-poly1305@openssh.com */

		    if ((* encryptor->write_hmac_post)(encryptor, &packet)==0) {

			pthread_mutex_lock(&send->mutex);

			/* wait to become first */

			while (send->senders.head!=&sender.list) {

			    int result=pthread_cond_wait(&send->cond, &send->mutex);

			}

			written=write_socket(session, &packet, &error);

			/* function will serialize the sending after kexinit and use newkeys after newkeys
			    in other cases this does nothing 
			    NOTE: the send process is lock protected */

			(* post_send)(session, written);

			if (sender.list.next) {

			    send->senders.head=sender.list.next;

			} else {

			    send->senders.head=NULL;
			    send->senders.tail=NULL;

			}

			sender.listed=0;
			send->sending--;
			pthread_cond_broadcast(&send->cond);
			pthread_mutex_unlock(&send->mutex);

			(* encryptor->queue)(encryptor);
			encryptor=NULL;

			if (written==-1) {

			    if (error==0) error=EIO;
			    logoutput("write_ssh_packet: error %i sending packet (%s)", error, strerror(error));

			}

		    } else {

			logoutput("write_ssh_packet: error writing hmac post");

		    }

		} else {

		    logoutput("write_ssh_packet: error encrypt pakket");

		}

	    } else {

		logoutput("write_ssh_packet: error writing hmac pre");

	    }

	    if (encryptor) {

		(* encryptor->queue)(encryptor);
		encryptor=NULL;

	    }

	} /* compress */ else {

	    logoutput("write_ssh_packet: error compress payload");

	}

	queue_compressor(compressor);
	compressor=NULL;

	if (sender.listed) {

	    pthread_mutex_lock(&send->mutex);
	    remove_list_element(&send->senders.head, &send->senders.tail, &sender.list);
	    pthread_cond_broadcast(&send->cond);
	    pthread_mutex_unlock(&send->mutex);
	    sender.listed=0;

	}

    }

    // logoutput("_write_ssh_packet: written %i", written);

    return written;

}

static void post_send_default(struct ssh_session_s *s, int written)
{
}

int write_ssh_packet(struct ssh_session_s *session, struct ssh_payload_s *payload, unsigned int *seq)
{
    return _write_ssh_packet(session, payload, post_send_default, seq);
}

static void post_send_kexinit(struct ssh_session_s *session, int written)
{
    struct ssh_send_s *send=&session->send;
    set_send_behaviour(send, "kexinit");

}

int write_ssh_packet_kexinit(struct ssh_session_s *session, struct ssh_payload_s *payload, unsigned int *seq)
{
    return _write_ssh_packet(session, payload, post_send_kexinit, seq);
}

static void post_send_newkeys(struct ssh_session_s *session, int written)
{
    struct ssh_send_s *send=&session->send;
    struct keyexchange_s *keyexchange=session->keyexchange;

    /* TODO: action depends on written, this maybe -1 when error */

    if (keyexchange) {
	struct algo_list_s *algos=keyexchange->data.algos;
	int index_compr=keyexchange->data.chosen[SSH_ALGO_TYPE_COMPRESS_C2S];
	int index_cipher=keyexchange->data.chosen[SSH_ALGO_TYPE_CIPHER_C2S];
	int index_hmac=keyexchange->data.chosen[SSH_ALGO_TYPE_HMAC_C2S];
	struct algo_list_s *algo_compr=&algos[index_compr];
	struct algo_list_s *algo_cipher=&algos[index_cipher];
	struct algo_list_s *algo_hmac=(index_hmac>=0) ? &algos[index_hmac] : NULL;

	get_current_time(&send->newkeys);
	reset_compress(send, algo_compr);
	reset_encrypt(session, algo_cipher, algo_hmac);
	finish_send_newkeys(send);

    }

}

int write_ssh_packet_newkeys(struct ssh_session_s *session, struct ssh_payload_s *payload, unsigned int *seq)
{
    return _write_ssh_packet(session, payload, post_send_newkeys, seq);
}
