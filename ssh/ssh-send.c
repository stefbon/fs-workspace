/*
  2010, 2011, 2012, 2103, 2014, 2015 Stef Bon <stefbon@gmail.com>

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
#include <fcntl.h>
#include <dirent.h>
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
#include "ssh-compression.h"
#include "ssh-encryption.h"
#include "ssh-mac.h"

#include "ssh-send.h"

void free_send(struct ssh_session_s *session)
{
    struct ssh_send_s *send=&session->send;
    pthread_mutex_destroy(&send->mutex);
}

void log_message(unsigned char *buff, unsigned int len, const char *name, unsigned int seq)
{
    char logfile[128];

    if (snprintf(logfile, 128, "/tmp/logsftp-%s-%i", name, seq)>0) {
	int fd=0;
	unsigned char lf[1];

	lf[0]=10;

	fd = open(logfile, O_RDWR | O_APPEND);

	if (fd==-1 && errno==ENOENT) {
	    mode_t mode=S_IRUSR | S_IWUSR | S_IRGRP;

	    fd=open(logfile, O_RDWR | O_CREAT, mode);

	    if (fd==-1) return;

	}

	write(fd, buff, len);
	//write(fd, lf, 1);

	close(fd);

    }

}

/*
	create a complete ssh packet (RFC4253)
	global a packet looks like:
	- uint32	packet_length 			length of packet in bytes, not including 'mac' and the field packet_length self
	- byte		padding_length			length of the padding in bytes
	- byte[n1]	payload0			n1 = packet_length - padding_length - 1
	- byte[n2]	padding				n2 = padding_length
	- byte[m]	mac				m = mac_length

	extra: size(uint32) + 1 + n1 + n2 + m = multiple  of 8 (when not using cipher)
	so adjust n2 (=padding_length) to follow this rule
	and n2>=4
*/

static int _send_complete_message(struct ssh_session_s *session, int (*fill_raw_message)(struct ssh_session_s *session, struct ssh_payload_s *payload, void *ptr), void *ptr, unsigned int *seq)
{
    unsigned int payload_len=fill_raw_message(session, NULL, ptr);
    char buffer[sizeof(struct ssh_payload_s) + payload_len];
    struct ssh_payload_s *payload=(struct ssh_payload_s *) buffer;
    unsigned int error=0;
    unsigned int cipher_blocksize=get_cipher_blocksize_c2s(session);
    unsigned int message_blocksize=(cipher_blocksize<8) ? 8 : cipher_blocksize;
    unsigned int len=5 + payload_len;
    unsigned char raw_message[sizeof(struct ssh_packet_s) + len + 2 * message_blocksize]; /* append enough bytes to do the padding */
    unsigned char n2=0, len_mod=0;
    int result=0;
    unsigned char *pos=NULL;
    struct ssh_packet_s packet;
    struct ssh_send_s *send=&session->send;

    /* get the payload */

    payload->type=0;
    payload->len=payload_len;
    payload->sequence=0;
    payload->next=NULL;
    payload->prev=NULL;
    memset(payload->buffer, 0, payload_len);
    payload->len=fill_raw_message(session, payload, ptr);

    /* fill the ssh message  */

    memset(raw_message, '\0', sizeof(struct ssh_packet_s) + len + 2 * message_blocksize); /* a buffer large enough */
    len=payload->len + 5; /* payload length plus 4 for the length and the byte for the padding length */
    n2=get_message_padding(session, len, message_blocksize); /* the padding depends on the cipher used */

    packet.buffer=raw_message;
    packet.len = len + n2; /* packet len plus the padding size */
    packet.padding=n2;
    packet.error=0;

    /* store the packet len (minus the first field) */

    pos=packet.buffer;
    store_uint32(pos, packet.len - 4);
    pos+=4;

    /* store the number of padding */

    *(pos) = n2;
    pos++;

    /* the ssh payload */

    memcpy(pos, payload->buffer, payload->len);
    pos+=payload->len;

    /* fill the padding bytes */

    pos += fill_random(pos, n2);

    /* write the mac of the unencrypted message (when mac before encryption is used) */

    packet.sequence=send->sequence_number;
    write_mac_pre_encrypt(session, &packet);

    /* encrypt */

    if (ssh_encrypt(session, &packet)==0) {

	/* write the mac of the encrypted message (when mac after encryption is used) */

	write_mac_post_encrypt(session, &packet); 
	result=send_c2s(session, &packet);

	if (result==-1) {

	    session->status.error=packet.error;

	} else {

	    *seq=send->sequence_number;
	    send->sequence_number++;

	}

    } else {

	result=-1;
	session->status.error=EIO;

    }

    /* ????? reset here ???? */
    // reset_c2s_mac(session);
    return result;

}

/*
    construct a ssh packet without compression, encryption and mac
    used in the init phase
*/

static int _send_init_message(struct ssh_session_s *session, int (*fill_raw_message)(struct ssh_session_s *s, struct ssh_payload_s *p, void *ptr), void *ptr, unsigned int *seq)
{
    unsigned int payload_len=fill_raw_message(session, NULL, ptr); /* get the required size by calling the cb without parameters */
    unsigned char buffer[sizeof(struct ssh_payload_s) + payload_len];
    struct ssh_payload_s *payload=(struct ssh_payload_s *) buffer;
    unsigned int error=0;
    unsigned int cipher_blocksize=get_cipher_blocksize_c2s(session);
    unsigned int message_blocksize=(cipher_blocksize<8) ? 8 : cipher_blocksize;
    unsigned int len=5 + payload_len;
    unsigned char raw_message[len + 2 * message_blocksize]; /* append enough bytes to do the padding */
    unsigned char n2=0, len_mod=0;
    int result=0;
    unsigned char *pos=NULL;
    struct ssh_packet_s packet;
    struct ssh_send_s *send=&session->send;

    payload->type=0;
    payload->len=payload_len;
    payload->sequence=0;
    payload->next=NULL;
    payload->prev=NULL;
    memset(payload->buffer, 0, payload_len);

    payload->len=fill_raw_message(session, payload, ptr);
    memset(&raw_message[0], '\0', len + 2 * message_blocksize);
    len=payload->len + 5;

    /* determine the number of bytes to pad so that the size is a multiple of max(8, cypherblock) AND the remainder is >= 4 */

    len_mod=len % message_blocksize;
    n2 =  message_blocksize - len_mod; /* padding */

    if ( n2 < 4) {

	/* the remainder is too less (message_blocksize - len_mod < 4): add an extra block */

	n2+=message_blocksize;

    }

    packet.buffer=&raw_message[0];
    packet.len = len + n2; /* packet len plus the padding size */
    packet.padding=n2;
    packet.error=0;
    packet.sequence=0;

    /* store the packet len (minus the first field: 4 bytes) */

    pos=packet.buffer;
    store_uint32(pos, packet.len - 4);
    pos+=4;

    /* store the number of padding */

    *(pos) = n2;
    pos++;

    /* the ssh payload */

    memcpy(pos, payload->buffer, payload->len);
    pos+=payload->len;

    /* fill the padding bytes */

    pos += fill_random(pos, n2);
    packet.sequence=send->sequence_number;

    // logoutput("_send_init_message: len %i : written %i seq %i", len, (unsigned int) (pos-packet.buffer), packet.sequence);

    result=send_c2s(session, &packet);

    if (result==-1) {

	session->status.error=packet.error;
	return -1;

    } else {

	*seq=send->sequence_number;
	send->sequence_number++;

    }

    return 0;

}

/* send a message when initializing: do nothing */

static int _send_none_message(struct ssh_session_s *session, int (*fill_raw_message)(struct ssh_session_s *session, struct ssh_payload_s *payload, void *ptr), void *ptr, unsigned int *seq)
{
    return -1;
}

int send_ssh_message(struct ssh_session_s *session, int (*fill_raw_message)(struct ssh_session_s *session, struct ssh_payload_s *payload, void *ptr), void *ptr, unsigned int *seq)
{
    struct ssh_send_s *send=&session->send;
    int result=0;

    pthread_mutex_lock(&send->mutex);
    result=(* send->send_message)(session, fill_raw_message, ptr, seq);
    pthread_mutex_unlock(&send->mutex);

    return result;
}

int init_send(struct ssh_session_s *session)
{
    struct ssh_send_s *send=&session->send;

    pthread_mutex_init(&send->mutex, NULL);
    send->send_message=_send_none_message;
    send->sequence_number=0;

    switch_send_process(session, "init");

    return 0;

}

void switch_send_process(struct ssh_session_s *session, const char *phase)
{
    struct ssh_send_s *send=&session->send;

    pthread_mutex_lock(&send->mutex);

    if (strcmp(phase, "none")==0) {

	send->send_message=_send_none_message;

    } else if (strcmp(phase, "init")==0) {

	send->send_message=_send_complete_message;

    } else if (strcmp(phase, "session")==0) {

	send->send_message=_send_complete_message;

    } else {

	logoutput_warning("switch_send_process: error phase %s not reckognized", phase);

    }

    pthread_mutex_unlock(&send->mutex);

}
