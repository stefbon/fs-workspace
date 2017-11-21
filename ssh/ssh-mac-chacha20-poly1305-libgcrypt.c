/*
  2010, 2011, 2012, 2103, 2014, 2015, 2016 Stef Bon <stefbon@gmail.com>

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
#include <gcrypt.h>

#include "logging.h"
#include "main.h"

#include "utils.h"

#include "ssh-common.h"
#include "ssh-mac.h"
#include "ssh-mac-chacha20-poly1305-libgcrypt.h"

#define POLY1305_TAGLEN				16

extern gcry_mac_hd_t get_mac_handle_s2c_chacha20_poly1305(struct ssh_encryption_s *encryption);
extern gcry_mac_hd_t get_mac_handle_c2s_chacha20_poly1305(struct ssh_encryption_s *encryption);

static void _reset_dummy(struct ssh_hmac_s *hmac)
{
}

static void _free_dummy(struct ssh_hmac_s *hmac)
{
    /* do nothing here: the encryption frees everything */
}

static int _verify_mac_pre(struct rawdata_s *data)
{
    struct ssh_session_s *session=data->session;
    struct ssh_hmac_s *hmac=&session->crypto.hmac;
    gcry_mac_hd_t mac_handle=(gcry_mac_hd_t) hmac->library_s2c.ptr;
    gcry_error_t result=0;

    gcry_mac_write(mac_handle, data->buffer, data->len - data->maclen);

    result=gcry_mac_verify(mac_handle, data->buffer + data->len - data->maclen, data->maclen);

    if (result==0) {

	return 0;

    } else {

	logoutput("_verify_mac_pre: error %s/%s", gcry_strsource(result), gcry_strerror(result));

    }

    return -1;
}


static int _verify_mac_post(struct rawdata_s *data)
{
    return 0;
}

/* create the mac by reading the sequence and the packet */

static void _write_mac_pre(struct ssh_hmac_s *hmac, struct ssh_packet_s *packet)
{
}

static void _write_mac_post(struct ssh_hmac_s *hmac, struct ssh_packet_s *packet)
{
    gcry_mac_hd_t mac_handle=(gcry_mac_hd_t) hmac->library_c2s.ptr;
    gcry_mac_write(mac_handle, packet->buffer, packet->len);

}

/* send the outgoing packet including the mac */

static ssize_t _send_c2s(struct ssh_session_s *session, struct ssh_packet_s *packet)
{
    struct ssh_hmac_s *hmac=&session->crypto.hmac;
    gcry_mac_hd_t mac_handle=(gcry_mac_hd_t) hmac->library_c2s.ptr;
    ssize_t written=0;
    size_t size=hmac->maclen_c2s;
    char mac[size];

    if (gcry_mac_read(mac_handle, &mac[0], &size)==0) {
	struct iovec iov[2];

	// logoutput("_send_c2s: maclen %i(%i) packet len %i packet size %i padding %i", size, hmac->maclen_c2s, packet->len, get_uint32(packet->buffer), (unsigned char) (packet->buffer+4));

	iov[0].iov_base=(void *) packet->buffer;
	iov[0].iov_len=packet->len;
	iov[1].iov_base=(void *) &mac[0];
	iov[1].iov_len=hmac->maclen_c2s;

	written=writev(session->connection.fd, iov, 2);
	if (written==-1) packet->error=errno;

    } else {

	packet->error=EIO;
	written=-1;

    }

    return written;

}

int _set_hmac_c2s_chacha20_poly1305(struct ssh_hmac_s *hmac, unsigned int *error)
{

    hmac->reset_c2s 		= _reset_dummy;
    hmac->write_mac_pre 	= _write_mac_pre;
    hmac->write_mac_post 	= _write_mac_post;
    hmac->send_c2s 		= _send_c2s;
    hmac->free_c2s 		= _free_dummy;

    hmac->maclen_c2s=POLY1305_TAGLEN;

    return 0;

}

int _set_hmac_s2c_chacha20_poly1305(struct ssh_hmac_s *hmac, unsigned int *error)
{

    hmac->reset_s2c 		= _reset_dummy;
    hmac->verify_mac_pre 	= _verify_mac_pre;
    hmac->verify_mac_post 	= _verify_mac_post;
    hmac->free_s2c 		= _free_dummy;

    hmac->maclen_s2c=POLY1305_TAGLEN;

    return 0;

}

unsigned int _get_mac_keylen_chacha20_poly1305()
{
    /* no key for mac used */
    return 0;
}

