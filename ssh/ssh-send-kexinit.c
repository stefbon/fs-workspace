/*
  2010, 2011, 2012, 2103, 2014, 2015, 2016, 2017 Stef Bon <stefbon@gmail.com>

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
#include "ssh-common-protocol.h"

#include "ssh-pubkey.h"
#include "ssh-compression.h"
#include "ssh-encryption.h"
#include "ssh-mac.h"
#include "ssh-keyx.h"
#include "ssh-language.h"
#include "ssh-data.h"

#include "ssh-utils.h"

static unsigned int get_kex_algo(char *pos, unsigned int size)
{

    if (pos) {
	struct commalist_s list={pos, 0, size};

	return ssh_get_keyx_list(&list);

    }

    return ssh_get_keyx_list(NULL);

}

static unsigned int get_server_hostkey_algo(char *pos, unsigned int size)
{

    if (pos) {
	struct commalist_s list={pos, 0, size};

	return ssh_get_pubkey_list(&list);

    }

    return ssh_get_pubkey_list(NULL);

}

static unsigned int get_encryption_client_algo(char *pos, unsigned int size)
{

    if (pos) {
	struct commalist_s list={pos, 0, size};

	return ssh_get_cipher_list(&list);

    }

    return ssh_get_cipher_list(NULL);

}

/* same as client */

static unsigned int get_encryption_server_algo(char *pos, unsigned int size)
{

    if (pos) {
	struct commalist_s list={pos, 0, size};

	return ssh_get_cipher_list(&list);

    }

    return ssh_get_cipher_list(NULL);

}

static unsigned int get_mac_client_algo(char *pos, unsigned int size)
{

    if (pos) {
	struct commalist_s list={pos, 0, size};

	return ssh_get_mac_list(&list);

    }

    return ssh_get_mac_list(NULL);

}

/* same as client */

static unsigned int get_mac_server_algo(char *pos, unsigned int size)
{

    if (pos) {
	struct commalist_s list={pos, 0, size};

	return ssh_get_mac_list(&list);

    }

    return ssh_get_mac_list(NULL);

}

static unsigned int get_compression_client_algo(char *pos, unsigned int size)
{

    if (pos) {
	struct commalist_s list={pos, 0, size};

	return ssh_get_compression_list(&list);

    }

    return ssh_get_compression_list(NULL);

}

/* same as client */

static unsigned int get_compression_server_algo(char *pos, unsigned int size)
{

    if (pos) {
	struct commalist_s list={pos, 0, size};

	return ssh_get_compression_list(&list);

    }

    return ssh_get_compression_list(NULL);

}

/* languages not supported yet */

static unsigned int get_lang_client_names(char *pos, unsigned int size)
{
    return 0;
}

static unsigned int get_lang_server_names(char *pos, unsigned int size)
{
    return 0;
}


int send_kexinit(struct ssh_session_s *session, struct ssh_payload_s *payload, void *ptr)
{

    if (payload) {
	char *pos=payload->buffer;
	unsigned int len=0;

	*pos=SSH_MSG_KEXINIT;
	pos++;

	memset(pos, '\0', 16);
	pos+=fill_random(pos, 16);

	len=get_kex_algo(pos+4, (unsigned int) (payload->buffer + payload->len - pos));

	if (len>0) {

	    store_uint32(pos, len);
	    pos+=4+len;

	} else {

	    session->status.error=ENOBUFS;
	    return -1;

	}

	len=get_server_hostkey_algo(pos+4, (unsigned int) (payload->buffer + payload->len - pos));

	if (len>0) {

	    store_uint32(pos, len);
	    pos+=4+len;

	} else {

	    session->status.error=ENOBUFS;
	    return -1;

	}

	len=get_encryption_client_algo(pos+4, (unsigned int) (payload->buffer + payload->len - pos));

	if (len>0) {

	    store_uint32(pos, len);
	    pos+=4+len;

	} else {

	    session->status.error=ENOBUFS;
	    return -1;

	}

	len=get_encryption_server_algo(pos+4, (unsigned int) (payload->buffer + payload->len - pos));

	if (len>0) {

	    store_uint32(pos, len);
	    pos+=4+len;

	} else {

	    session->status.error=ENOBUFS;
	    return -1;

	}

	len=get_mac_client_algo(pos+4, (unsigned int) (payload->buffer + payload->len - pos));

	if (len>0) {

	    store_uint32(pos, len);
	    pos+=4+len;

	} else {

	    session->status.error=ENOBUFS;
	    return -1;

	}

	len=get_mac_server_algo(pos+4, (unsigned int) (payload->buffer + payload->len - pos));

	if (len>0) {

	    store_uint32(pos, len);
	    pos+=4+len;

	} else {

	    session->status.error=ENOBUFS;
	    return -1;

	}

	len=get_compression_client_algo(pos+4, (unsigned int) (payload->buffer + payload->len - pos));

	if (len>0) {

	    store_uint32(pos, len);
	    pos+=4+len;

	} else {

	    session->status.error=ENOBUFS;
	    return -1;

	}

	len=get_compression_server_algo(pos+4, (unsigned int) (payload->buffer + payload->len - pos));

	if (len>0) {

	    store_uint32(pos, len);
	    pos+=4+len;

	} else {

	    session->status.error=ENOBUFS;
	    return -1;

	}

	len=get_lang_client_names(pos+4, (unsigned int) (payload->buffer + payload->len - pos));

	if (len>=0) {

	    store_uint32(pos, len);
	    pos+=4+len;

	} else {

	    session->status.error=ENOBUFS;
	    return -1;

	}

	len=get_lang_server_names(pos+4, (unsigned int) (payload->buffer + payload->len - pos));

	if (len>=0) {

	    store_uint32(pos, len);
	    pos+=4+len;

	} else {

	    session->status.error=ENOBUFS;
	    return -1;

	}

	if ((unsigned int) (payload->buffer + payload->len - pos) < 5 ) {

	    session->status.error=ENOBUFS;
	    return -1;

	} else {

	    /* first_kex_packet_follows */

	    *pos=0;
	    pos++;

	    /* trailing uint32 0 */

	    store_uint32(pos, 0);
	    pos+=4;

	}

	payload->len=(unsigned int) (pos - payload->buffer);

	/*
	    copy the payload for the computation of the H (RFC4253 8.  Diffie-Hellman Key Exchange)
	    (what if another method for key exchange is used?)
	*/

	if (store_kexinit_client(session, payload, &session->status.error)==0) {

	    logoutput("send_kexinit: stored client kexinit message");

	} else {

	    logoutput("send_kexinit: error storing kexinit message (%i:%s)", session->status.error, strerror(session->status.error));

	}

	return payload->len;

    } else {
	unsigned int len=0;

	len=1 + 16; /* byte SSH_MSG_KEXINIT plus cookie 16 bytes */

	len+=4+get_kex_algo(NULL, 0);
	len+=4+get_server_hostkey_algo(NULL, 0);
	len+=4+get_encryption_client_algo(NULL, 0);
	len+=4+get_encryption_server_algo(NULL, 0);
	len+=4+get_mac_client_algo(NULL, 0);
	len+=4+get_mac_server_algo(NULL, 0);
	len+=4+get_compression_client_algo(NULL, 0);
	len+=4+get_compression_server_algo(NULL, 0);
	len+=4+get_lang_client_names(NULL, 0);
	len+=4+get_lang_server_names(NULL, 0);

	len+=1 + 4; /* one byte for first_kex_packet_follows plus uint32 (reserved for future extension) */

	return len;

    }

    return -1;
}

int send_newkeys(struct ssh_session_s *session, struct ssh_payload_s *payload, void *ptr)
{

    if (payload) {

	logoutput("send_newkeys: len %i", payload->len);

	if (payload->len<1) return -1;
	payload->buffer[0]=(unsigned char) SSH_MSG_NEWKEYS;
	return 1;

    } else {

	return 1; /* byte SSH_MSG_NEWKEYS */

    }

    return -1;
}
