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
#include <sys/stat.h>

#include "logging.h"
#include "main.h"

#include "utils.h"

#include "ssh-common-protocol.h"
#include "ssh-common.h"
#include "ssh-utils.h"
#include "ssh-keyx-dh-libgcrypt.h"
#include "ssh-data.h"

#include "ssh-receive.h"
#include "ssh-queue-payload.h"

#include "ssh-send.h"
#include "ssh-send-greeter.h"
#include "ssh-encryption.h"
#include "ssh-mac.h"
#include "ssh-pubkey.h"
#include "ssh-pubkey-utils.h"
#include "ssh-connection.h"

#include "ctx-keystore.h"

static unsigned char dh_p_group1_value[] = {
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xC9, 0x0F, 0xDA, 0xA2,
        0x21, 0x68, 0xC2, 0x34, 0xC4, 0xC6, 0x62, 0x8B, 0x80, 0xDC, 0x1C, 0xD1,
        0x29, 0x02, 0x4E, 0x08, 0x8A, 0x67, 0xCC, 0x74, 0x02, 0x0B, 0xBE, 0xA6,
        0x3B, 0x13, 0x9B, 0x22, 0x51, 0x4A, 0x08, 0x79, 0x8E, 0x34, 0x04, 0xDD,
        0xEF, 0x95, 0x19, 0xB3, 0xCD, 0x3A, 0x43, 0x1B, 0x30, 0x2B, 0x0A, 0x6D,
        0xF2, 0x5F, 0x14, 0x37, 0x4F, 0xE1, 0x35, 0x6D, 0x6D, 0x51, 0xC2, 0x45,
        0xE4, 0x85, 0xB5, 0x76, 0x62, 0x5E, 0x7E, 0xC6, 0xF4, 0x4C, 0x42, 0xE9,
        0xA6, 0x37, 0xED, 0x6B, 0x0B, 0xFF, 0x5C, 0xB6, 0xF4, 0x06, 0xB7, 0xED,
        0xEE, 0x38, 0x6B, 0xFB, 0x5A, 0x89, 0x9F, 0xA5, 0xAE, 0x9F, 0x24, 0x11,
        0x7C, 0x4B, 0x1F, 0xE6, 0x49, 0x28, 0x66, 0x51, 0xEC, 0xE6, 0x53, 0x81,
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};

#define P_GROUP1_LEN 128

static unsigned char dh_g_group1_value[] = {0x02};

#define G_GROUP1_LEN 1

static unsigned char dh_p_group14_value[] = {
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xC9, 0x0F, 0xDA, 0xA2,
        0x21, 0x68, 0xC2, 0x34, 0xC4, 0xC6, 0x62, 0x8B, 0x80, 0xDC, 0x1C, 0xD1,
        0x29, 0x02, 0x4E, 0x08, 0x8A, 0x67, 0xCC, 0x74, 0x02, 0x0B, 0xBE, 0xA6,
        0x3B, 0x13, 0x9B, 0x22, 0x51, 0x4A, 0x08, 0x79, 0x8E, 0x34, 0x04, 0xDD,
        0xEF, 0x95, 0x19, 0xB3, 0xCD, 0x3A, 0x43, 0x1B, 0x30, 0x2B, 0x0A, 0x6D,
        0xF2, 0x5F, 0x14, 0x37, 0x4F, 0xE1, 0x35, 0x6D, 0x6D, 0x51, 0xC2, 0x45,
        0xE4, 0x85, 0xB5, 0x76, 0x62, 0x5E, 0x7E, 0xC6, 0xF4, 0x4C, 0x42, 0xE9,
        0xA6, 0x37, 0xED, 0x6B, 0x0B, 0xFF, 0x5C, 0xB6, 0xF4, 0x06, 0xB7, 0xED,
        0xEE, 0x38, 0x6B, 0xFB, 0x5A, 0x89, 0x9F, 0xA5, 0xAE, 0x9F, 0x24, 0x11,
        0x7C, 0x4B, 0x1F, 0xE6, 0x49, 0x28, 0x66, 0x51, 0xEC, 0xE4, 0x5B, 0x3D,
        0xC2, 0x00, 0x7C, 0xB8, 0xA1, 0x63, 0xBF, 0x05, 0x98, 0xDA, 0x48, 0x36,
        0x1C, 0x55, 0xD3, 0x9A, 0x69, 0x16, 0x3F, 0xA8, 0xFD, 0x24, 0xCF, 0x5F,
        0x83, 0x65, 0x5D, 0x23, 0xDC, 0xA3, 0xAD, 0x96, 0x1C, 0x62, 0xF3, 0x56,
        0x20, 0x85, 0x52, 0xBB, 0x9E, 0xD5, 0x29, 0x07, 0x70, 0x96, 0x96, 0x6D,
        0x67, 0x0C, 0x35, 0x4E, 0x4A, 0xBC, 0x98, 0x04, 0xF1, 0x74, 0x6C, 0x08,
        0xCA, 0x18, 0x21, 0x7C, 0x32, 0x90, 0x5E, 0x46, 0x2E, 0x36, 0xCE, 0x3B,
        0xE3, 0x9E, 0x77, 0x2C, 0x18, 0x0E, 0x86, 0x03, 0x9B, 0x27, 0x83, 0xA2,
        0xEC, 0x07, 0xA2, 0x8F, 0xB5, 0xC5, 0x5D, 0xF0, 0x6F, 0x4C, 0x52, 0xC9,
        0xDE, 0x2B, 0xCB, 0xF6, 0x95, 0x58, 0x17, 0x18, 0x39, 0x95, 0x49, 0x7C,
        0xEA, 0x95, 0x6A, 0xE5, 0x15, 0xD2, 0x26, 0x18, 0x98, 0xFA, 0x05, 0x10,
        0x15, 0x72, 0x8E, 0x5A, 0x8A, 0xAC, 0xAA, 0x68, 0xFF, 0xFF, 0xFF, 0xFF,
        0xFF, 0xFF, 0xFF, 0xFF};

#define P_GROUP14_LEN 256

static unsigned char dh_g_group14_value[] = {0x02};

#define G_GROUP14_LEN 1

static int create_H(struct ssh_session_s *session, struct common_buffer_s *out)
{
    struct ssh_key_s *hostkey=&session->crypto.pubkey.server_hostkey;
    struct ssh_keyx_s *keyx=&session->crypto.keyx;
    struct ssh_dh_s *dh=&keyx->method.dh;
    unsigned char buffer[4096]; /* buffer large enough to create H */
    unsigned int len=0;
    unsigned char *pos=&buffer[0];
    struct common_buffer_s input;
    unsigned int error=0;

    /* create exchange H */

    /* client identification string */

    len=create_greeter(NULL);

    if (len>0) {

	store_uint32(pos, (uint32_t) len);
	pos+=4;
	len=create_greeter(pos);
	pos+=len;

    } else {

	session->status.error=EINVAL;
	return -1;

    }

    /* server greeter string */

    len=session->data.greeter_server.len;

    if (len>0) {

	store_uint32(pos, (uint32_t) len);
	pos+=4;
	memcpy(pos, session->data.greeter_server.ptr, len);
	pos+=len;

    } else {

	session->status.error=EINVAL;
	return -1;

    }

    /* client SSH_MSG_KEXINIT message */

    len=session->crypto.keydata.kexinit_client.len;

    if (len>0) {

	store_uint32(pos, (uint32_t) len);
	pos+=4;
	memcpy(pos, session->crypto.keydata.kexinit_client.ptr, len);
	pos+=len;

    } else {

	session->status.error=EINVAL;
	return -1;

    }

    /* server SSH_MSG_KEXINIT message */

    len=session->crypto.keydata.kexinit_server.len;

    if (len>0) {

	store_uint32(pos, (uint32_t) len);
	pos+=4;
	memcpy(pos, session->crypto.keydata.kexinit_server.ptr, len);
	pos+=len;

    } else {

	session->status.error=EINVAL;
	return -1;

    }

    /* server public hostkey */

    len=hostkey->data.len;

    if (len>0) {

	store_uint32(pos, (uint32_t) len);
	pos+=4;
	memcpy(pos, hostkey->data.ptr, len);
	pos+=len;

    } else {

	session->status.error=EINVAL;
	return -1;

    }

    /* dh e parameter */

    len=(* dh->write_e)(dh, pos, (unsigned int) (&buffer[0] + 4096 - pos));

    if (len==0) {

	session->status.error=EINVAL;
	return -1;

    }

    pos+=len;

    /* dh f parameter */

    len=(* dh->write_f)(dh, pos, (unsigned int) (&buffer[0] + 4096 - pos));

    if (len==0) {

	session->status.error=EINVAL;
	return -1;

    }

    pos+=len;

    /* dh K parameter */

    len=(* dh->write_K)(dh, pos, (unsigned int) (&buffer[0] + 4096 - pos));

    if (len==0) {

	session->status.error=EINVAL;
	return -1;

    }

    pos+=len;

    /* compute hash (name of the hashtype is in keyx->digestname) */

    init_common_buffer(&input);
    input.len=(unsigned int) (pos - &buffer[0]);
    input.ptr=(char *) &buffer[0];

    logoutput("create_H: get hash H of %i bytes using %s", input.len, keyx->digestname);

    len=hash(keyx->digestname, &input, out, &error);
    if (len==0) return -1;

    return len;

}

static void _create_keyx_hash(struct ssh_session_s *session, unsigned char singlechar, struct common_buffer_s *H, struct common_buffer_s *key)
{
    struct ssh_keyx_s *keyx=&session->crypto.keyx;
    struct ssh_dh_s *dh=&keyx->method.dh;
    unsigned int hashlen=get_digest_len(keyx->digestname);
    unsigned char out[hashlen];
    unsigned char *buffer=NULL;
    size_t size=2048;
    unsigned char *pos=NULL;
    struct common_buffer_s input;
    struct common_buffer_s output;
    unsigned int error=0;
    unsigned int len=0;

    buffer=(unsigned char *) malloc(size);

    if ( ! buffer) {

	error=ENOMEM;
	goto error;

    }

    init_common_buffer(&input);
    input.ptr=(char *) buffer;
    input.size=size;
    input.len=0;

    pos=buffer;

    /* dh K parameter */

    len=(* dh->write_K)(dh, pos, input.size - input.len);

    if (len==0) {

	error=EINVAL;
	goto error;

    }

    pos+=len;
    input.len+=len;

    /* H */

    memcpy(pos, (char *) H->ptr, H->len);
    pos+=H->len;
    input.len+=H->len;

    /* "A" or "B", or ...*/

    *pos=singlechar;
    pos++;
    input.len++;

    /* session id */

    memcpy(pos, session->data.sessionid.ptr, session->data.sessionid.len);
    pos+=session->data.sessionid.len;
    input.len+=session->data.sessionid.len;

    /* create hash of K || H || "X" || session_id */

    output.len=hashlen;
    output.ptr=(char *) &out[0];

    len=hash(keyx->digestname, &input, &output, &error);
    if (len==0) goto error;

    if (output.len >= key->size) {

	/* enough data for the key */

	memcpy(key->ptr, output.ptr, key->size);
	key->len=key->size;

    } else {

	/*
	    not enough data for key: create new hashes according to
	    RFC4253 7.2
	    and append to the key
	*/

	memcpy(key->ptr, output.ptr, output.len);
	key->len+=output.len;

	/* create new hash K||H||K1 */

	memset(input.ptr, '\0', input.size);
	pos=buffer;
	input.len=0;

	/* K */

	len=(* dh->write_K)(dh, pos, input.size - input.len);

	if (len==0) {

	    error=EINVAL;
	    goto error;

	}

	pos+=len;
	input.len+=len;

	/* H */

	memcpy(pos, H->ptr, H->len);
	pos+=H->len;
	input.len+=H->len;

	append:

	/* check size is enough */

	if (input.len + output.len > input.size) {

	    /* does not fit */

	    size+=(output.len > 512) ? output.len : 512;
	    buffer=realloc(buffer, size);

	    if (! buffer) {

		error=ENOMEM;
		goto error;

	    }

	    if (input.ptr != buffer) {

		pos=(unsigned char *) (buffer + input.len);

	    }

	    input.size=size;
	    goto append;

	}

	/* append previous hash */

	memcpy(pos, output.ptr, output.len);
	pos+=output.len;
	input.len+=output.len;

	/* create a new hash K2, K3, .... */

	len=hash(keyx->digestname, &input, &output, &error);
	if (len==0) goto error;

	if (key->len + output.len >= key->size) {

	    /* enough */

	    memcpy(key->ptr+key->len, output.ptr, key->size - key->len);
	    key->len=key->size;

	} else {

	    memcpy(key->ptr+key->len, output.ptr, output.len);
	    key->len+=output.len;

	    goto append;

	}

    }

    if (buffer) {

	free(buffer);
	buffer=NULL;

    }

    return;

    error:

    logoutput_warning("create_keyx_hashes: error (%i:%s) creating hash", error, strerror(error));

    if (buffer) {

	free(buffer);
	buffer=NULL;

    }

}

static int create_keyx_hashes(struct ssh_session_s *session, struct common_buffer_s *H, struct ssh_init_algo *algos)
{
    unsigned int keylen=0;
    unsigned int error=0;

    /*
	iv client to server
	c2s
    */

    keylen=get_session_ivsize(session, algos->encryption_c2s, algos->hmac_c2s);

    if (keylen>0) {
	unsigned char buffer[keylen];
	struct ssh_string_s key;
	struct common_buffer_s buff;

	logoutput("create_keyx_hashes: iv size %i for cipher %s", keylen, algos->encryption_c2s);

	memset(&buffer[0], '\0', keylen);

	init_common_buffer(&buff);
	buff.ptr=(char *) &buffer[0];
	buff.size=keylen;
	buff.len=0;

	_create_keyx_hash(session, 'A', H, &buff);

	key.ptr=buff.ptr;
	key.len=buff.len;

	if (set_session_iv_c2s(session, algos->encryption_c2s, algos->hmac_c2s, &key)==-1) {

	    session->status.error=ENOMEM;
	    goto error;

	}

    } else {

	logoutput("create_keyx_hashes: iv size zero for cipher %s", algos->encryption_c2s);

    }

    /*
	iv server to client
	s2c
    */

    keylen=get_session_ivsize(session, algos->encryption_s2c, algos->hmac_s2c);

    if (keylen>0) {
	unsigned char buffer[keylen];
	struct ssh_string_s key;
	struct common_buffer_s buff;

	logoutput("create_keyx_hashes: iv size %i for cipher %s", keylen, algos->encryption_s2c);

	memset(&buffer[0], '\0', keylen);

	init_common_buffer(&buff);
	buff.ptr=(char *)&buffer[0];
	buff.size=keylen;
	buff.len=0;

	_create_keyx_hash(session, 'B', H, &buff);

	key.ptr=buff.ptr;
	key.len=buff.len;

	if (set_session_iv_s2c(session, algos->encryption_s2c, algos->hmac_s2c, &key)==-1) {

	    session->status.error=ENOMEM;
	    goto error;

	}

    } else {

	logoutput("create_keyx_hashes: iv size zero for cipher %s", algos->encryption_s2c);

    }

    /* encryption key client to server */

    keylen=get_cipher_keysize(session, algos->encryption_c2s);

    if (keylen>0) {
	unsigned char buffer[keylen];
	struct ssh_string_s key;
	struct common_buffer_s buff;

	logoutput("create_keyx_hashes: keysize %i for cipher %s", keylen, algos->encryption_c2s);

	memset(&buffer[0], '\0', keylen);

	init_common_buffer(&buff);
	buff.ptr=(char *)&buffer[0];
	buff.size=keylen;
	buff.len=0;

	_create_keyx_hash(session, 'C', H, &buff);

	key.ptr=buff.ptr;
	key.len=buff.len;

	if (set_cipher_key_c2s(session, algos->encryption_c2s, &key)==-1) {

	    session->status.error=ENOMEM;
	    goto error;

	}

    } else {

	logoutput("create_keyx_hashes: keylen zero for cipher %s", algos->encryption_c2s);

    }

    /* encryption key server to client */

    keylen=get_cipher_keysize(session, algos->encryption_s2c);

    if (keylen>0) {
	unsigned char buffer[keylen];
	struct ssh_string_s key;
	struct common_buffer_s buff;

	logoutput("create_keyx_hashes: keysize %i for cipher %s", keylen, algos->encryption_s2c);

	memset(&buffer[0], '\0', keylen);

	init_common_buffer(&buff);
	buff.ptr=(char *)&buffer[0];
	buff.size=keylen;
	buff.len=0;

	_create_keyx_hash(session, 'D', H, &buff);

	key.ptr=buff.ptr;
	key.len=buff.len;

	if (set_cipher_key_s2c(session, algos->encryption_s2c, &key)==-1) {

	    session->status.error=ENOMEM;
	    goto error;

	}

    } else {

	logoutput("create_keyx_hashes: keylen zero for cipher %s", algos->encryption_s2c);

    }

    /* integrity key client to server */

    keylen=get_mac_keylen(session, algos->hmac_c2s);

    if (keylen>0) {
	unsigned char buffer[keylen];
	struct ssh_string_s key;
	struct common_buffer_s buff;

	logoutput("create_keyx_hashes: keysize %i for mac %s", keylen, algos->hmac_c2s);

	memset(&buffer[0], '\0', keylen);

	init_common_buffer(&buff);
	buff.ptr=(char *)&buffer[0];
	buff.size=keylen;
	buff.len=0;

	_create_keyx_hash(session, 'E', H, &buff);

	key.ptr=buff.ptr;
	key.len=buff.len;

	logoutput("create_keyx_hashes: len mackey %i", key.len);

	if (set_mac_key_c2s(session, algos->hmac_c2s, &key)==-1) {

	    session->status.error=ENOMEM;
	    goto error;

	}

    } else {

	logoutput("create_keyx_hashes: keylen zero for mac %s", algos->hmac_c2s);

    }

    /* integrity key server to client */

    keylen=get_mac_keylen(session, algos->hmac_s2c);

    if (keylen>0) {
	unsigned char buffer[keylen];
	struct ssh_string_s key;
	struct common_buffer_s buff;

	logoutput("create_keyx_hashes: keysize %i for mac %s", keylen, algos->hmac_s2c);

	memset(&buffer[0], '\0', keylen);

	init_common_buffer(&buff);
	buff.ptr=(char *)&buffer[0];
	buff.size=keylen;
	buff.len=0;

	_create_keyx_hash(session, 'F', H, &buff);

	key.ptr=buff.ptr;
	key.len=buff.len;

	if (set_mac_key_s2c(session, algos->hmac_s2c, &key)==-1) {

	    session->status.error=ENOMEM;
	    goto error;

	}

    } else {

	logoutput("create_keyx_hashes: keylen zero for mac %s", algos->hmac_s2c);

    }

    return 0;

    error:

    logoutput("create_keyx_hashes: error (%i:%s) creating keys", session->status.error, strerror(session->status.error));

    return -1;

}

static int _send_kexdh_init_message(struct ssh_session_s *session, struct ssh_payload_s *payload, void *ptr)
{
    struct ssh_keyx_s *keyx=&session->crypto.keyx;
    struct ssh_dh_s *dh=&keyx->method.dh;

    if (payload==NULL) {
	unsigned int bits=(*dh->get_size_modgroup)(dh);

	/*
	    size of message:
	    1 SSH_MSG_KEYDH_INIT
	    4 + bytes for e (=bits/8)

	    take 64 + bits/8 for sure
	*/

	return 64 +  bits/8;

    } else {
	unsigned char *pos=payload->buffer;

	*pos=(unsigned char) SSH_MSG_KEXDH_INIT;
	pos++;
	pos+=(*dh->write_e)(dh, pos, (unsigned int) (payload->len + payload->buffer - pos));

	return (unsigned int) (pos - payload->buffer);

    }

    return 0;

}

static int read_keyx_dh_reply(struct ssh_session_s *session, struct ssh_payload_s *payload, struct ssh_init_algo *algos)
{
    struct ssh_key_s *hostkey=&session->crypto.pubkey.server_hostkey;
    struct ssh_keyx_s *keyx=&session->crypto.keyx;
    struct ssh_dh_s *dh=&keyx->method.dh;
    unsigned int hashlen=get_digest_len(keyx->digestname);
    unsigned char hash[hashlen];
    struct common_buffer_s H;
    unsigned int len=0;
    unsigned int error=0;
    struct common_buffer_s sigH;
    unsigned int left=0;
    struct common_buffer_s message;

    logoutput("read_keyx_dh_reply");

    /*
	message has following form:
	byte 	SSH_MSG_KEXDH_REPLY
	string	server public host key
	mpint	f
	string	signature of H
    */

    init_common_buffer(&sigH);
    init_common_buffer(&H);
    init_common_buffer(&message);

    message.ptr=payload->buffer;
    message.size=payload->len;
    message.len=payload->len;
    message.pos=message.ptr;

    left=payload->len;

    /* read servers public hostkey */

    if (left>5) {

	message.pos++; /* skip the first byte */
	len=get_uint32(message.pos);
	message.pos+=4;
	left-=5;

    } else {

	error=EIO;
	goto error;

    }

    if (len>0 && len < left) {

	hostkey->data.ptr=malloc(len);

	if (hostkey->data.ptr) {

	    memcpy(hostkey->data.ptr, message.pos, len);
	    hostkey->data.size=len;
	    hostkey->data.len=len;

	} else {

	    error=ENOMEM;
	    goto error;

	}

    } else {

	error=EIO;
	goto error;

    }

    message.pos+=len;
    left-=len;

    /* check the received public hostkey (against a "known hosts file" etcetera) */

    if (check_serverkey(session, hostkey)==0) {

	logoutput_info("keyx_read_dh_reply: check public key server success");

    } else {

	logoutput_info("keyx_read_dh_reply: check public key server failed");
	error=EACCES;
	goto error;

    }

    /* read parameters (type has been set in negotiation) */

    if (read_parameters_pubkey(session, hostkey, &error)==-1) {

	error=EIO;
	logoutput_info("keyx_read_dh_reply: reading parameters server public key failed: error %i:%s", error, strerror(error));
	goto error;

    }

    /* read f */

    len=(* dh->read_f)(dh, message.pos, left);

    if (len==0) {

	error=EIO;
	goto error;

    }

    dh->status=_DH_STATUS_FRECEIVED;
    message.pos+=len;
    left-=len;

    /* calculate K */

    (* dh->calc_K)(dh);

    /*

    check the received data containing the signature has the right format
    it has the following format (as used by ssh):

    - string			data containing signature of H

    this string is:

    - uint32			len of rest (n)
    - byte[n]			which is a combination of two strings:
	- string 		public key format like "ssh-rsa" and "ssh-dss"
	- string		signature blob

    see:

    RFC4253
	6.6.  Public Key Algorithms
	and
	8.  Diffie-Hellman Key Exchange
    */

    if (left>4) {

	len=get_uint32(message.pos);
	message.pos+=4;
	left-=4;

    } else {

	error=EIO;
	goto error;

    }

    if (len <= left && len>8) {
	unsigned char type=0;

	left=len;
	len=read_ssh_type_pubkey_buffer(&message, &type, &error);

	if (len==0 || ! (type==hostkey->type)) {

	    logoutput("keyx_read_dh_reply: error type signature different from server hostkey");
	    goto error;

	}

	left-=len;

    } else {

	logoutput("keyx_read_dh_reply: error length signature");
	error=EIO;
	goto error;

    }

    if (left>4) {

	len=get_uint32(message.pos);
	message.pos+=4;
	left-=4;

	if (len<=left) {

	    /* the actual signature blob
		extra check len is equal to expected hashlen? anyway if this is not the case
		the signature check will fail */

	    logoutput("keyx_read_dh_reply: found signature (%i bytes)", len);

	    sigH.len=len;
	    sigH.ptr=message.pos;
	    sigH.size=len;
	    sigH.pos=sigH.ptr;

	} else {

	    logoutput("keyx_read_dh_reply: error len signature (%i)", len);
	    error=EIO;
	    goto error;

	}

    } else {

	logoutput("keyx_read_dh_reply: error length signature");
	error=EIO;
	goto error;

    }

    /* check the signature is correct by creating the H self
	and verify using the public key of the server */

    H.len=hashlen;
    H.pos=NULL;
    H.ptr=&hash[0];
    H.size=hashlen;

    if (create_H(session, &H)==-1) {

	error=EIO;
	logoutput_info("keyx_read_dh_reply: error creating H (%i bytes)", hashlen);
	goto error;

    } else {

	logoutput_info("keyx_read_dh_reply: created H (%i bytes)", hashlen);

    }

    if (verify_sigH(session, hostkey, &H, &sigH)==-1) {

	error=EACCES;
	logoutput_info("keyx_read_dh_reply: check sig H failed");
	goto error;

    } else {

	logoutput_info("keyx_read_dh_reply: check sig H success");

    }

    /* store H as session identifier */

    if (store_ssh_session_id(session, H.ptr, H.len)==-1) {

	error=ENOMEM;
	logoutput_info("keyx_read_dh_reply: failed to store session id");
	goto error;

    }

    /* create the different hashes */

    if (create_keyx_hashes(session, &H, algos)==-1) {

	error=ENOMEM;
	logoutput_info("keyx_read_dh_reply: failed to create key hashes");
	goto error;

    }

    return 0;

    error:

    if (session->status.error==0) session->status.error=(error>0) ? error : EIO;
    logoutput("keyx_read_dh_reply: error reading reply: %i:%s", session->status.error, strerror(session->status.error));
    return -1;

}

/*
    start the "static" dh shared key exchange
    the mod group is already set (=static)

    see: RFC4253 8. Diffie-Hellman Key Exchange

    - first send a random number e to server
    - receive hostkey||f||sigH from server
    - check hostkey is really hostkey of server, calculate the shared key K, create the exchange hash H and verify the signature of H using the public key
*/

static int start_keyx_dh_static(struct ssh_session_s *session, struct ssh_init_algo *algos)
{
    struct ssh_keyx_s *keyx=&session->crypto.keyx;
    struct ssh_dh_s *dh=&keyx->method.dh;
    struct timespec expire;
    unsigned int error=0;
    unsigned int sequence=0;
    struct ssh_payload_s *payload=NULL;

    logoutput("start_keyx_dh_static");

    if (session->status.status != SESSION_STATUS_KEYEXCHANGE) {

	error=EINVAL;
	goto error;

    }

    session->status.substatus|=SUBSTATUS_KEYEXCHANGE_STARTED;

    /* client: calculate e */

    (* dh->calc_e)(dh);

    /* send the kexdh init message */

    if (send_ssh_message(session, _send_kexdh_init_message, NULL, &sequence)==-1) {

	error=session->status.error;
	logoutput("start_keyx_dh_static: error %i:%s sending kexdh_init", error, strerror(error));
	goto error;

    }

    dh->status=_DH_STATUS_ESEND;

    /* wait for SSH_MSG_KEXDH_REPLY */

    get_session_expire_init(session, &expire);
    payload=get_ssh_payload(session, &expire, &sequence, &error);

    if (! payload) {

	if (session->status.error==0) session->status.error=(error>0) ? error : EIO;
	logoutput("start_keyx_dh_static: error waiting for kexdh_reply");
	error=EIO;
	goto error;

    } else {

	if (payload->type == SSH_MSG_KEXDH_REPLY) {

	    if (read_keyx_dh_reply(session, payload, algos)==-1) {

		logoutput("start_keyx_dh_static: error reading dh reply");
		error=EIO;
		free(payload);
		goto error;

	    }

	} else {

	    logoutput("start_keyx_dh_static: error: received a %i message, expecting %i", payload->type, SSH_MSG_KEXDH_REPLY);
	    free(payload);
	    error=EPROTO;
	    goto error;

	}

	free(payload);

    }

    session->status.substatus|=SUBSTATUS_KEYEXCHANGE_FINISHED;
    return 0;

    error:

    if (session->status.error==0) session->status.error=(error>0) ? error : EIO;
    session->status.substatus|=SUBSTATUS_KEYEXCHANGE_ERROR;
    return -1;

}

static void free_keyx_dh_static(struct ssh_session_s *session)
{
    struct ssh_keyx_s *keyx=&session->crypto.keyx;
    struct ssh_dh_s *dh=&keyx->method.dh;

    (* dh->free)(dh);

}

int set_keyx_dh(struct ssh_session_s *session, const char *name, unsigned int *error)
{
    struct ssh_keyx_s *keyx=&session->crypto.keyx;
    struct ssh_dh_s *dh=&keyx->method.dh;

    memset(dh, 0, sizeof(struct ssh_dh_s));
    dh->status=_DH_STATUS_INIT;

    if (strcmp(name, "diffie-hellman-group1-sha1")==0) {

	strcpy(keyx->digestname, "sha1");
	keyx->start_keyx=start_keyx_dh_static;
	keyx->free=free_keyx_dh_static;

	return init_dh_libgcrypt(dh, dh_p_group1_value, P_GROUP1_LEN, dh_g_group1_value, G_GROUP1_LEN);

    } else if (strcmp(name, "diffie-hellman-group14-sha1")==0) {

	strcpy(keyx->digestname, "sha1");
	keyx->start_keyx=start_keyx_dh_static;
	keyx->free=free_keyx_dh_static;

	return init_dh_libgcrypt(dh, dh_p_group14_value, P_GROUP14_LEN, dh_g_group14_value, G_GROUP14_LEN);

    }

    *error=EINVAL;
    return -1;

}
