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

#include "common-utils/utils.h"

#include "ssh-utils.h"
#include "ssh-common-protocol.h"
#include "ssh-common.h"
#include "ssh-data.h"
#include "ssh-connections.h"
#include "ssh-receive.h"
#include "ssh-send.h"

#include "pk/openssh-localdb.h"
#include "pk/pk-types.h"

static unsigned int write_H(struct msg_buffer_s *mb, struct ssh_connection_s *connection, struct ssh_keyex_s *k, struct ssh_key_s *pkey)
{
    struct ssh_session_s *session=get_ssh_connection_session(connection);
    struct ssh_dh_s *dh=&k->method.dh;
    struct ssh_setup_s *setup=&connection->setup;
    struct keyex_ops_s *ops=k->ops;

    msg_write_ssh_string(mb, 's', (void *) &session->data.greeter_client);
    msg_write_ssh_string(mb, 's', (void *) &session->data.greeter_server);
    msg_write_ssh_string(mb, 's', (void *) &setup->phase.transport.type.kex.kexinit_client);
    msg_write_ssh_string(mb, 's', (void *) &setup->phase.transport.type.kex.kexinit_server);
    msg_write_pkey(mb, pkey, PK_DATA_FORMAT_SSH_STRING);
    (* ops->msg_write_client_key)(mb, k);
    (* ops->msg_write_server_key)(mb, k);
    (* ops->msg_write_sharedkey)(mb, k);

    return mb->pos;

}

int create_H(struct ssh_connection_s *connection, struct ssh_keyex_s *k, struct ssh_key_s *pkey, struct ssh_hash_s *H)
{
    struct msg_buffer_s mb=INIT_SSH_MSG_BUFFER;
    unsigned int len=write_H(&mb, connection, k, pkey) + 64;
    char buffer[len];
    unsigned int error=0;

    set_msg_buffer(&mb, buffer, len);
    len=write_H(&mb, connection, k, pkey);

    if (mb.error==0) {

	len=create_hash(buffer, len, H, &mb.error);
	if (len>0) return 0;

    }

    if (mb.error==0) mb.error=EIO;
    logoutput("create_H: error %i creating H (%s)", mb.error, strerror(mb.error));
    return -1;

}

/* estimate the size of the buffer required to create enough keymaterial of length keylen */

static unsigned int estimate_buffer_size(unsigned int lenSessionId, struct ssh_keyex_s *k, unsigned int lenH, unsigned int hashlen, unsigned int keylen)
{
    struct ssh_dh_s *dh=&k->method.dh;
    unsigned int count=0;
    unsigned int len=0;
    unsigned int lenK = 4 + get_nbytes_ssh_mpint(&dh->sharedkey);

    /* count the number of hashes required to fill the whole key */

    logoutput("estimate_buffer_size: len H %i hashlen %i keylen %i", lenH, hashlen, keylen);

    count=keylen / hashlen;
    if ((keylen % hashlen) > 0) count++;

    /* basically (count - 1) * hashlen extra bytes */

    len = lenK + lenH + count * hashlen;
    if (lenK + lenH + 1 + lenSessionId > len) len=lenK + lenH + 1 + lenSessionId;

    return len;

}

static void _create_keyx_hash(struct ssh_connection_s *connection, struct ssh_keyex_s *k, unsigned char singlechar, struct ssh_hash_s *H, struct common_buffer_s *key)
{
    unsigned int hashlen=get_hash_size(k->digestname);
    char hashdata[sizeof(struct ssh_hash_s) + hashlen];
    struct ssh_hash_s *out=(struct ssh_hash_s *) hashdata;
    struct ssh_session_s *session=get_ssh_connection_session(connection);
    struct ssh_string_s *sessionId=&session->data.sessionid;
    struct msg_buffer_s mb=INIT_SSH_MSG_BUFFER;
    unsigned int len = estimate_buffer_size(sessionId->len, k, H->len, hashlen, key->size);
    char buffer[len];
    struct ssh_dh_s *dh=&k->method.dh;
    struct keyex_ops_s *ops=k->ops;
    unsigned int error=0;

    set_msg_buffer(&mb, buffer, len);
    init_ssh_hash(out, k->digestname, hashlen);

    /* create hash of K || H || "X" || session_id */

    (* ops->msg_write_sharedkey)(&mb, k);
    msg_write_bytes(&mb, (unsigned char *) H->digest, H->len);
    msg_write_byte(&mb, singlechar);
    msg_write_bytes(&mb, (unsigned char *) sessionId->ptr, sessionId->len);

    if (out->size >= key->size) {

	/* enough data for the key */

	if (create_hash(mb.data, mb.pos, out, &error)==0) goto error;
	memcpy(key->ptr, out->digest, key->size);
	key->len=key->size;

    } else {

	/* key requires more data */

	// out.ptr=key->ptr;
	// out.len=hashlen;

	if (create_hash(mb.data, mb.pos, out, &error)==0) goto error;
	memcpy(key->ptr, out->digest, out->size);
	key->len=out->size;

	/*
	    not enough data for key: create new hashes according to
	    RFC4253 7.2
	    and append to the key
	*/

	/* create new hash K||H||K1 */

	mb.pos=0;
	(* ops->msg_write_sharedkey)(&mb, k);
	msg_write_bytes(&mb, (unsigned char *) H->digest, H->len);

	append:

	/* append previous hash K1, K2, .... 
	    to create a new hash K2, K3, .... */

	msg_write_bytes(&mb, (unsigned char *) out->digest, out->len);
	if (create_hash(mb.data, mb.pos, out, &error)==0) goto error;

	if (key->len + out->size >= key->size) {

	    /* enough */

	    memcpy(key->ptr + key->len, out->digest, key->size - key->len);
	    key->len=key->size;

	} else {

	    memcpy(key->ptr + key->len, out->digest, out->size);
	    key->len+=out->size;
	    goto append;

	}

    }

    return;

    error:

    logoutput_warning("create_keyx_hashes: error (%i:%s) creating hash", error, strerror(error));

}

static void init_data_buffer(char *data, unsigned int size, struct common_buffer_s *buffer)
{
    memset(data, '\0', size);
    buffer->ptr=data;
    buffer->size=size;
    buffer->len=0;
}

static int copy_buffer_ssh_string(struct common_buffer_s *b, struct ssh_string_s *s)
{
    return (create_ssh_string(s, b->size, b->ptr)==b->size ? 0 : -1);
}

int create_keyx_hashes(struct ssh_connection_s *connection, struct ssh_keyex_s *k, struct ssh_hash_s *H, unsigned int *error)
{
    struct ssh_session_s *session=get_ssh_connection_session(connection);
    struct ssh_setup_s *setup=&connection->setup;
    struct ssh_keyexchange_s *kex=&setup->phase.transport.type.kex;
    struct algo_list_s *algos=kex->algos;
    unsigned int keylen=0;
    int index=0;

    /* iv cipher client to server: c2s
	get the length of the iv from the encrypt ops belonging to the algo chosen */

    keylen=0;
    index=kex->chosen[SSH_ALGO_TYPE_CIPHER_C2S];
    if (index>=0) {
	struct encrypt_ops_s *ops=(struct encrypt_ops_s *) algos[index].ptr;

	keylen=(* ops->get_cipher_ivsize)(algos[index].sshname);

    }

    if (keylen>0) {
	char data[keylen];
	struct common_buffer_s buffer;
	struct ssh_string_s *iv=&kex->cipher_iv_c2s;

	logoutput("create_keyx_hashes: iv size %i for cipher c2s %s", keylen, algos[index].sshname);

	init_data_buffer(data, keylen, &buffer);
	_create_keyx_hash(connection, k, 'A', H, &buffer);

	if (copy_buffer_ssh_string(&buffer, iv)==-1) {

	    *error=ENOMEM;
	    goto error;

	}

    } else {

	if (index>=0) {

	    logoutput("create_keyx_hashes: iv size zero for cipher c2s %s", algos[index].sshname);

	} else {

	    logoutput("create_keyx_hashes: no cipher c2s");

	}

    }

    /* iv cipher server to client: s2c */

    keylen=0;
    index=kex->chosen[SSH_ALGO_TYPE_CIPHER_S2C];
    if (index>=0) {
	struct decrypt_ops_s *ops=(struct decrypt_ops_s *) algos[index].ptr;

	keylen=(* ops->get_cipher_ivsize)(algos[index].sshname);

    }

    if (keylen>0) {
	char data[keylen];
	struct common_buffer_s buffer;
	struct ssh_string_s *iv=&kex->cipher_iv_s2c;

	logoutput("create_keyx_hashes: iv size %i for cipher s2c %s", keylen, algos[index].sshname);

	init_data_buffer(data, keylen, &buffer);
	_create_keyx_hash(connection, k, 'B', H, &buffer);

	if (copy_buffer_ssh_string(&buffer, iv)==-1) {

	    *error=ENOMEM;
	    goto error;

	}

    } else {

	if (index>=0) {

	    logoutput("create_keyx_hashes: iv size zero for cipher s2c %s", algos[index].sshname);

	} else {

	    logoutput("create_keyx_hashes: no cipher s2c");

	}

    }

    /* encryption key client to server */

    keylen=0;
    index=kex->chosen[SSH_ALGO_TYPE_CIPHER_C2S];
    if (index>=0) {
	struct encrypt_ops_s *ops=(struct encrypt_ops_s *) algos[index].ptr;

	keylen=(* ops->get_cipher_keysize)(algos[index].sshname);

    }

    if (keylen>0) {
	char data[keylen];
	struct common_buffer_s buffer;
	struct ssh_string_s *key=&kex->cipher_key_c2s;

	logoutput("create_keyx_hashes: keysize %i for cipher c2s %s", keylen, algos[index].sshname);

	init_data_buffer(data, keylen, &buffer);
	_create_keyx_hash(connection, k, 'C', H, &buffer);

	if (copy_buffer_ssh_string(&buffer, key)==-1) {

	    *error=ENOMEM;
	    goto error;

	}

    } else {

	if (index>=0) {

	    logoutput("create_keyx_hashes: keylen zero for cipher c2s %s", algos[index].sshname);

	} else {

	    logoutput("create_keyx_hashes: no cipher c2s");

	}

    }

    /* encryption key server to client */

    keylen=0;
    index=kex->chosen[SSH_ALGO_TYPE_CIPHER_S2C];
    if (index>=0) {
	struct decrypt_ops_s *ops=(struct decrypt_ops_s *) algos[index].ptr;

	keylen=(* ops->get_cipher_keysize)(algos[index].sshname);

    }

    if (keylen>0) {
	char data[keylen];
	struct common_buffer_s buffer;
	struct ssh_string_s *key=&kex->cipher_key_s2c;

	logoutput("create_keyx_hashes: keysize %i for cipher s2c %s", keylen, algos[index].sshname);

	init_data_buffer(data, keylen, &buffer);
	_create_keyx_hash(connection, k, 'D', H, &buffer);

	if (copy_buffer_ssh_string(&buffer, key)==-1) {

	    *error=ENOMEM;
	    goto error;

	}

    } else {

	if (index>=0) {

	    logoutput("create_keyx_hashes: keylen zero for cipher s2c %s", algos[index].sshname);

	} else {

	    logoutput("create_keyx_hashes: no cipher s2c");

	}

    }

    /* hmac key client to server */

    keylen=0;
    index=kex->chosen[SSH_ALGO_TYPE_HMAC_C2S];
    if (index>=0) {
	struct encrypt_ops_s *ops=(struct encrypt_ops_s *) algos[index].ptr;

	keylen=(* ops->get_hmac_keysize)(algos[index].sshname);

    }

    if (keylen>0) {
	char data[keylen];
	struct common_buffer_s buffer;
	struct ssh_string_s *key=&kex->hmac_key_c2s;

	logoutput("create_keyx_hashes: keysize %i for hmac c2s %s", keylen, algos[index].sshname);

	init_data_buffer(data, keylen, &buffer);
	_create_keyx_hash(connection, k, 'E', H, &buffer);

	if (copy_buffer_ssh_string(&buffer, key)==-1) {

	    *error=ENOMEM;
	    goto error;

	}

    } else {

	if (index>=0) {

	    logoutput("create_keyx_hashes: keylen zero for hmac c2s %s", algos[index].sshname);

	} else {

	    logoutput("create_keyx_hashes: no hmac c2s");

	}

    }

    /* hmac key server to client */

    keylen=0;
    index=kex->chosen[SSH_ALGO_TYPE_HMAC_S2C];
    if (index>=0) {
	struct decrypt_ops_s *ops=(struct decrypt_ops_s *) algos[index].ptr;

	keylen=(* ops->get_hmac_keysize)(algos[index].sshname);

    }

    if (keylen>0) {
	char data[keylen];
	struct common_buffer_s buffer;
	struct ssh_string_s *key=&kex->hmac_key_s2c;

	logoutput("create_keyx_hashes: keysize %i for hmac s2c %s", keylen, algos[index].sshname);

	init_data_buffer(data, keylen, &buffer);
	_create_keyx_hash(connection, k, 'F', H, &buffer);

	if (copy_buffer_ssh_string(&buffer, key)==-1) {

	    *error=ENOMEM;
	    goto error;

	}

    } else {

	if (index>=0) {

	    logoutput("create_keyx_hashes: keylen zero for hmac s2c %s", algos[index].sshname);

	} else {

	    logoutput("create_keyx_hashes: no hmac s2c");

	}

    }

    return 0;

    error:
    logoutput("create_keyx_hashes: error (%i:%s) creating keys", *error, strerror(*error));
    return -1;

}
