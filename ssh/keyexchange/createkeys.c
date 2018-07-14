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

#include "utils.h"

#include "ssh-common-protocol.h"
#include "ssh-common.h"
#include "ssh-utils.h"
#include "ssh-data.h"

#include "ssh-receive.h"
#include "ssh-send.h"
#include "pk/openssh-localdb.h"
#include "pk/pk-types.h"

static unsigned int write_H(struct msg_buffer_s *mb, struct ssh_session_s *session, struct ssh_keyx_s *keyx, struct ssh_key_s *pkey)
{
    struct ssh_dh_s *dh=&keyx->method.dh;

    logoutput("write_H");

    msg_write_ssh_string(mb, 's', (void *) &session->data.greeter_client);
    msg_write_ssh_string(mb, 's', (void *) &session->data.greeter_server);
    msg_write_ssh_string(mb, 's', (void *) &session->keyexchange->data.kexinit_client);
    msg_write_ssh_string(mb, 's', (void *) &session->keyexchange->data.kexinit_server);
    msg_write_pkey(mb, pkey, PK_DATA_FORMAT_SSH_STRING);

    // logoutput("write_H: A");
    (* keyx->msg_write_client_key)(mb, keyx);
    (* keyx->msg_write_server_key)(mb, keyx);
    (* keyx->msg_write_shared_K)(mb, keyx);

    return mb->pos;

}

int create_H(struct ssh_session_s *session, struct ssh_keyx_s *keyx, struct ssh_key_s *pkey, struct ssh_string_s *H)
{
    struct msg_buffer_s mb=INIT_SSH_MSG_BUFFER;
    unsigned int len=write_H(&mb, session, keyx, pkey) + 64;
    char buffer[len];
    unsigned int error=0;

    set_msg_buffer(&mb, buffer, len);
    len=write_H(&mb, session, keyx, pkey);

    if (mb.error==0) {

	len=create_hash(keyx->digestname, buffer, len, H, &mb.error);
	if (len>0) return 0;

    }

    if (mb.error==0) mb.error=EIO;
    logoutput("create_H: error %i creating H (%s)", mb.error, strerror(mb.error));
    return -1;

}

/* estimate the size of the buffer required to create enough keymaterial of length keylen */

static unsigned int estimate_buffer_size(unsigned int lenSessionId, struct ssh_keyx_s *keyx, unsigned int lenH, unsigned int hashlen, unsigned int keylen)
{
    struct ssh_dh_s *dh=&keyx->method.dh;
    unsigned int count=0;
    unsigned int len=0;
    unsigned int lenK = 4 + get_nbytes_ssh_mpint(&dh->K);

    /* count the number of hashes required to fill the whole key */

    count=keylen / hashlen;
    if ((keylen % hashlen) > 0) count++;

    /* basically (count - 1) * hashlen extra bytes */

    len = lenK + lenH + count * hashlen;
    if (lenK + lenH + 1 + lenSessionId > len) len=lenK + lenH + 1 + lenSessionId;

    return len;

}

static void _create_keyx_hash(struct ssh_session_s *session, struct ssh_keyx_s *keyx, unsigned char singlechar, struct ssh_string_s *H, struct common_buffer_s *key)
{
    unsigned int hashlen=create_hash(keyx->digestname, NULL, 0, NULL, NULL);
    struct ssh_string_s *sessionId=&session->data.sessionid;
    struct msg_buffer_s mb=INIT_SSH_MSG_BUFFER;
    unsigned int len = estimate_buffer_size(sessionId->len, keyx, H->len, hashlen, key->size);
    char buffer[len];
    struct ssh_dh_s *dh=&keyx->method.dh;
    unsigned int error=0;

    set_msg_buffer(&mb, buffer, len);

    /* create hash of K || H || "X" || session_id */

    (* keyx->msg_write_shared_K)(&mb, keyx);
    msg_write_bytes(&mb, (unsigned char *) H->ptr, H->len);
    msg_write_byte(&mb, singlechar);
    msg_write_bytes(&mb, (unsigned char *) sessionId->ptr, sessionId->len);

    if (hashlen >= key->size) {
	struct ssh_string_s out;

	/* enough data for the key */

	out.ptr=key->ptr;
	out.len=key->size;

	if (create_hash(keyx->digestname, mb.data, mb.pos, &out, &error)==0) goto error;
	key->len=key->size;

    } else {
	struct ssh_string_s out;

	out.ptr=key->ptr;
	out.len=hashlen;

	if (create_hash(keyx->digestname, mb.data, mb.pos, &out, &error)==0) goto error;

	/*
	    not enough data for key: create new hashes according to
	    RFC4253 7.2
	    and append to the key
	*/

	key->len=out.len;

	/* create new hash K||H||K1 */

	mb.pos=0;
	(* keyx->msg_write_shared_K)(&mb, keyx);
	msg_write_bytes(&mb, (unsigned char *) H->ptr, H->len);

	append:

	/* append previous hash K1, K2, .... 
	    to create a new hash K2, K3, .... */

	msg_write_bytes(&mb, (unsigned char *) out.ptr, out.len);

	out.ptr=(char *)(key->ptr + key->len);

	if (key->len + hashlen >= key->size) {

	    out.len=(key->size - key->len);
	    if (create_hash(keyx->digestname, mb.data, mb.pos, &out, &error)==0) goto error;

	    /* enough */

	    key->len=key->size;

	} else {

	    out.len=hashlen;
	    if (create_hash(keyx->digestname, mb.data, mb.pos, &out, &error)==0) goto error;
	    key->len+=hashlen;
	    goto append;

	}

    }

    return;

    error:

    logoutput_warning("create_keyx_hashes: error (%i:%s) creating hash", error, strerror(error));

}

int create_keyx_hashes(struct ssh_session_s *session, struct ssh_keyx_s *keyx, struct ssh_string_s *H, unsigned int *error)
{
    struct keyexchange_s *keyexchange=session->keyexchange;
    struct algo_list_s *algos=keyexchange->data.algos;
    unsigned int keylen=0;
    int index=0;

    if (keyexchange==NULL) {

	*error=EINVAL;
	return -1;

    }

    /* iv cipher client to server: c2s
	get the length of the iv from the encrypt ops belonging to the algo chosen */

    keylen=0;
    index=keyexchange->data.chosen[SSH_ALGO_TYPE_CIPHER_C2S];
    if (index>=0) {
	struct encrypt_ops_s *ops=(struct encrypt_ops_s *) algos[index].ptr;

	keylen=(* ops->get_cipher_ivsize)(algos[index].sshname);

    }

    if (keylen>0) {
	char data[keylen];
	struct common_buffer_s buffer;
	struct ssh_string_s *iv=&keyexchange->data.cipher_iv_c2s;

	logoutput("create_keyx_hashes: iv size %i for cipher c2s %s", keylen, algos[index].sshname);

	memset(data, '\0', keylen);
	buffer.ptr=data;
	buffer.size=keylen;
	buffer.len=0;

	_create_keyx_hash(session, keyx, 'A', H, &buffer);

	if (create_ssh_string(iv, keylen)==keylen) {

	    memcpy(iv->ptr, data, keylen);
	    iv->len=keylen;

	} else {

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
    index=keyexchange->data.chosen[SSH_ALGO_TYPE_CIPHER_S2C];
    if (index>=0) {
	struct decrypt_ops_s *ops=(struct decrypt_ops_s *) algos[index].ptr;

	keylen=(* ops->get_cipher_ivsize)(algos[index].sshname);

    }

    if (keylen>0) {
	char data[keylen];
	struct common_buffer_s buffer;
	struct ssh_string_s *iv=&keyexchange->data.cipher_iv_s2c;

	logoutput("create_keyx_hashes: iv size %i for cipher s2c %s", keylen, algos[index].sshname);

	memset(data, '\0', keylen);
	buffer.ptr=data;
	buffer.size=keylen;
	buffer.len=0;

	_create_keyx_hash(session, keyx, 'B', H, &buffer);

	if (create_ssh_string(iv, keylen)==keylen) {

	    memcpy(iv->ptr, data, keylen);
	    iv->len=keylen;

	} else {

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
    index=keyexchange->data.chosen[SSH_ALGO_TYPE_CIPHER_C2S];
    if (index>=0) {
	struct encrypt_ops_s *ops=(struct encrypt_ops_s *) algos[index].ptr;

	keylen=(* ops->get_cipher_keysize)(algos[index].sshname);

    }

    if (keylen>0) {
	char data[keylen];
	struct common_buffer_s buffer;
	struct ssh_string_s *key=&keyexchange->data.cipher_key_c2s;

	logoutput("create_keyx_hashes: keysize %i for cipher c2s %s", keylen, algos[index].sshname);

	memset(data, '\0', keylen);
	buffer.ptr=data;
	buffer.size=keylen;
	buffer.len=0;

	_create_keyx_hash(session, keyx, 'C', H, &buffer);

	if (create_ssh_string(key, keylen)==keylen) {

	    memcpy(key->ptr, data, keylen);
	    key->len=keylen;

	} else {

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
    index=keyexchange->data.chosen[SSH_ALGO_TYPE_CIPHER_S2C];
    if (index>=0) {
	struct decrypt_ops_s *ops=(struct decrypt_ops_s *) algos[index].ptr;

	keylen=(* ops->get_cipher_keysize)(algos[index].sshname);

    }

    if (keylen>0) {
	char data[keylen];
	struct common_buffer_s buffer;
	struct ssh_string_s *key=&keyexchange->data.cipher_key_s2c;

	logoutput("create_keyx_hashes: keysize %i for cipher s2c %s", keylen, algos[index].sshname);

	memset(data, '\0', keylen);
	buffer.ptr=data;
	buffer.size=keylen;
	buffer.len=0;

	_create_keyx_hash(session, keyx, 'D', H, &buffer);

	if (create_ssh_string(key, keylen)==keylen) {

	    memcpy(key->ptr, data, keylen);
	    key->len=keylen;

	} else {

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
    index=keyexchange->data.chosen[SSH_ALGO_TYPE_HMAC_C2S];
    if (index>=0) {
	struct encrypt_ops_s *ops=(struct encrypt_ops_s *) algos[index].ptr;

	keylen=(* ops->get_hmac_keysize)(algos[index].sshname);

    }

    if (keylen>0) {
	char data[keylen];
	struct common_buffer_s buffer;
	struct ssh_string_s *key=&keyexchange->data.hmac_key_c2s;

	logoutput("create_keyx_hashes: keysize %i for hmac c2s %s", keylen, algos[index].sshname);

	memset(data, '\0', keylen);
	buffer.ptr=data;
	buffer.size=keylen;
	buffer.len=0;

	_create_keyx_hash(session, keyx, 'E', H, &buffer);

	if (create_ssh_string(key, keylen)==keylen) {

	    memcpy(key->ptr, data, keylen);
	    key->len=keylen;

	} else {

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
    index=keyexchange->data.chosen[SSH_ALGO_TYPE_HMAC_S2C];
    if (index>=0) {
	struct decrypt_ops_s *ops=(struct decrypt_ops_s *) algos[index].ptr;

	keylen=(* ops->get_hmac_keysize)(algos[index].sshname);

    }

    if (keylen>0) {
	char data[keylen];
	struct common_buffer_s buffer;
	struct ssh_string_s *key=&keyexchange->data.hmac_key_s2c;

	logoutput("create_keyx_hashes: keysize %i for hmac s2c %s", keylen, algos[index].sshname);

	memset(data, '\0', keylen);
	buffer.ptr=data;
	buffer.size=keylen;
	buffer.len=0;

	_create_keyx_hash(session, keyx, 'F', H, &buffer);

	if (create_ssh_string(key, keylen)==keylen) {

	    memcpy(key->ptr, data, keylen);
	    key->len=keylen;

	} else {

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
