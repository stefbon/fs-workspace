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
#include "options.h"

#include "ssh-utils.h"
#include "ssh-common-protocol.h"
#include "ssh-common.h"
#include "ssh-connections.h"
#include "ssh-receive.h"
#include "ssh-send.h"
#include "ssh-keyexchange.h"
#include "ssh-data.h"

extern struct fs_options_s fs_options;

static int verify_signature_H(struct ssh_key_s *pkey, struct ssh_hash_s *H, const char *hashname, struct ssh_string_s *sigH)
{
    unsigned int error=0;
    return (* pkey->verify)(pkey,(char *)H->digest, H->len, sigH, hashname, &error);
}

static void msg_read_keyx_server_key(struct msg_buffer_s *mb, struct ssh_keyex_s *k)
{
    (* k->ops->msg_read_server_key)(mb, k);
}

static int keyx_calc_shared_key(struct ssh_keyex_s *k)
{
    return (* k->ops->calc_sharedkey)(k);
}

static unsigned int write_kexdh_init_message(struct msg_buffer_s *mb, struct ssh_keyex_s *k)
{
    msg_write_byte(mb, SSH_MSG_KEXDH_INIT);
    (* k->ops->msg_write_client_key)(mb, k);
    return mb->pos;
}

static int send_kexdh_init_message(struct ssh_connection_s *connection, struct ssh_keyex_s *k)
{
    struct msg_buffer_s mb=INIT_SSH_MSG_BUFFER;
    unsigned int len=write_kexdh_init_message(&mb, k) + 64;
    char buffer[sizeof(struct ssh_payload_s) + len];
    struct ssh_payload_s *payload=(struct ssh_payload_s *) buffer;
    unsigned int seq=0;

    init_ssh_payload(payload, len);
    set_msg_buffer_payload(&mb, payload);
    payload->len=write_kexdh_init_message(&mb, k);

    return write_ssh_packet(connection, payload, &seq);
}

/* look for the right pk alogorithm give the signname and the name for the publickey algorithm */

static int select_pksign_session(void *ptr, char *pkname, char *signname)
{
    struct ssh_session_s *session=(struct ssh_session_s *) ptr;
    struct ssh_pkalgo_s *pkalgo=NULL;

    /* TODO :
	- return 0 for signalgo with name signname is supported for session
	(look in the extensions for the session)
	*/

    pkalgo=get_pkalgo(pkname, strlen(pkname), NULL);

    if (pkalgo) {
	struct ssh_pksign_s *pksign=NULL;

	pksign=get_next_pksign(pkalgo, pksign, NULL);

	while (pksign) {

	    if (pksign->name) {

		if (strcmp(pksign->name, signname)==0) break;

	    } else {

		if (strcmp(pkalgo->name, signname)==0) break;

	    }

	    pksign=get_next_pksign(pkalgo, pksign, NULL);

	}

	if (pksign) {

	    /* simply assume that if ids for signalgo's is zero every signalgo is supported, too simple?? */

	    if (session->pubkey.ids_pksign>0) {
		int index=get_index_pksign(pksign);

		if (session->pubkey.ids_pksign & (1 << (index - 1))) return 0;

	    } else {

		return 0;

	    }

	}

    }

    return -1;

}

static int read_kex_dh_reply(struct ssh_connection_s *connection, struct ssh_keyex_s *k, struct ssh_payload_s *payload,
				struct ssh_string_s *keydata, struct ssh_string_s *signalgo, struct ssh_string_s *sigH, unsigned int *error)
{
    struct msg_buffer_s mb=INIT_SSH_MSG_BUFFER;

    set_msg_buffer_payload(&mb, payload);

    /*
	message has following form:
	byte 	SSH_MSG_KEXDH_REPLY
	string	server public host key
	mpint	f
	string	signature of H

	rules:
	- algo of server public hostkey and the signature are the same as negotiated during keyinit
    */

    msg_read_byte(&mb, NULL);

    /* read public key or certificate */

    msg_read_ssh_string(&mb, keydata);

    /* read f */

    msg_read_keyx_server_key(&mb, k); /* f or Q_S or .. store value in keyx.method.dh or .. */

    /*

    check the received data containing the signature has the right format
    it has the following format (as used by ssh):

    - string			data containing signature of H

    this string is:

    - uint32			len of rest (n)
    - byte[n]			which is a combination of two strings:
	- string 		name of pk algo used to sign like "ssh-rsa" and "ssh-dss" and "rsa-sha2-256" and "rsa-sha2-512"
	- string		signature blob

    see:

    RFC4253

	6.6.  Public Key Algorithms
	and
	8.  Diffie-Hellman Key Exchange

    and

    draft-rsa-dsa-sha2-256

    */

    msg_read_pksignature(&mb, signalgo, sigH);

    if (mb.error>0) {

	*error=mb.error;
	logoutput("read_keyx_dh_reply: reading MSG_KEXDH_REPLY failed: error %i:%s", mb.error, strerror(mb.error));
	return -1;

    }

    return 0;

}

static struct ssh_payload_s *receive_keyx_dh_reply(struct ssh_connection_s *connection, unsigned int *error)
{
    struct payload_queue_s *queue=&connection->setup.queue;
    struct ssh_payload_s *payload=NULL;
    struct timespec expire;
    unsigned int sequence=0;

    /* wait for SSH_MSG_KEXDH_REPLY */

    get_ssh_connection_expire_init(connection, &expire);
    *error=EPROTO;

    getkexdhreply:

    payload=get_ssh_payload(connection, queue, &expire, &sequence, error);

    if (payload==NULL) {

	logoutput("start_keyexchange: error %i waiting for KEXDH REPLY (%s)", *error, strerror(*error));

    } else if (payload->type == SSH_MSG_KEXDH_REPLY) {

	goto out;

    } else {

	logoutput("start_keyexchange: error: received a %i message, expecting %i", payload->type, SSH_MSG_KEXDH_REPLY);
	free_payload(&payload);
	payload=NULL;

    }

    out:

    return payload;

}

int start_kex_dh(struct ssh_connection_s *connection, struct ssh_keyex_s *k)
{
    struct ssh_session_s *session=get_ssh_connection_session(connection);
    struct ssh_setup_s *setup=&connection->setup;
    struct ssh_keyexchange_s *kex=&setup->phase.transport.type.kex;
    unsigned int error=EIO;
    struct ssh_payload_s *payload=NULL;
    unsigned int hashlen=get_hash_size(k->digestname); /* get length of required buffer to store hash */
    char hashdata[sizeof(struct ssh_hash_s) + hashlen];
    struct ssh_hash_s *H=(struct ssh_hash_s *) hashdata;
    struct ssh_string_s sign_H;
    struct ssh_string_s sign_algo_name;
    struct ssh_pksign_s *pksign=NULL;
    struct ssh_hostkey_s hostkey;
    struct ssh_key_s *pkey=NULL;
    struct ssh_string_s keydata;
    int result=-1;

    init_ssh_hash(H, k->digestname, hashlen);

    /* hostkey type defined in kexinit */
    /* is algo a certificate ? */

    if (k->pkauth.type == SSH_PKAUTH_TYPE_PKCERT) {
	struct ssh_pkcert_s *pkcert=k->pkauth.method.pkcert;
	struct ssh_pkalgo_s *pkalgo=get_pkalgo_byid(pkcert->pkalgo_id, NULL);

	/* hostkey is a certificate */

	if (pkcert->flags & SSH_PKCERT_FLAG_OPENSSH_COM_CERTIFICATE) {

	    pkey=&hostkey.data.openssh_cert.key;
	    hostkey.type=SSH_HOSTKEY_TYPE_OPENSSH_COM_CERT;
	    init_ssh_cert_openssh_com(&hostkey.data.openssh_cert, pkcert, pkalgo);

	}

	/* TODO: else ?? */

    } else if (k->pkauth.type == SSH_PKAUTH_TYPE_PKALGO) {

	/* hostkey is a public key */

	pkey=&hostkey.data.key;
	init_ssh_key(pkey, SSH_KEY_TYPE_PUBLIC, k->pkauth.method.pkalgo);

    }

    /* else ?? */

    init_ssh_string(&sign_H); 						/* signature */
    init_ssh_string(&sign_algo_name);					/* name of signalgo used to create signature */
    init_ssh_string(&keydata);						/* keydata, pk key or certificate  */

    logoutput("start_kex_dh");

    /* client: calculate the client key e/Q_C */

    if ((* k->ops->create_client_key)(k)==-1) {

	logoutput("start_kex_dh: creating kex dh client key failed");
	goto out;

    }

    /* send SSH_MSG_KEXDH_INIT message */

    if (send_kexdh_init_message(connection, k)==-1) {

	logoutput("start_kex_dh: error %i:%s sending kex dh init", error, strerror(error));
	goto out;

    }

    change_ssh_connection_setup(connection, "transport", SSH_TRANSPORT_TYPE_KEX, SSH_KEX_FLAG_KEXDH_C2S, 0, NULL, NULL);

    /* wait for SSH_MSG_KEXDH_REPLY */

    payload=receive_keyx_dh_reply(connection, &error);

    if (payload==NULL) {

	logoutput("start_kex_dh: error %i receiving KEXDH REPLY (%s)", error, strerror(error));
	goto out;

    }

    change_ssh_connection_setup(connection, "transport", SSH_TRANSPORT_TYPE_KEX, SSH_KEX_FLAG_KEXDH_S2C, 0, NULL, NULL);

    /* read server hostkey (keydata), the server public keyexchange value f/Q_S, the name of the pk algo used to sign and the signature */

    if (read_kex_dh_reply(connection, k, payload, &keydata, &sign_algo_name, &sign_H, &error)==-1) {

	logoutput("start_kex_dh: error %i reading dh reply (%s)", error, strerror(error));
	goto out;

    }

    logoutput("start_kex_dh: read hostkey (len %i), sign algo name %.*s (len %i) and sigH (len %i)", keydata.len, sign_algo_name.len, sign_algo_name.ptr, sign_algo_name.len, sign_H.len);

    if (k->pkauth.type == SSH_PKAUTH_TYPE_PKCERT) {

	/* read certificate from key data */

	if (read_cert_openssh_com(&hostkey.data.openssh_cert, &keydata)==-1) {

	    logoutput("start_kex_dh: failed to read openssh.com certificate");
	    goto out;

	}

	/* check certificate is complete */

	if (check_cert_openssh_com(&hostkey.data.openssh_cert, SSH_PKCERT_FLAG_HOST, select_pksign_session, (void *) session)==-1) {

	    logoutput("start_kex_dh: certificate not valid");
	    goto out;

	}

    } else if (k->pkauth.type == SSH_PKAUTH_TYPE_PKALGO) {

	/* read the server host keydata using SSH format */

	if ((* pkey->read_key)(pkey, keydata.ptr, keydata.len, PK_DATA_FORMAT_SSH, &error)==-1) {

	    logoutput("start_kex_dh: error %i reading public key from host (%s)", error, strerror(error));
	    goto out;

	}

    }

    /* check the received public hostkey (against a "known hosts file" etcetera)
	TODO: make a check using another local db/agent possible 
	TODO: make a check of certificates possible (look for a CA) */

    if (fs_options.ssh.trustdb == _OPTIONS_SSH_TRUSTDB_NONE) {

	logoutput_info("start_kex_dh: no trustdb used, hostkey is not checked to local db of trusted keys");

    } else {
	unsigned int done = fs_options.ssh.trustdb;

	if (fs_options.ssh.trustdb & _OPTIONS_SSH_TRUSTDB_OPENSSH) {

	    done-=_OPTIONS_SSH_TRUSTDB_OPENSSH;

	    if (check_serverkey_openssh(&connection->connection, &session->identity.pwd, pkey, (k->pkauth.type == SSH_PKAUTH_TYPE_PKCERT) ? "ca" : "pk")==0) {

		logoutput("start_kex_dh: check public key server success");

	    } else {

		logoutput("start_kex_dh: check public key server failed");
		goto out;

	    }

	    /* store fp of servers hostkey */

	    /* encode/decode first ?? */

	    // logoutput("start_kex_dh: creating fp server public hostkey");

	    // if (create_ssh_string(&hostinfo->fp, create_hash("sha1", NULL, 0, NULL, &error))>0) {

		// if (create_hash("sha1", keydata.ptr, keydata.len, &hostinfo->fp, &error)>0) {

		    // logoutput("start_kex_dh: servers fp %.*s (len=%i)", hostinfo->fp.len, hostinfo->fp.ptr, hostinfo->fp.len);

		// }

	    //}

	}

	if (done>0) {

	    logoutput_warning("start_kex_dh: not all trustdbs %i supported", done);

	}

    }

    /* check the signalgo used to sign is supported in this session */

    pksign=check_signature_algo(pkey->algo, &sign_algo_name, select_pksign_session, (void *) session);

    if (pksign==NULL) {

	logoutput("start_kex_dh: signalgo %.*s not supported", sign_algo_name.len, sign_algo_name.ptr);
	goto out;

    }

    /* calculate the shared K from the client keyx key (e/Q_C/..) and the server keyx key (f/Q_S/..)*/

    if (keyx_calc_shared_key(k)==-1) {

	logoutput("start_kex_dh: calculation shared key K failed");
	goto out;

    }

    /* check the signature is correct by creating the H self
	and verify using the public key of the server */

    if (create_H(connection, k, pkey, H)==-1) {

	logoutput("start_kex_dh: error creating H (len %i size %i)", H->len, H->size);
	goto out;

    } else {

	logoutput("start_kex_dh: created H (%i size %i)", H->len, H->size);

    }

    if (verify_signature_H(pkey, H, get_hashname_sign(pksign), &sign_H)==-1) {

	logoutput("start_kex_dh: verify signature H failed");
	goto out;

    } else {

	logoutput("start_kex_dh: signature H verified");

    }

    /* store H as session identifier (only when transport phase is NOT completed) */

    if ((connection->flags & SSH_CONNECTION_FLAG_MAIN) && (setup->flags & SSH_SETUP_FLAG_TRANSPORT)==0) {
	struct ssh_string_s tmp={H->len, (char *) H->digest};
	struct ssh_session_s *session=get_ssh_connection_session(connection);

	if (store_ssh_session_id(session, &tmp)==-1) {

	    logoutput("start_kex_dh: failed to store session identifier");
	    goto out;

	}

    }

    /* now the hostkey is found in some db, the signature is checked and the shared key K is computed,
	create the different hashes with it */

    if (create_keyx_hashes(connection, k, H, &error)==0) {

	logoutput("start_kex_dh: key hashes created");
	result=0;

    } else {

	logoutput("start_kex_dh: failed to create key hashes");

    }

    out:

    (* k->ops->free)(k);
    if (payload) free_payload(&payload);
    free_ssh_key(pkey);
    return result;

}
