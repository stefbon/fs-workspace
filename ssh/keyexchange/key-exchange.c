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

#include "ssh-common-protocol.h"
#include "ssh-common.h"
#include "ssh-utils.h"

#include "ssh-receive.h"
#include "ssh-send.h"
#include "createkeys.h"
#include "dh.h"
#include "ecdh.h"
#include "ssh-data.h"

extern struct fs_options_s fs_options;

static int verify_sigH(struct ssh_key_s *pkey, struct ssh_string_s *H, const char *hashname, struct ssh_string_s *sigH)
{
    unsigned int error=0;
    return (* pkey->verify)(pkey, H->ptr, H->len, sigH, hashname, &error);
}

static void msg_read_keyx_server_key(struct msg_buffer_s *mb, struct ssh_keyx_s *keyx)
{
    (* keyx->msg_read_server_key)(mb, keyx);
}

static int keyx_calc_shared_K(struct ssh_keyx_s *keyx)
{
    return (* keyx->calc_shared_K)(keyx);
}

static unsigned int write_kexdh_init_message(struct msg_buffer_s *mb, struct ssh_keyx_s *keyx)
{

    msg_write_byte(mb, SSH_MSG_KEXDH_INIT);
    (* keyx->msg_write_client_key)(mb, keyx);

    logoutput("write_kexdh_init_message: len %i", mb->pos);

    return mb->pos;

}

static int send_kexdh_init_message(struct ssh_session_s *session, struct ssh_keyx_s *keyx)
{
    struct msg_buffer_s mb=INIT_SSH_MSG_BUFFER;
    unsigned int len=write_kexdh_init_message(&mb, keyx) + 64;
    char buffer[sizeof(struct ssh_payload_s) + len];
    struct ssh_payload_s *payload=(struct ssh_payload_s *) buffer;
    unsigned int seq=0;

    init_ssh_payload(payload, len);
    set_msg_buffer_payload(&mb, payload);
    payload->len=write_kexdh_init_message(&mb, keyx);

    return write_ssh_packet(session, payload, &seq);

}

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

static int read_keyx_dh_reply(struct ssh_session_s *session, struct ssh_keyx_s *keyx, struct ssh_payload_s *payload,
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

    msg_read_keyx_server_key(&mb, keyx); /* f or Q_S or .. store value in keyx.method.dh or .. */

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

int start_key_exchange(struct ssh_session_s *session, struct ssh_keyx_s *keyx, struct sessionphase_s *sessionphase)
{
    struct keyexchange_s *keyexchange=session->keyexchange;
    struct timespec expire;
    unsigned int error=0;
    unsigned int sequence=0;
    struct ssh_payload_s *payload=NULL;
    unsigned int hashlen=create_hash(keyx->digestname, NULL, 0, NULL, NULL);
    char hashdata[hashlen];
    struct ssh_string_s H;
    struct ssh_string_s sigH;
    struct ssh_string_s signalgo;
    struct ssh_pksign_s *pksign=NULL;
    struct ssh_hostkey_s hostkey;
    struct ssh_key_s *pkey=NULL;
    struct ssh_string_s keydata;
    int change=0;

    /* hostkey type defined in kexinit */
    /* is algo a certificate ? */

    if (keyx->pkauth.type == SSH_PKAUTH_TYPE_PKCERT) {
	struct ssh_pkcert_s *pkcert=keyx->pkauth.method.pkcert;
	struct ssh_pkalgo_s *pkalgo=get_pkalgo_byid(pkcert->pkalgo_id, NULL);

	if (pkcert->flags & SSH_PKCERT_FLAG_OPENSSH_COM_CERTIFICATE) {

	    pkey=&hostkey.data.openssh_cert.key;
	    hostkey.type=SSH_HOSTKEY_TYPE_OPENSSH_COM_CERT;
	    init_ssh_cert_openssh_com(&hostkey.data.openssh_cert, pkcert, pkalgo);

	}

	/* else ?? */

    } else if (keyx->pkauth.type == SSH_PKAUTH_TYPE_PKALGO) {

	pkey=&hostkey.data.key;
	init_ssh_key(pkey, SSH_KEY_TYPE_PUBLIC, keyx->pkauth.method.pkalgo);

    }

    /* else ?? */

    init_ssh_string(&H);						/* exchange hash */
    init_ssh_string(&sigH); 						/* signature */
    init_ssh_string(&signalgo);						/* name of signalgo used to create signature */
    init_ssh_string(&keydata);						/* keydata, pk key or certificate  */

    logoutput("start_keyexchange");

    /* client: calculate e/Q_C */

    if ((* keyx->create_client_key)(keyx)==-1) {

	logoutput("start_keyexchange: creating keyx client key failed");
	set_sessionphase_failed(sessionphase);
	goto error;

    }

    /* send SSH_MSG_KEXDH_INIT message */

    if (send_kexdh_init_message(session, keyx)==-1) {

	set_sessionphase_failed(sessionphase);
	logoutput("start_keyexchange: error %i:%s sending kexdh_init", error, strerror(error));
	goto error;

    }

    sessionphase->status|=SESSION_STATUS_KEYEXCHANGE_KEYX_C2S;
    change=change_status_sessionphase(session, sessionphase);
    if (change<0) goto error;

    /* wait for SSH_MSG_KEXDH_REPLY */

    get_session_expire_init(session, &expire);
    payload=get_ssh_payload(session, keyexchange->queue, &expire, &sequence, &error);

    if (! payload) {

	logoutput("start_keyexchange: error waiting for kexdh_reply");
	set_sessionphase_failed(sessionphase);
	goto error;

    } else if (payload->type != SSH_MSG_KEXDH_REPLY) {

	logoutput("start_keyexchange: error: received a %i message, expecting %i", payload->type, SSH_MSG_KEXDH_REPLY);
	set_sessionphase_failed(sessionphase);
	goto error;

    }

    if (read_keyx_dh_reply(session, keyx, payload, &keydata, &signalgo, &sigH, &error)==-1) {

	logoutput("start_keyexchange: error reading dh reply");
	set_sessionphase_failed(sessionphase);
	goto error;

    }

    logoutput("start_keyexchange: read hostkey (len %i), signalgo (len %i) and sigH (len %i)", keydata.len, signalgo.len, sigH.len);

    sessionphase->status|=SESSION_STATUS_KEYEXCHANGE_KEYX_S2C;
    change=change_status_sessionphase(session, sessionphase);
    if (change<0) goto error;

    if (keyx->pkauth.type == SSH_PKAUTH_TYPE_PKCERT) {

	if (read_cert_openssh_com(&hostkey.data.openssh_cert, &keydata)==-1) {

	    logoutput("start_keyexchange: failed to read openssh.com certificate");
	    set_sessionphase_failed(sessionphase);
	    goto error;

	}

	if (check_cert_openssh_com(&hostkey.data.openssh_cert, SSH_PKCERT_FLAG_HOST, select_pksign_session, (void *) session)==-1) {

	    logoutput("start_keyexchange: certificate not valid");
	    set_sessionphase_failed(sessionphase);
	    goto error;

	}

    } else if (keyx->pkauth.type == SSH_PKAUTH_TYPE_PKALGO) {

	if ((* pkey->read_key)(pkey, keydata.ptr, keydata.len, PK_DATA_FORMAT_SSH, &error)==-1) {

	    logoutput("start_keyexchange: error %i reading public key from host (%s)", error, strerror(error));
	}

    }

    /* check the received public hostkey (against a "known hosts file" etcetera)
	TODO: make a check using another local db/agent possible 
	TODO: make a check of certificates possible (look for a CA) */

    if (fs_options.ssh.trustdb == _OPTIONS_SSH_TRUSTDB_NONE) {

	logoutput_info("start_keyexchange: no trustdb used, hostkey is not checked to local db of trusted keys");

    } else {
	unsigned int done = fs_options.ssh.trustdb;

	if (fs_options.ssh.trustdb & _OPTIONS_SSH_TRUSTDB_OPENSSH) {

	    done-=_OPTIONS_SSH_TRUSTDB_OPENSSH;

	    if (check_serverkey_openssh(session->connection.fd, &session->identity.pwd, pkey, (keyx->pkauth.type == SSH_PKAUTH_TYPE_PKCERT) ? "ca" : "pk")==0) {

		logoutput_info("start_keyexchange: check public key server success");

	    } else {

		logoutput_info("start_keyexchange: check public key server failed");
		set_sessionphase_failed(sessionphase);
		goto error;

	    }

	}

	if (done>0) {

	    logoutput_warning("start_keyexchange: not all trustdbs %i supported", done);

	}

    }

    /* check the signalgo used to sign is supported in this session */

    pksign=check_signature_algo(pkey->algo, &signalgo, select_pksign_session, (void *) session);

    if (pksign==NULL) {

	logoutput_info("start_keyexchange: signalgo %.*s not supported", signalgo.len, signalgo.ptr);
	set_sessionphase_failed(sessionphase);
	goto error;

    }

    /* calculate the shared K from the client keyx key (e/Q_C/..) and the server keyx key (f/Q_S/..)*/

    if (keyx_calc_shared_K(keyx)==-1) {

	logoutput_info("start_keyexchange: calculation shared key K failed");
	set_sessionphase_failed(sessionphase);
	goto error;

    }

    /* check the signature is correct by creating the H self
	and verify using the public key of the server */

    H.len=hashlen;
    H.ptr=hashdata;

    if (create_H(session, keyx, pkey, &H)==-1) {

	set_sessionphase_failed(sessionphase);
	logoutput_info("start_keyexchange: error creating H (%i bytes)", hashlen);
	goto error;

    } else {

	logoutput_info("start_keyexchange: created H (%i bytes)", hashlen);

    }

    if (verify_sigH(pkey, &H, get_hashname_sign(pksign), &sigH)==-1) {

	set_sessionphase_failed(sessionphase);
	logoutput_info("start_keyexchange: verify sig H failed");
	goto error;

    } else {

	logoutput_info("start_keyexchange: sig H verified");

    }

    if (sessionphase->phase==SESSION_PHASE_SETUP) {

	/* store H as session identifier (only in setup) */

	if (store_ssh_session_id(session, H.ptr, H.len)==-1) {

	    set_sessionphase_failed(sessionphase);
	    logoutput_info("start_keyexchange: failed to store session id");
	    goto error;

	}

    }

    /* create the different hashes */

    if (create_keyx_hashes(session, keyx, &H, &error)==0) {

	logoutput_info("start_keyexchange: key hashes created");

    } else {

	logoutput_info("start_keyexchange: failed to create key hashes");
	goto error;

    }

    if (payload) free_payload(&payload);
    free_ssh_key(pkey);
    return 0;

    error:

    if (payload) free_payload(&payload);
    free_ssh_key(pkey);
    logoutput("start_keyexchange: error");
    return -1;

}
