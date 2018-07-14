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

#include "main.h"
#include "logging.h"

#include "common-utils/utils.h"

#include "ssh-common.h"
#include "ssh-common-protocol.h"

#include "ssh-receive.h"
#include "ssh-send.h"
#include "ssh-hostinfo.h"
#include "ssh-utils.h"
#include "userauth/utils.h"

/*
    functions to handle authentication based on public key
    see:
    https://tools.ietf.org/html/rfc4252#section-7
*/

/* create a signature to do public key authentication

    create a signature of

    - string			session identifier
    - byte			SSH_MSG_USERAUTH_REQUEST
    - string			username
    - string			service
    - string			"publickey"
    - boolean			TRUE
    - string 			algo used to sign (defaults to the algo of pubkey)
    - string			pubkey

*/

static unsigned int msg_write_pk_signature(struct msg_buffer_s *mb, struct ssh_session_s *session, char *r_user, const char *service, struct ssh_key_s *pkey, struct ssh_pksign_s *pksign, struct ssh_string_s *signature)
{

    msg_write_ssh_string(mb, 's', (void *) &session->data.sessionid);
    msg_write_userauth_pubkey_request(mb, r_user, service, pkey, pksign, signature);
    return mb->pos;
}

static signed char create_pk_signature(struct ssh_session_s *session, char *r_user, const char *service, struct ssh_key_s *pkey, struct ssh_key_s *skey, struct ssh_pksign_s *pksign, struct ssh_string_s *signature)
{
    struct msg_buffer_s mb=INIT_SSH_MSG_BUFFER;
    unsigned int len = msg_write_pk_signature(&mb, session, r_user, service, pkey, pksign, signature) + 64;
    char buffer[len];
    unsigned int error=0;
    int result=0;
    const char *hashname=get_hashname_sign(pksign);

    logoutput("create_pk_signature: hash %s", hashname);

    set_msg_buffer(&mb, buffer, len);
    len = msg_write_pk_signature(&mb, session, r_user, service, pkey, pksign, signature);

    /* create a signature of this data using the private key belonging to the public key */

    if ((* skey->sign)(skey, buffer, len, signature, hashname, &error)>=0) {

	return 0;

    } else {

	logoutput("create_pk_signature: error %i creating signature (%s)", error, strerror(error));

    }

    return -1;

}

static unsigned int construct_USERAUTH_PK_OK(struct msg_buffer_s *mb, struct ssh_key_s *pkey, struct ssh_pksign_s *pksign)
{
    msg_write_byte(mb, SSH_MSG_USERAUTH_PK_OK);
    msg_write_pksign(mb, pksign);
    msg_write_pkey(mb, pkey, PK_DATA_FORMAT_SSH_STRING);
    return mb->pos;
}

/* check the format of the SSH_MSG_USERAUTH_PK_OK message
    it must look exactly like constructed below
    - byte 			SSH_MSG_USERAUTH_PK_OK
    - string			public key algo name from request
    - string 			public key blob from request
*/

static int check_received_pubkey_pk(struct ssh_payload_s *payload, struct ssh_key_s *pkey, struct ssh_pksign_s *pksign)
{
    struct msg_buffer_s mb = INIT_SSH_MSG_BUFFER;
    unsigned int len = construct_USERAUTH_PK_OK(&mb, pkey, pksign) + 64;
    char buffer[len];

    set_msg_buffer(&mb, buffer, len);
    len=construct_USERAUTH_PK_OK(&mb, pkey, pksign);

    logoutput("check_received_pubkey_pk: len %i payload len %i", len, payload->len);

    if ( len == payload->len && memcmp(buffer, payload->buffer, len) == 0) return 0;

    return -1;

}

static int ssh_send_pk_signature(struct ssh_session_s *session, char *r_user, struct ssh_key_s *pkey, struct ssh_key_s *skey, struct ssh_pksign_s *pksign, struct ssh_userauth_s *userauth)
{
    struct ssh_string_s signature;
    int result=-1;
    unsigned int seq=0;

    init_ssh_string(&signature);

    if (create_pk_signature(session, r_user, "ssh-connection", pkey, skey, pksign, &signature)==-1) {

	logoutput("ssh_send_pk_signature: creating public key signature failed");
	goto out;

    }

    /* send userauth publickey request to server with signature */

    if (send_userauth_pubkey_message(session, r_user, "ssh-connection", pkey, pksign, &signature, &seq)==0) {
	struct timespec expire;
	struct ssh_payload_s *payload=NULL;
	unsigned int error=0;

	get_session_expire_init(session, &expire);

	getresponse:

	payload=get_ssh_payload(session, userauth->queue, &expire, &seq, &error);

	if (! payload) {

	    if (error==0) error=EIO;
	    logoutput("ssh_send_pk_signature: error %i waiting for server SSH_MSG_SERVICE_REQUEST (%s)", error, strerror(error));
	    goto out;

	}

	if (payload->type==SSH_MSG_IGNORE || payload->type==SSH_MSG_DEBUG || payload->type==SSH_MSG_USERAUTH_BANNER) {

	    process_cb_ssh_payload(session, payload);
	    payload=NULL;
	    goto getresponse;

	} else if (payload->type==SSH_MSG_USERAUTH_SUCCESS) {

	    userauth->required_methods=0;
	    result=0;

	} else if (payload->type==SSH_MSG_USERAUTH_FAILURE) {

	    result=handle_userauth_failure(session, payload, userauth);

	}

	if (payload) free_payload(&payload);

    } else {

	logoutput("ssh_send_pk_signature: error sending SSH_MSG_SERVICE_REQUEST");

    }

    out:

    free_ssh_string(&signature);
    return result;

}

/* test pk algo and public key are accepted */

static int send_userauth_pubkey(struct ssh_session_s *session, char *r_user, struct ssh_key_s *pkey, struct ssh_pksign_s *pksign, struct ssh_userauth_s *userauth)
{
    unsigned int seq=0;
    int result=-1;

    logoutput("send_userauth_pubkey");

    if (send_userauth_pubkey_message(session, r_user, "ssh-connection", pkey, pksign, NULL, &seq)==0) {
	struct timespec expire;
	struct ssh_payload_s *payload=NULL;
	unsigned int error=0;

	get_session_expire_init(session, &expire);
	payload=get_ssh_payload(session, userauth->queue, &expire, &seq, &error);

	if (! payload) {

	    /* why not receiving payload ? */

	    if (error == 0) error=EIO;
	    logoutput("send_userauth_pubkey: error %i waiting for server SSH_MSG_USERAUTH_REQUEST (%s)", error, strerror(error));
	    return -1;

	}

	if (payload->type==SSH_MSG_USERAUTH_PK_OK) {

	    logoutput("send_userauth_pubkey: pubkey accepted");

	    /*
		public key is accepted by server

		message has the form:
		- byte				SSH_MSG_USERAUTH_PK_OK
		- string			algo name
		- string			public key
	    */

	    /* check the received key is the same as the one send */

	    result=check_received_pubkey_pk(payload, pkey, pksign);

	} else if (payload->type==SSH_MSG_USERAUTH_FAILURE) {

	    logoutput("send_userauth_pubkey: pubkey rejected");

	} else {

	    logoutput("send_userauth_pubkey: reply %i not reckognized", payload->type);

	}

	free_payload(&payload);

    } else {

	logoutput("send_userauth_pubkey: error %i sending SSH_MSG_SERVICE_REQUEST (%s)", EIO, strerror(EIO));

    }

    return result;

}

/* perform pubkey authentication using identities */

struct pk_identity_s *ssh_auth_pubkey(struct ssh_session_s *session, struct pk_list_s *pkeys, struct ssh_userauth_s *userauth)
{
    struct pk_identity_s *user_identity=NULL;
    char *r_user=NULL;
    unsigned int error=0;

    /* browse the identities */

    user_identity=get_next_pk_identity(pkeys, "user");

    while (user_identity) {
	struct ssh_key_s pkey;
	struct ssh_pksign_s *pksign=NULL;
	int result=-1;

	init_ssh_key(&pkey, SSH_KEY_TYPE_PUBLIC, NULL);

	if (read_key_param(user_identity, &pkey)==-1) {

	    logoutput("ssh_auth_pubkey: error reading public key");
	    goto next;

	}

	/* if there is a remote user with this identity take that one
	    otherwise fall back to the local user */

	r_user=get_pk_identity_user(user_identity);
	if (r_user==NULL) r_user=session->identity.pwd.pw_name;

	/* TODO:
	    try all the available sign algo's for pkey
	    now it uses only the default (which always works by the way)
	    but there might be different available like:
	    - rsa-sha2-256
	    - rsa-sha2-512
	*/

	pksign=get_default_pksign(pkey.algo);

	if (send_userauth_pubkey(session, r_user, &pkey, pksign, userauth)==0) {
	    struct ssh_key_s skey;

	    /* confirm the signature method is accepted by server if not alrady */

	    /* current public key is accepted by server: send signature
		get the private key for this identity */

	    init_ssh_key(&skey, SSH_KEY_TYPE_PRIVATE, pkey.algo);

	    if (read_key_param(user_identity, &skey)==0) {

		result=ssh_send_pk_signature(session, r_user, &pkey, &skey, pksign, userauth);

	    } else {

		/*
		    what to do?
		    if private key is not found try next public key ?
		    or break..
		*/

		logoutput_info("ssh_auth_pubkey: private key not found");

	    }

	    free_ssh_key(&skey);

	}

	next:

	free_ssh_key(&pkey);
	if (result==0) break; /* if success then ready */

	free(user_identity);
	user_identity=get_next_pk_identity(pkeys, "user");

    }

    return user_identity;

}
