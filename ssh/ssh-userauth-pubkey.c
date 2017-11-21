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

#include "main.h"
#include "logging.h"

#include "utils.h"

#include "ssh-common.h"
#include "ssh-common-protocol.h"

#include "ssh-pubkey.h"
#include "ssh-pubkey-utils.h"
#include "ssh-pubkey-layout.h"

#include "ssh-receive.h"
#include "ssh-queue-payload.h"

#include "ssh-send.h"
#include "ssh-send-userauth.h"
#include "ssh-hostinfo.h"

#include "ssh-utils.h"
#include "ssh-userauth-utils.h"
#include "ctx-keystore.h"

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
    - string 			algo
    - string			pubkey

*/

static signed char create_pk_signature(struct ssh_session_s *session, struct ssh_string_s *remote_user, const char *service, struct ssh_key_s *public_key, struct ssh_key_s *private_key, struct ssh_string_s *signature)
{
    unsigned int len=write_userauth_pubkey_request(NULL, 0, remote_user, service, public_key) + 4 + session->data.sessionid.len;
    char buffer[len];
    unsigned int pos=0;
    struct common_buffer_s data;
    unsigned int error=0;

    logoutput("create_pk_signature");

    /* session id */

    store_uint32(&buffer[pos], session->data.sessionid.len);
    pos+=4;
    memcpy(&buffer[pos], (char *) session->data.sessionid.ptr, session->data.sessionid.len);
    pos+=session->data.sessionid.len;

    pos+=write_userauth_pubkey_request(&buffer[pos], (len - pos), remote_user, service, public_key);

    /* create a signature of this data using the private key belonging to the public key */

    init_common_buffer(&data);
    data.ptr=&buffer[0];
    data.size=pos;

    if (create_signature(session, private_key, &data, signature, &error)>=0) {

	return 0;

    } else {

	logoutput("create_pk_signature: error %i creating signature (%s)", error, strerror(error));

    }

    return -1;

}

/* check the format of the SSH_MSG_USERAUTH_PK_OK message
    it must look exactly like constructed below */

static int check_received_pubkey_pk(unsigned char *payload, unsigned int len, struct ssh_key_s *public_key)
{
    const unsigned char *algo_name=get_pubkey_name(public_key->type);
    unsigned int algo_len=strlen((char *) algo_name);

    if (9 + algo_len + public_key->data.size==len) {
	unsigned char data[len];
	unsigned int pos=0;

	data[pos]=SSH_MSG_USERAUTH_PK_OK;
	pos++;

	store_uint32(&data[pos], algo_len);
	pos+=4;
	memcpy(&data[pos], algo_name, algo_len);
	pos+=algo_len;

	store_uint32(&data[pos], public_key->data.size);
	pos+=4;
	memcpy(&data[pos], public_key->data.ptr, public_key->data.size);
	pos+=public_key->data.size;

	if (memcmp(payload, data, len)==0) {

	    return 0;

	}

    }

    return -1;

}

static int ssh_send_pk_signature(struct ssh_session_s *session, struct ssh_string_s *remote_user, struct ssh_key_s *public_key, struct ssh_key_s *private_key, unsigned int *methods)
{
    struct ssh_string_s signature;
    int result=-1;
    unsigned int seq=0;

    logoutput("ssh_send_pk_signature");

    signature.len=0;
    signature.ptr=NULL;

    if (create_pk_signature(session, remote_user, "ssh-connection", public_key, private_key, &signature)==-1) {

	logoutput("ssh_send_pk_signature: creating public key signature failed");
	goto out;

    }

    /* send userauth publickey request to server with signature */

    if (send_userauth_pubkey_message(session, remote_user, "ssh-connection", public_key, &signature, &seq)==0) {
	struct timespec expire;
	struct ssh_payload_s *payload=NULL;
	unsigned int error=0;

	session->status.substatus|=SUBSTATUS_USERAUTH_SEND;
	get_session_expire_init(session, &expire);

	getresponse:

	payload=get_ssh_payload(session, &expire, &seq, &error);

	if (! payload) {

	    session->status.substatus|=SUBSTATUS_USERAUTH_ERROR;
	    if (session->status.error==0) session->status.error=EIO;
	    logoutput("ssh_send_pk_signature: error %i waiting for server SSH_MSG_SERVICE_REQUEST (%s)", session->status.error, strerror(session->status.error));
	    goto out;

	}

	session->status.substatus|=SUBSTATUS_USERAUTH_RECEIVED;

	if (payload->type==SSH_MSG_IGNORE || payload->type==SSH_MSG_DEBUG || payload->type==SSH_MSG_USERAUTH_BANNER) {

	    if (payload->type==SSH_MSG_USERAUTH_BANNER) log_userauth_banner(payload);
	    free(payload);
	    payload=NULL;
	    goto getresponse;

	} else if (payload->type==SSH_MSG_USERAUTH_SUCCESS) {

	    session->status.substatus|=SUBSTATUS_USERAUTH_OK;
	    *methods=0;
	    result=0;
	    free(payload);
	    payload=NULL;

	} else if (payload->type == SSH_MSG_USERAUTH_FAILURE) {

	    result=handle_userauth_failure_message(session, payload, methods);
	    free(payload);
	    payload=NULL;

	} else {

	    session->status.substatus|=SUBSTATUS_USERAUTH_ERROR;
	    free(payload);
	    payload=NULL;

	}

    } else {

	session->status.substatus|=SUBSTATUS_USERAUTH_ERROR;

    }

    out:

    if (signature.ptr) {

	free(signature.ptr);
	signature.ptr=NULL;

    }

    return result;

}

static int send_userauth_pubkey_common(struct ssh_session_s *session, struct ssh_string_s *remote_user, struct ssh_key_s *public_key)
{
    unsigned int sequence=0;
    int result=-1;

    if (send_userauth_pubkey_message(session, remote_user, "ssh-connection", public_key, NULL, &sequence)==0) {
	struct timespec expire;
	struct ssh_payload_s *payload=NULL;
	unsigned int error=0;

	get_session_expire_init(session, &expire);
	payload=get_ssh_payload(session, &expire, &sequence, &error);

	if (! payload) {

	    if (session->status.error==0) session->status.error=(error==0) ? EIO : error;
	    logoutput("send_userauth_pubkey_common: error %i waiting for server SSH_MSG_SERVICE_REQUEST (%s)", session->status.error, strerror(session->status.error));
	    return -1;

	}

	if (payload->type==SSH_MSG_USERAUTH_PK_OK) {

	    /*
		message has the form:
		- byte				SSH_MSG_USERAUTH_PK_OK
		- string			algo name
		- string			public key
	    */

	    /* check the received key is the same as the one send */

	    if (check_received_pubkey_pk(payload->buffer, payload->len, public_key)==0) result=0;

	}

	free(payload);
	payload=NULL;

    } else {

	if (session->status.error==0) session->status.error=EIO;
	logoutput("send_userauth_pubkey_common: error %i sending SSH_MSG_SERVICE_REQUEST (%s)", session->status.error, strerror(session->status.error));

    }

    return result;

}

/* perform authentication when no identity file is specified: read from standard locations and try every public key found */

struct common_identity_s *ssh_auth_pubkey_generic(struct ssh_session_s *session, void *ptr, unsigned int *methods)
{
    int result=-1;
    struct common_identity_s *identity=NULL;
    struct ssh_string_s remote_user;
    unsigned int error=0;

    /* get the next public key for this user
	note: the filename is usefull for getting the related private key file later */

    identity=get_next_identity_record(ptr);

    while (identity) {
	struct ssh_key_s public_key;

	init_ssh_key(&public_key);

	if (identity->file) logoutput("ssh_auth_pubkey_generic: send public key (%s)", identity->file);

	if (read_public_key_helper(identity, &public_key)==-1) {

	    logoutput("ssh_auth_pubkey_generic: error reading public key");
	    goto next;

	}

	/* if there is a remote user with this identity take that one
	    otherwise fall back to the local user */

	remote_user.ptr=session->identity.pwd.pw_name;
	if (identity->user) remote_user.ptr=identity->user;
	remote_user.len=strlen(remote_user.ptr);

	if (remote_user.len>0) {
	    char string[remote_user.len+1];

	    memcpy(string, remote_user.ptr, remote_user.len);
	    string[remote_user.len]='\0';

	    logoutput("ssh_auth_pubkey_generic: send user %s", string);

	}

	if (send_userauth_pubkey_common(session, &remote_user, &public_key)==0) {
	    struct ssh_key_s private_key;

	    /* current public key is accepted by server: send signature
		get the private key for this identity */

	    init_ssh_key(&private_key);
	    private_key.type=_PUBKEY_METHOD_PRIVATE;
	    private_key.type|=public_key.type & (_PUBKEY_METHOD_SSH_DSS | _PUBKEY_METHOD_SSH_RSA | _PUBKEY_METHOD_SSH_ED25519);

	    if (read_private_key_helper(identity, &private_key)==0) {

		result=ssh_send_pk_signature(session, &remote_user, &public_key, &private_key, methods);

	    } else {

		/*
		    what to do?
		    if private key is not found try next public key ?
		    or break..
		*/

		logoutput_info("ssh_auth_pubkey_generic: private key not found");

	    }

	    free_ssh_key(&private_key);

	}

	next:

	/* get next identity */
	free_ssh_key(&public_key);
	if (result==0) break;
	free_identity_record(identity);
	identity=get_next_identity_record(ptr);

    }

    return identity;

}
