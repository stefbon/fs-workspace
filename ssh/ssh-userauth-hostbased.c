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
#include "ssh-pubkey-utils.h"
#include "ssh-pubkey-layout.h"

#include "ssh-receive.h"
#include "ssh-queue-payload.h"

#include "ssh-send.h"
#include "ssh-send-userauth.h"
#include "ssh-hostinfo.h"

#include "ssh-utils.h"
#include "ssh-userauth-utils.h"

/*
    function to handle authentication based on host key
    see:
    https://tools.ietf.org/html/rfc4252#section-9
*/
    /*
	create a signature of

	- string		session identifier
	- byte			SSH_MSG_USERAUTH_REQUEST
	- string		username
	- string		service
	- string		"hostbased"
	- string 		algo
	- string		pubkey of this host
	- string		client hostname
	- string		username on this host

	using the private key
    */

static signed char create_hb_signature(struct ssh_session_s *session, struct ssh_string_s *r_user, const char *service, struct ssh_key_s *public_key, struct ssh_string_s *hostname, struct ssh_string_s *l_user, struct ssh_key_s *private_key, struct ssh_string_s *signature)
{
    struct common_buffer_s data=INIT_COMMON_BUFFER;
    unsigned int len=write_userauth_hostbased_request(&data, r_user, service, public_key, hostname, l_user) + 4 + session->data.sessionid.len;
    char buffer[len];
    unsigned int error=0;

    data.ptr=&buffer[0];
    data.pos=data.ptr;
    data.size=len;
    data.len=0;

    /* session id */

    data.len+=copy_ssh_string_to_buffer(&data, &session->data.sessionid);

    /* write the userauth hostbased message */

    data.len+=write_userauth_hostbased_request(&data, r_user, service, public_key, hostname, l_user);

    /* create a signature of this data using the private key belonging to the host key */

    if (create_signature(session, private_key, &data, signature, &error)>=0) {

	return 0;

    } else {

	logoutput_debug("create_pk_signature: error %i creating signature (%s)", error, strerror(error));

    }

    return -1;

}

static int ssh_send_hostbased_signature(struct ssh_session_s *session, struct ssh_string_s *r_user, struct ssh_key_s *public_key, struct ssh_string_s *hostname, struct ssh_string_s *l_user, struct ssh_key_s *private_key, unsigned int *methods)
{
    struct ssh_string_s signature;
    int result=-1;
    unsigned int seq=0;

    init_ssh_string(&signature);

    if (create_hb_signature(session, r_user, "ssh-connection", public_key, hostname, l_user, private_key, &signature)==-1) {

	logoutput("ssh_send_hostbased_signature: creating public hostkey signature failed");
	goto out;

    }

    /* send userauth hostbased request to server with signature */

    if (send_userauth_hostbased_message(session, r_user, "ssh-connection", public_key, hostname, l_user, &signature, &seq)==0) {
	struct timespec expire;
	struct ssh_payload_s *payload=NULL;
	unsigned int error=0;

	get_session_expire_init(session, &expire);

	getresponse:

	payload=get_ssh_payload(session, &expire, &seq, &error);

	if (! payload) {

	    session->userauth.status|=SESSION_USERAUTH_STATUS_ERROR;
	    if (session->status.error==0) session->status.error=EIO;
	    logoutput("ssh_send_hostbased_signature: error %i waiting for server SSH_MSG_SERVICE_REQUEST (%s)", session->status.error, strerror(session->status.error));
	    goto out;

	}

	if (payload->type == SSH_MSG_IGNORE || payload->type == SSH_MSG_DEBUG || payload->type == SSH_MSG_USERAUTH_BANNER ) {

	    process_ssh_message(session, payload);
	    payload=NULL;
	    goto getresponse;

	} else if (payload->type == SSH_MSG_USERAUTH_SUCCESS) {

	    session->userauth.status|=SESSION_USERAUTH_STATUS_ACCEPT;
	    result=0;

	} else if (payload->type == SSH_MSG_USERAUTH_FAILURE) {

	    result=handle_userauth_failure(session, payload, methods);

	} else {

	    session->userauth.status|=SESSION_USERAUTH_STATUS_ERROR;

	}

	if (payload) {

	    free(payload);
	    payload=NULL;

	}

    } else {

	session->userauth.status|=SESSION_USERAUTH_STATUS_ERROR;

    }

    out:

    free_ssh_string(&signature);

    return result;

}

/* perform hostbased authentication try every public hostkey found
    get the public hostkeys from the standard location
    is it known here which type to use?

    TODO: look for the hostkey in the desired format as negotiated in
    https://tools.ietf.org/html/rfc4253#section-7.1 Algorithm Negotiation
    try that first, if failed then try the remaining hostkeys
*/

int ssh_auth_hostbased(struct ssh_session_s *session, struct ssh_string_s *remote_user, struct ssh_string_s *hostname, struct ssh_string_s *local_user, unsigned int *methods)
{
    void *ptr=NULL;
    int result=-1;
    unsigned int error=0;
    struct common_identity_s *identity=NULL;

    logoutput("ssh_auth_hostbased");

    ptr=init_identity_records(&session->identity.pwd, NULL, "host", &error);
    if (ptr==NULL) return -1;

    identity=get_next_identity_record(ptr);

    while (identity) {
	struct ssh_key_s public_key;
	struct ssh_key_s private_key;

	init_ssh_key(&public_key);
	init_ssh_key(&private_key);

	if (identity->file) logoutput("ssh_auth_hostbased: send public key (%s)", identity->file);

	if (read_public_key_helper(identity, &public_key)==-1) {

	    logoutput("ssh_auth_hostbased: error reading public key");
	    goto next;

	}

	private_key.type=_PUBKEY_METHOD_PRIVATE;
	private_key.type|=public_key.type & (_PUBKEY_METHOD_SSH_DSS | _PUBKEY_METHOD_SSH_RSA | _PUBKEY_METHOD_SSH_ED25519);

	if (read_private_key_helper(identity, &private_key)==0) {

	    if (ssh_send_hostbased_signature(session, remote_user, &public_key, hostname, local_user, &private_key, methods)==0) {

		logoutput("ssh_auth_hostbased: server accepted hostkey signature");
		result=0;

	    }

	}

	next:

	free_ssh_key(&public_key);
	free_ssh_key(&private_key);
	free_identity_record(identity);

	if (result==0) break;
	identity=get_next_identity_record(ptr);

    }

    finish:
    finish_identity_records(ptr);

    return result;

}
