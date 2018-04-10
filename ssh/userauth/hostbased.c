/*
  2016, 2017, 2018 Stef Bon <stefbon@gmail.com>

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

#include "common-utils/utils.h"

#include "ssh-common.h"
#include "ssh-common-protocol.h"

#include "ssh-pubkey.h"
#include "pk/pk-types.h"
#include "pk/pk-keys.h"
#include "pk/pk-keystore.h"
#include "pk/sign-types.h"

#include "ssh-receive.h"
#include "ssh-queue-payload.h"

#include "ssh-send.h"
#include "ssh-send-userauth.h"
#include "ssh-hostinfo.h"

#include "ssh-utils.h"
#include "userauth/utils.h"

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

static signed char create_hb_signature(struct ssh_session_s *session, char *r_user, const char *service, struct ssh_key_s *pkey, char *l_hostname, char *l_user, struct ssh_key_s *skey, struct ssh_string_s *signature)
{
    unsigned int len=write_userauth_hostbased_request(NULL, 0, r_user, service, pkey, l_hostname, l_user) + write_ssh_string(NULL, 0, 's', (void *) &session->data.sessionid);
    unsigned int left = len;
    char buffer[len];
    unsigned int error=0;
    int result = 0;
    char *pos = buffer;

    /* session id */

    result = write_ssh_string(pos, left, 's', (void *) &session->data.sessionid);
    pos += result;
    left -= result;

    /* write the userauth hostbased message */

    result = write_userauth_hostbased_request(pos, left, r_user, service, pkey, l_hostname, l_user);
    pos += result;
    left -= result;

    /* create a signature of this data using the private key belonging to the host key */

    if ((* skey->sign)(skey, buffer, (unsigned int)(pos - buffer), signature, NULL, &error)>=0) {

	return 0;

    } else {

	logoutput("create_hb_signature: error %i creating signature (%s)", error, strerror(error));

    }

    return -1;

}

static int ssh_send_hb_signature(struct ssh_session_s *session, char *r_user, struct ssh_key_s *pkey, char *l_hostname, char *l_user, struct ssh_key_s *skey, struct ssh_userauth_s *userauth)
{
    struct ssh_string_s signature;
    int result=-1;
    unsigned int seq=0;

    init_ssh_string(&signature);

    if (create_hb_signature(session, r_user, "ssh-connection", pkey, l_hostname, l_user, skey, &signature)==-1) {

	logoutput("ssh_send_hostbased_signature: creating public hostkey signature failed");
	goto out;

    }

    /* send userauth hostbased request to server with signature */

    if (send_userauth_hostbased_message(session, r_user, "ssh-connection", pkey, l_hostname, l_user, &signature, &seq)==0) {
	struct timespec expire;
	struct ssh_payload_s *payload=NULL;
	unsigned int error=0;

	get_session_expire_init(session, &expire);

	getresponse:

	payload=get_ssh_payload(session, &expire, &seq, &error);

	if (! payload) {

	    if (error==0) error=EIO;
	    logoutput("ssh_send_hb_signature: error %i waiting for server SSH_MSG_SERVICE_REQUEST (%s)", error, strerror(error));
	    userauth->error=error;
	    userauth->status|=SSH_USERAUTH_STATUS_ERROR;
	    goto out;

	}

	if (payload->type == SSH_MSG_IGNORE || payload->type == SSH_MSG_DEBUG || payload->type == SSH_MSG_USERAUTH_BANNER ) {

	    process_ssh_message(session, payload);
	    payload=NULL;
	    goto getresponse;

	} else if (payload->type == SSH_MSG_USERAUTH_SUCCESS) {

	    userauth->required_methods=0;
	    result=0;

	} else if (payload->type == SSH_MSG_USERAUTH_FAILURE) {

	    result=handle_userauth_failure(session, payload, userauth);

	} else {

	    userauth->status|=SSH_USERAUTH_STATUS_ERROR;

	}

	if (payload) {

	    free(payload);
	    payload=NULL;

	}

    } else {

	userauth->status|=SSH_USERAUTH_STATUS_ERROR;

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

struct pk_identity_s *ssh_auth_hostbased(struct ssh_session_s *session, struct pk_list_s *pkeys, char *r_user, char *l_user, struct ssh_userauth_s *userauth)
{
    int result=-1;
    unsigned int error=0;
    struct pk_identity_s *host_identity=NULL;

    logoutput("ssh_auth_hostbased");

    host_identity=get_next_pk_identity(pkeys, "host");

    while (host_identity) {
	struct ssh_key_s pkey;
	struct ssh_key_s skey;

	init_ssh_key(&pkey, SSH_KEY_TYPE_PUBLIC, NULL);
	init_ssh_key(&skey, SSH_KEY_TYPE_PRIVATE, NULL);

	if (read_key_param(host_identity, &pkey)==-1) {

	    logoutput("ssh_auth_hostbased: error reading public key");
	    goto next;

	}

	init_ssh_key(&skey, SSH_KEY_TYPE_PRIVATE, pkey.algo);

	if (read_key_param(host_identity, &skey)==-1) {

	    logoutput("ssh_auth_hostbased: error reading private key");
	    goto next;

	}

	if (ssh_send_hb_signature(session, r_user, &pkey, userauth->l_hostname, l_user, &skey, userauth)==0) {

	    logoutput("ssh_auth_hostbased: server accepted hostkey");
	    result=0;

	}

	next:

	free_ssh_key(&pkey);
	free_ssh_key(&skey);

	if (result==0) break;
	free(host_identity);
	host_identity=get_next_pk_identity(pkeys, "host");

    }

    finish:

    return host_identity;

}
