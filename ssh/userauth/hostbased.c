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
#include "ssh-connections.h"
#include "ssh-receive.h"
#include "ssh-send.h"
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

static unsigned int msg_write_pk_signature(struct msg_buffer_s *mb, struct ssh_session_s *session, char *r_user, const char *service, struct ssh_key_s *pkey, char *l_hostname, char *l_user)
{
    msg_write_ssh_string(mb, 's', (void *) &session->data.sessionid);
    msg_write_userauth_hostbased_request(mb, r_user, service, pkey, l_hostname, l_user);
    return mb->pos;
}

static signed char create_hb_signature(struct ssh_session_s *session, char *r_user, const char *service, struct ssh_key_s *pkey, char *l_hostname, char *l_user, struct ssh_key_s *skey, struct ssh_string_s *signature)
{
    struct msg_buffer_s mb=INIT_SSH_MSG_BUFFER;
    unsigned int len=msg_write_pk_signature(&mb, session, r_user, service, pkey, l_hostname, l_user) + 64;
    char buffer[len];
    unsigned int error=0;
    int result = 0;
    struct ssh_pksign_s *pksign=NULL;
    const char *hashname=NULL;

    pksign=get_default_pksign(pkey->algo);
    hashname=get_hashname_sign(pksign);

    logoutput("create_hb_signature: hash %s", hashname);

    set_msg_buffer(&mb, buffer, len);
    len=msg_write_pk_signature(&mb, session, r_user, service, pkey, l_hostname, l_user);

    /* create a signature of this data using the private key belonging to the host key */

    if ((* skey->sign)(skey, buffer, len, signature, hashname, &error)>=0) {

	return 0;

    } else {

	logoutput("create_hb_signature: error %i creating signature (%s)", error, strerror(error));

    }

    return -1;

}

static int ssh_send_hb_signature(struct ssh_connection_s *connection, char *r_user, struct ssh_key_s *pkey, char *l_hostname, char *l_user, struct ssh_key_s *skey, struct ssh_auth_s *auth)
{
    struct ssh_session_s *session=get_ssh_connection_session(connection);
    struct ssh_string_s signature;
    int result=-1;
    unsigned int seq=0;
    unsigned int error=EIO;

    logoutput("ssh_send_hostbased_signature");

    init_ssh_string(&signature);

    if (create_hb_signature(session, r_user, "ssh-connection", pkey, l_hostname, l_user, skey, &signature)==-1) {

	logoutput("ssh_send_hostbased_signature: creating public hostkey signature failed");
	goto out;

    }

    logoutput("ssh_send_hostbased_signature: created hash %i bytes", signature.len);

    /* send userauth hostbased request to server with signature */

    if (send_userauth_hostbased_message(connection, r_user, "ssh-connection", pkey, l_hostname, l_user, &signature, &seq)==0) {
	struct ssh_payload_s *payload=NULL;

	payload=receive_message_common(connection, handle_auth_reply, &error);
	if (payload==NULL) goto out;

	if (payload->type == SSH_MSG_USERAUTH_SUCCESS) {

	    logoutput("ssh_send_hostbased_signature: success");
	    auth->required=0;
	    result=0;

	} else if (payload->type == SSH_MSG_USERAUTH_FAILURE) {

	    logoutput("ssh_send_hostbased_signature: failed");
	    result=handle_auth_failure(payload, auth);

	}

	free_payload(&payload);

    } else {

	logoutput("ssh_send_hostbased_signature: error sending SSH_MSG_SERVICE_REQUEST");

    }

    out:

    free_ssh_string(&signature);
    if (result==-1) logoutput("ssh_send_hostbased_signature: error %i (%s)", error, strerror(error));
    return result;

}

/* perform hostbased authentication try every public hostkey found
    get the public hostkeys from the standard location
    is it known here which type to use?

    TODO: look for the hostkey in the desired format as negotiated in
    https://tools.ietf.org/html/rfc4253#section-7.1 Algorithm Negotiation
    try that first, if failed then try the remaining hostkeys
*/

struct pk_identity_s *ssh_auth_hostbased(struct ssh_connection_s *connection, struct pk_list_s *pkeys, char *r_user, char *l_user, struct ssh_auth_s *auth)
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

	if (ssh_send_hb_signature(connection, r_user, &pkey, auth->l_hostname, l_user, &skey, auth)==0) {

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
