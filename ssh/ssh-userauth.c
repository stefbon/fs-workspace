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

#include "utils.h"
#include "network-utils.h"

#include "ssh-common.h"
#include "ssh-common-protocol.h"

#include "ssh-pubkey.h"

#include "ssh-receive.h"
#include "ssh-queue-payload.h"

#include "ssh-send.h"
#include "ssh-send-userauth.h"
#include "ssh-connection.h"
#include "ssh-utils.h"

#include "pk/pk-types.h"
#include "pk/pk-keys.h"
#include "pk/pk-utils.h"
#include "pk/pk-keystore.h"

#include "userauth/pubkey.h"
#include "userauth/hostbased.h"
#include "userauth/utils.h"
#include "userauth/none.h"

static void init_ssh_userauth(struct ssh_userauth_s *userauth)
{
    memset(userauth, 0, sizeof(struct ssh_userauth_s));

    userauth->status=0;
    userauth->error=0;
    userauth->required_methods=0;
    userauth->methods_done=0;

    userauth->l_hostname=NULL;
    userauth->l_ipv4=NULL;

    userauth->r_hostname=NULL;
    userauth->r_ipv4=NULL;

}

static void clear_ssh_userauth(struct ssh_userauth_s *userauth)
{

    if (userauth->l_hostname) free(userauth->l_hostname);
    if (userauth->l_ipv4) free(userauth->l_ipv4);

    if (userauth->r_hostname) free(userauth->r_hostname);
    if (userauth->r_ipv4) free(userauth->r_ipv4);

}

static int userauth_method_supported(unsigned int methods)
{

    if (methods & SSH_USERAUTH_METHOD_NONE) methods -= SSH_USERAUTH_METHOD_NONE;
    if (methods & SSH_USERAUTH_METHOD_PUBLICKEY) methods -= SSH_USERAUTH_METHOD_PUBLICKEY;
    if (methods & SSH_USERAUTH_METHOD_HOSTBASED) methods -= SSH_USERAUTH_METHOD_HOSTBASED;

    return (methods > 0) ? -1 : 0;
}

int ssh_authentication(struct ssh_session_s *session)
{
    unsigned int error=0;
    int result=-1;
    struct pk_list_s pkeys;
    struct pk_identity_s *user_identity=NULL;
    struct pk_identity_s *host_identity=NULL;
    struct ssh_userauth_s userauth;

    init_ssh_userauth(&userauth);

    init_list_public_keys(&session->identity.pwd, &pkeys);

    /* get the list of authemtication 'method name' values
	see https://tools.ietf.org/html/rfc4252#section-5.2: The "none" Authentication Request
	note the remote user is set as the local user since the remote user is not known here */

    result=send_userauth_none(session, session->identity.pwd.pw_name, &userauth);

    if (userauth.status == SSH_USERAUTH_STATUS_DISCONNECT || userauth.error > 0) {

	/* system/fatal error and/or disconnected by server */
	result=-1;
	goto finish;

    } else if (userauth.required_methods == SSH_USERAUTH_METHOD_NONE || userauth.required_methods == 0) {

	/* no futher methods required */
	userauth.status=SSH_USERAUTH_STATUS_SUCCESS;
	result=0;
	goto finish;

    } else if (userauth_method_supported(userauth.required_methods)==-1) {

	/* not supported userauth methods requested by server */
	result=-1;
	goto finish;

    }

    trypublickey:

    /* 	try publickey first if required
	assume the order of methods does not matter to the server
    */

    if (userauth.required_methods & SSH_USERAUTH_METHOD_PUBLICKEY) {

	result = -1;

	if (userauth.methods_done & SSH_USERAUTH_METHOD_PUBLICKEY) {

	    /* prevent cycles */

	    logoutput("ssh_authentication: publickey auth failed: cycles detected");
	    userauth.status|=SSH_USERAUTH_STATUS_FAILURE;
	    goto finish;

	}

	logoutput("ssh_authentication: starting publickey userauth");

	if (populate_list_public_keys(&pkeys, PK_IDENTITY_SOURCE_OPENSSH_LOCAL, "user")==0) {

	    userauth.status|=SSH_USERAUTH_STATUS_FAILURE;
	    goto finish;

	}

	userauth.methods_done|=SSH_USERAUTH_METHOD_PUBLICKEY;

	user_identity=ssh_auth_pubkey(session, &pkeys, &userauth);

	if (userauth.status == SSH_USERAUTH_STATUS_DISCONNECT || userauth.status == SSH_USERAUTH_STATUS_FAILURE || userauth.status == SSH_USERAUTH_STATUS_ERROR) {

	    /* system/fatal error and/or disconnected by server */
	    goto finish;

	}

	if (user_identity==NULL) {

	    /* pubkey userauth should result in at least one pk identity */

	    logoutput("ssh_authentication: publickey auth failed/no identity found");
	    userauth.status|=SSH_USERAUTH_STATUS_FAILURE;
	    goto finish;

	} else {
	    char *user=get_pk_identity_user(user_identity);
	    char *file=get_pk_identity_file(user_identity);

	    if (user==NULL) user=session->identity.pwd.pw_name;

	    if (file) {

		logoutput("ssh_authentication: publickey userauth success with file %s (user %s)", file, user);

	    } else {

		logoutput("ssh_authentication: publickey userauth success with user %s", user);

	    }

	}

	if (userauth.required_methods==0) {

	    /* no more methods required: ready */
	    userauth.status=SSH_USERAUTH_STATUS_SUCCESS;
	    result=0;
	    goto finish;

	} else if (userauth_method_supported(userauth.required_methods)==-1) {

	    userauth.status|=SSH_USERAUTH_STATUS_FAILURE;
	    userauth.error=EPROTO;
	    goto finish;

	} else if ( userauth.required_methods & SSH_USERAUTH_METHOD_PUBLICKEY) {

	    /* another publickey or unknown or password is not supported */
	    userauth.status|=SSH_USERAUTH_STATUS_FAILURE;
	    userauth.error=EPROTO;
	    goto finish;

	}

    }

    /* is hostbased auth required? */

    if (userauth.required_methods & SSH_USERAUTH_METHOD_HOSTBASED) {
	char *l_user=NULL;
	char *r_user=NULL;

	if (userauth.methods_done & SSH_USERAUTH_METHOD_HOSTBASED) {

	    /* prevent cycles */

	    logoutput("ssh_authentication: hostbased auth failed: cycles detected");
	    userauth.status|=SSH_USERAUTH_STATUS_FAILURE;
	    goto finish;

	}

	if (populate_list_public_keys(&pkeys, PK_IDENTITY_SOURCE_OPENSSH_LOCAL, "host")==0) {

	    userauth.status|=SSH_USERAUTH_STATUS_FAILURE;
	    goto finish;

	}

	userauth.methods_done|=SSH_USERAUTH_METHOD_HOSTBASED;

	userauth.l_hostname=get_connection_hostname(session->connection.fd, 0, &error);

	if (userauth.l_hostname==NULL) {

	    logoutput("ssh_authentication: failed to get local hostname");
	    userauth.status|=SSH_USERAUTH_STATUS_ERROR;
	    userauth.error=error;
	    goto finish;

	}

	logoutput("ssh_authentication: using hostname %s for hostbased userauth", userauth.l_hostname);

	l_user=session->identity.pwd.pw_name;

	if (user_identity) {

	    r_user=get_pk_identity_user(user_identity);
	    if (r_user==NULL) r_user=l_user;

	}

	host_identity=ssh_auth_hostbased(session, &pkeys, r_user, l_user, &userauth);

	if (userauth.status == SSH_USERAUTH_STATUS_DISCONNECT || userauth.error > 0) {

	    /* system/fatal error and/or disconnected by server */
	    goto finish;

	}

	if (host_identity==NULL) {

	    /* hostbased userauth should result in at least one pk identity */

	    logoutput("ssh_authentication: hostbased auth failed/no identity found");
	    userauth.status|=SSH_USERAUTH_STATUS_FAILURE;
	    goto finish;

	}

	if (userauth.required_methods==0) {

	    /* no more methods required: ready */
	    userauth.status=SSH_USERAUTH_STATUS_SUCCESS;
	    result=0;
	    goto finish;

	} else if (userauth.required_methods & SSH_USERAUTH_METHOD_HOSTBASED) {

	    /* another publickey or unknown or password is not supported */
	    userauth.status|=SSH_USERAUTH_STATUS_FAILURE;
	    userauth.error=EPROTO;
	    result=-1;
	    goto finish;

	} else if (userauth_method_supported(userauth.required_methods)==-1) {

	    /* another publickey or unknown or password is not supported */
	    userauth.status|=SSH_USERAUTH_STATUS_FAILURE;
	    userauth.error=EPROTO;
	    result=-1;
	    goto finish;

	} else if (userauth.required_methods & SSH_USERAUTH_METHOD_PUBLICKEY) {

	    goto trypublickey;

	}

    }

    finish:

    if (result == 0) {
	char *r_user=NULL;
	unsigned int len=0;

	if (user_identity) {

	    r_user=get_pk_identity_user(user_identity);

	    /* fallback to local user */

	    if (r_user==NULL) r_user=session->identity.pwd.pw_name;

	}

	len=strlen(r_user);

	/* if there is a remote user keep that */

	session->identity.remote_user.ptr=malloc(len);

	if (session->identity.remote_user.ptr) {

	    memcpy(session->identity.remote_user.ptr, r_user, len);
	    session->identity.remote_user.len=len;

	}

    }

    /* also do something with the public key file ? */

    if (host_identity) free(host_identity);
    if (user_identity) free(user_identity);

    clear_ssh_userauth(&userauth);
    free_lists_public_keys(&pkeys);

    return result;

}
