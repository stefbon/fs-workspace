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

#include "ssh-receive.h"
#include "ssh-send.h"
#include "ssh-connections.h"
#include "ssh-utils.h"

#include "userauth/pubkey.h"
#include "userauth/hostbased.h"
#include "userauth/utils.h"
#include "userauth/none.h"
#include "userauth/password.h"

void init_ssh_auth(struct ssh_auth_s *auth)
{
    memset(auth, 0, sizeof(struct ssh_auth_s));

    auth->required=0;
    auth->done=0;

    auth->l_hostname=NULL;
    auth->l_ipv4=NULL;

    auth->r_hostname=NULL;
    auth->r_ipv4=NULL;

}

void clear_ssh_auth(struct ssh_auth_s *auth)
{
    if (auth->l_hostname) free(auth->l_hostname);
    if (auth->l_ipv4) free(auth->l_ipv4);
    if (auth->r_hostname) free(auth->r_hostname);
    if (auth->r_ipv4) free(auth->r_ipv4);
}

static int ssh_auth_method_supported(unsigned int methods)
{

    if (methods & SSH_AUTH_METHOD_NONE) methods -= SSH_AUTH_METHOD_NONE;
    if (methods & SSH_AUTH_METHOD_PUBLICKEY) methods -= SSH_AUTH_METHOD_PUBLICKEY;
    if (methods & SSH_AUTH_METHOD_HOSTBASED) methods -= SSH_AUTH_METHOD_HOSTBASED;
    if (methods & SSH_AUTH_METHOD_PASSWORD) methods -= SSH_AUTH_METHOD_PASSWORD;

    return (methods > 0) ? -1 : 0;
}

int start_ssh_auth(struct ssh_connection_s *connection)
{
    struct ssh_session_s *session=get_ssh_connection_session(connection);
    unsigned int error=0;
    int result=-1;
    struct pk_list_s pkeys;
    struct pk_identity_s *user_identity=NULL;
    struct pk_identity_s *host_identity=NULL;
    struct ssh_setup_s *setup=&connection->setup;
    struct ssh_auth_s *auth=&setup->phase.service.type.auth;

    init_list_public_keys(&session->identity.pwd, &pkeys);

    if (request_ssh_service(connection, "ssh-userauth")==-1) {

	logoutput("start_ssh_auth: request for ssh userauth failed");
	goto finish;

    }

    /* get the list of authemtication 'method name' values
	see https://tools.ietf.org/html/rfc4252#section-5.2: The "none" Authentication Request
	note the remote user is set as the local user since the remote user is not known here */

    if (send_auth_none(connection, session->identity.pwd.pw_name, auth)==-1) {

	logoutput("start_ssh_auth: send userauth none failed");
	goto finish;

    } else {

	if (auth->required == 0) {

	    /* no futher methods required */

	    result=0;
	    goto finish;

	} else if (ssh_auth_method_supported(auth->required)==-1) {

	    /* not supported userauth methods requested by server */
	    result=-1;
	    goto finish;

	}

    }

    tryuserauth:

    logoutput("start_ssh_auth: (done: %i required: %i)", auth->done, auth->required);

    /* 	try publickey first if required
	assume the order of methods does not matter to the server
    */

    if (auth->required & SSH_AUTH_METHOD_PUBLICKEY) {
	unsigned int status=0;

	result = -1;

	if (auth->done & SSH_AUTH_METHOD_PUBLICKEY) {

	    /* prevent cycles */

	    logoutput("start_ssh_auth: pk userauth failed: cycles detected");
	    goto finish;

	}

	logoutput("start_ssh_auth: starting pk userauth");

	/* get list of pk keys from local openssh user files */

	if (populate_list_public_keys(&pkeys, PK_IDENTITY_SOURCE_OPENSSH_LOCAL, "user")==0) {

	    goto finish;

	}

	auth->done|=SSH_AUTH_METHOD_PUBLICKEY;
	user_identity=ssh_auth_pubkey(connection, &pkeys, auth);

	if (user_identity==NULL) {

	    /* pubkey userauth should result in at least one pk identity */

	    logoutput("start_ssh_auth: no pk identity found");
	    goto finish;

	} else {
	    char *user=get_pk_identity_user(user_identity);
	    char *file=get_pk_identity_file(user_identity);

	    if (user==NULL) user=session->identity.pwd.pw_name;
	    logoutput("start_ssh_auth: pk userauth success (done: %i required: %i) with file %s (user %s)", auth->done, auth->required, (file ? file : "unknown"), user);

	}

	if (auth->required==0) {

	    /* no more methods required: ready */
	    logoutput("start_ssh_auth: no more methods required");
	    result=0;
	    goto finish;

	} else if (ssh_auth_method_supported(auth->required)==-1) {

	    /* not supported userauth methods requested by server */
	    logoutput("start_ssh_auth: methods not supported");
	    goto finish;

	} else if (auth->required & SSH_AUTH_METHOD_PUBLICKEY) {

	    /* another publickey or unknown or password is not supported */
	    logoutput("start_ssh_auth: more than one publickey required, not supported");
	    goto finish;

	}

    }

    if (auth->required & SSH_AUTH_METHOD_PASSWORD) {
	unsigned int status=0;
	struct pw_list_s *pwlist=NULL;

	result = -1;

	if (auth->done & SSH_AUTH_METHOD_PASSWORD) {

	    /* prevent cycles */

	    logoutput("start_ssh_auth: pk userauth failed: cycles detected");
	    goto finish;

	}

	logoutput("start_ssh_auth: starting password userauth");

	/* get list of pk keys from local openssh user files */

	if (read_private_pwlist(connection, &pwlist)==0) {

	    goto finish;

	}

	auth->done|=SSH_AUTH_METHOD_PASSWORD;

	if (ssh_auth_password(connection, pwlist, auth)==0) {

	    logoutput("start_ssh_auth: password auth success (done: %i required: %i)", auth->done, auth->required);

	}

	free_pwlist(pwlist);

	if (auth->required==0) {

	    /* no more methods required: ready */
	    result=0;
	    goto finish;

	} else if (ssh_auth_method_supported(auth->required)==-1) {

	    /* not supported userauth methods requested by server */
	    goto finish;

	} else if (auth->required & SSH_AUTH_METHOD_PASSWORD) {

	    /* another password or unknown or password is not supported */
	    goto finish;

	}

    }

    /* is hostbased auth required? */

    if (auth->required & SSH_AUTH_METHOD_HOSTBASED) {
	char *l_user=NULL;
	char *r_user=NULL;
	unsigned int status=0;
	int fd=-1;

	if (auth->done & SSH_AUTH_METHOD_HOSTBASED) {

	    /* prevent cycles */

	    logoutput("start_ssh_auth: hostbased auth failed: cycles detected");
	    goto finish;

	}

	if (populate_list_public_keys(&pkeys, PK_IDENTITY_SOURCE_OPENSSH_LOCAL, "host")==0) {

	    goto finish;

	}

	auth->done|=SSH_AUTH_METHOD_HOSTBASED;
	fd=connection->connection.io.socket.xdata.fd;
	if (fd>0) auth->l_hostname=get_connection_hostname(&connection->connection, fd, 0, &error);

	if (auth->l_hostname==NULL) {

	    logoutput("start_ssh_auth: failed to get local hostname");
	    goto finish;

	}

	logoutput("start_ssh_auth: using hostname %s for hb userauth", auth->l_hostname);
	l_user=session->identity.pwd.pw_name;

	if (user_identity) r_user=get_pk_identity_user(user_identity);
	if (r_user==NULL) r_user=l_user;

	logoutput("start_ssh_userauth: using local user %s amd remote user %s for hb userauth", l_user, r_user);

	host_identity=ssh_auth_hostbased(connection, &pkeys, r_user, l_user, auth);

	if (host_identity==NULL) {

	    /* hostbased userauth should result in at least one pk identity */

	    logoutput("start_ssh_userauth: hostbased failed/no identity found");
	    goto finish;

	} else {

	    logoutput("start_ssh_auth: hostbased success (done: %i required: %i)", auth->done, auth->required);

	}

	if (auth->required==0) {

	    /* no more methods required: ready */
	    result=0;
	    goto finish;

	} else if (auth->required & SSH_AUTH_METHOD_HOSTBASED) {

	    /* another hb userauth is not supported */
	    result=-1;
	    goto finish;

	} else if (ssh_auth_method_supported(auth->required)==-1) {

	    /* another publickey or unknown or password is not supported */
	    result=-1;
	    goto finish;

	}

    }

    if (auth->required & (SSH_AUTH_METHOD_PUBLICKEY | SSH_AUTH_METHOD_HOSTBASED | SSH_AUTH_METHOD_PASSWORD)) goto tryuserauth;

    finish:

    if (result == 0) {
	char *r_user=NULL;
	unsigned int len=0;

	if (user_identity) {

	    r_user=get_pk_identity_user(user_identity);

	    /* fallback to local user */

	    if (r_user==NULL) r_user=session->identity.pwd.pw_name;

	}

	if (r_user) {

	    logoutput("start_ssh_auth: remote user %s", r_user);

	    len=strlen(r_user);

	    /* if there is a remote user keep that */

	    session->identity.remote_user.ptr=malloc(len);

	    if (session->identity.remote_user.ptr) {

		memcpy(session->identity.remote_user.ptr, r_user, len);
		session->identity.remote_user.len=len;

	    }

	}

    }

    /* also do something with the public key file ? */

    if (host_identity) free(host_identity);
    if (user_identity) free(user_identity);
    free_lists_public_keys(&pkeys);

    return result;

}
