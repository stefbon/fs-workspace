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
#include "ssh-connection.h"
#include "ssh-utils.h"

#include "userauth/pubkey.h"
#include "userauth/hostbased.h"
#include "userauth/utils.h"
#include "userauth/none.h"
#include "userauth/password.h"

static void init_ssh_userauth(struct ssh_userauth_s *userauth)
{
    memset(userauth, 0, sizeof(struct ssh_userauth_s));

    userauth->required_methods=0;
    userauth->methods_done=0;

    userauth->l_hostname=NULL;
    userauth->l_ipv4=NULL;

    userauth->r_hostname=NULL;
    userauth->r_ipv4=NULL;

    userauth->queue=NULL;

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
    if (methods & SSH_USERAUTH_METHOD_PASSWORD) methods -= SSH_USERAUTH_METHOD_PASSWORD;

    return (methods > 0) ? -1 : 0;
}

int start_ssh_userauth(struct ssh_session_s *session, struct payload_queue_s *queue, struct sessionphase_s *sessionphase)
{
    unsigned int error=0;
    int result=-1;
    struct pk_list_s pkeys;
    struct pk_identity_s *user_identity=NULL;
    struct pk_identity_s *host_identity=NULL;
    struct ssh_userauth_s userauth;

    init_ssh_userauth(&userauth);
    userauth.queue=queue;
    session->userauth=&userauth;

    init_list_public_keys(&session->identity.pwd, &pkeys);

    if (request_ssh_service(session, "ssh-userauth", queue)==-1) {

	logoutput("start_ssh_userauth: request for ssh userauth failed");
	goto finish;

    }

    /* get the list of authemtication 'method name' values
	see https://tools.ietf.org/html/rfc4252#section-5.2: The "none" Authentication Request
	note the remote user is set as the local user since the remote user is not known here */

    if (send_userauth_none(session, session->identity.pwd.pw_name, &userauth)==-1) {

	logoutput("start_ssh_userauth: send userauth none failed");
	goto finish;

    } else {

	if (userauth.required_methods == 0) {

	    /* no futher methods required */

	    result=0;
	    goto finish;

	} else if (userauth_method_supported(userauth.required_methods)==-1) {

	    /* not supported userauth methods requested by server */
	    result=-1;
	    goto finish;

	}

    }

    tryuserauth:

    /* 	try publickey first if required
	assume the order of methods does not matter to the server
    */

    if (userauth.required_methods & SSH_USERAUTH_METHOD_PUBLICKEY) {
	unsigned int status=0;

	result = -1;

	if (userauth.methods_done & SSH_USERAUTH_METHOD_PUBLICKEY) {

	    /* prevent cycles */

	    logoutput("start_ssh_userauth: pk userauth failed: cycles detected");
	    goto finish;

	}

	logoutput("start_ssh_userauth: starting pk userauth");

	/* get list of pk keys from local openssh user files */

	if (populate_list_public_keys(&pkeys, PK_IDENTITY_SOURCE_OPENSSH_LOCAL, "user")==0) {

	    goto finish;

	}

	logoutput("start_ssh_userauth: A");

	userauth.methods_done|=SSH_USERAUTH_METHOD_PUBLICKEY;

	user_identity=ssh_auth_pubkey(session, &pkeys, &userauth);

	logoutput("start_ssh_userauth: B");

	if (user_identity==NULL) {

	    /* pubkey userauth should result in at least one pk identity */

	    logoutput("start_ssh_userauth: no pk identity found");
	    goto finish;

	} else {
	    char *user=get_pk_identity_user(user_identity);
	    char *file=get_pk_identity_file(user_identity);

	    if (user==NULL) user=session->identity.pwd.pw_name;

	    if (file) {

		logoutput("start_ssh_userauth: pk userauth success with file %s (user %s)", file, user);

	    } else {

		logoutput("start_ssh_userauth: pk userauth success with user %s", user);

	    }

	}

	if (userauth.required_methods==0) {

	    /* no more methods required: ready */
	    result=0;
	    goto finish;

	} else if (userauth_method_supported(userauth.required_methods)==-1) {

	    /* not supported userauth methods requested by server */
	    goto finish;

	} else if (userauth.required_methods & SSH_USERAUTH_METHOD_PUBLICKEY) {

	    /* another publickey or unknown or password is not supported */
	    goto finish;

	}

    }

    if (userauth.required_methods & SSH_USERAUTH_METHOD_PASSWORD) {
	unsigned int status=0;
	struct pw_list_s *pwlist=NULL;

	result = -1;

	if (userauth.methods_done & SSH_USERAUTH_METHOD_PASSWORD) {

	    /* prevent cycles */

	    logoutput("start_ssh_userauth: pk userauth failed: cycles detected");
	    goto finish;

	}

	logoutput("start_ssh_userauth: starting password userauth");

	/* get list of pk keys from local openssh user files */

	if (read_private_pwlist(session, &pwlist)==0) {

	    goto finish;

	}

	userauth.methods_done|=SSH_USERAUTH_METHOD_PASSWORD;

	if (ssh_auth_password(session, pwlist, &userauth)==0) {

	    logoutput("start_ssh_userauth: password userauth success");

	}

	free_pwlist(pwlist);

	if (userauth.required_methods==0) {

	    /* no more methods required: ready */
	    result=0;
	    goto finish;

	} else if (userauth_method_supported(userauth.required_methods)==-1) {

	    /* not supported userauth methods requested by server */
	    goto finish;

	} else if (userauth.required_methods & SSH_USERAUTH_METHOD_PASSWORD) {

	    /* another password or unknown or password is not supported */
	    goto finish;

	}

    }

    /* is hostbased auth required? */

    if (userauth.required_methods & SSH_USERAUTH_METHOD_HOSTBASED) {
	char *l_user=NULL;
	char *r_user=NULL;
	unsigned int status=0;
	int fd=-1;

	if (userauth.methods_done & SSH_USERAUTH_METHOD_HOSTBASED) {

	    /* prevent cycles */

	    logoutput("start_ssh_userauth: hostbased auth failed: cycles detected");
	    goto finish;

	}

	if (populate_list_public_keys(&pkeys, PK_IDENTITY_SOURCE_OPENSSH_LOCAL, "host")==0) {

	    goto finish;

	}

	userauth.methods_done|=SSH_USERAUTH_METHOD_HOSTBASED;
	fd=session->connection.io.socket.xdata.fd;
	if (fd>0) userauth.l_hostname=get_connection_hostname(&session->connection, fd, 0, &error);

	if (userauth.l_hostname==NULL) {

	    logoutput("start_ssh_userauth: failed to get local hostname");
	    goto finish;

	}

	logoutput("start_ssh_userauth: using hostname %s for hb userauth", userauth.l_hostname);

	l_user=session->identity.pwd.pw_name;

	if (user_identity) r_user=get_pk_identity_user(user_identity);
	if (r_user==NULL) r_user=l_user;

	logoutput("start_ssh_userauth: using local user %s amd remote user %s for hb userauth", l_user, r_user);

	host_identity=ssh_auth_hostbased(session, &pkeys, r_user, l_user, &userauth);

	if (host_identity==NULL) {

	    /* hostbased userauth should result in at least one pk identity */

	    logoutput("start_ssh_userauth: hostbased auth failed/no identity found");
	    goto finish;

	}

	if (userauth.required_methods==0) {

	    /* no more methods required: ready */
	    result=0;
	    goto finish;

	} else if (userauth.required_methods & SSH_USERAUTH_METHOD_HOSTBASED) {

	    /* another hb userauth is not supported */
	    result=-1;
	    goto finish;

	} else if (userauth_method_supported(userauth.required_methods)==-1) {

	    /* another publickey or unknown or password is not supported */
	    result=-1;
	    goto finish;

	}

    }

    if (userauth.required_methods & (SSH_USERAUTH_METHOD_PUBLICKEY | SSH_USERAUTH_METHOD_HOSTBASED | SSH_USERAUTH_METHOD_PASSWORD)) {

	goto tryuserauth;

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

	if (r_user) {

	    logoutput("start_ssh_userauth: remote user %s", r_user);

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
    clear_ssh_userauth(&userauth);
    free_lists_public_keys(&pkeys);

    return result;

}
