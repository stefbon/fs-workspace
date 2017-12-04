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

#include "ssh-receive.h"
#include "ssh-queue-payload.h"

#include "ssh-send.h"
#include "ssh-send-userauth.h"
#include "ssh-connection.h"

#include "ssh-utils.h"
#include "ssh-userauth-pubkey.h"
#include "ssh-userauth-hostbased.h"
#include "ssh-userauth-utils.h"

int ssh_authentication(struct ssh_session_s *session)
{
    struct ssh_string_s local_user;
    unsigned int error=0;
    char *remotehostname=NULL;
    char *remoteipv4=NULL;
    char *localhostname=NULL;
    unsigned int required_methods=0;
    unsigned int sequence=0;
    void *ptr=NULL;
    int result=-1;
    struct common_identity_s *identity=NULL;
    struct hostaddress_s hostaddress;

    local_user.ptr=session->identity.pwd.pw_name;
    local_user.len=strlen(local_user.ptr);

    /* find the user and identity to connect with
	with openssh there are different config file's
	where (user and/or system wide) the remote user and/or
	the identity is defined
    */

    remotehostname=get_ssh_hostname(session, 1, &error);

    if (remotehostname==NULL) {

	logoutput("ssh_authentication: failed to get remote hostname (error %i:%s)", error, strerror(error));
	goto finish;

    }

    remoteipv4=get_ssh_ipv4(session, 1, &error);

    if (remoteipv4==NULL) {

	logoutput("ssh_authentication: failed to get remote ipv number (error %i:%s)", error, strerror(error));
	goto finish;

    }

    hostaddress.type=_HOSTADDRESS_TYPE_IPV4;
    hostaddress.ip=remoteipv4;
    hostaddress.hostname=remotehostname;

    logoutput("ssh_authentication: found remote host %s", remotehostname);

    ptr=init_identity_records(&session->identity.pwd, &hostaddress, "user", &error);

    if (ptr==NULL) {

	logoutput("ssh_authentication: error %i init public keys for user (%s)", error, strerror(error));
	goto finish;

    }

    /* get the list of authemtication 'method name' values
	see https://tools.ietf.org/html/rfc4252#section-5.2: The "none" Authentication Request
	note the remote user is set as the local user since the remote user is not known here */

    logoutput("ssh_authentication: send none userauth request");

    if (send_userauth_none_message(session, &local_user, "ssh-connection", &sequence)==0) {
	struct ssh_payload_s *payload=NULL;
	struct timespec expire;

	get_session_expire_init(session, &expire);

	getresponse:

	payload=get_ssh_payload(session, &expire, &sequence, &error);

	if (! payload) {

	    session->userauth.status|=SESSION_USERAUTH_STATUS_ERROR;
	    if (error==0) error=EIO;
	    logoutput("ssh_authentication: error %i waiting for server SSH_MSG_USERAUTH_REQUEST (%s)", error, strerror(error));
	    goto finish;

	}

	if (payload->type == SSH_MSG_USERAUTH_SUCCESS) {

	    /* huhh?? which server allows this weak security? */

	    logoutput("ssh_authentication: server accepted none.....");
	    session->userauth.status|=SESSION_USERAUTH_STATUS_SUCCESS;
	    required_methods=SSH_USERAUTH_NONE;
	    result=0;

	} else if (payload->type == SSH_MSG_USERAUTH_FAILURE) {
	    unsigned int methods=0;

	    /* failure gives the required methods */

	    logoutput("ssh_authentication: handle failure/get methods");

	    result=handle_userauth_failure(session, payload, &methods);
	    if (methods>0) required_methods=methods;

	} else if (payload->type == SSH_MSG_IGNORE || payload->type == SSH_MSG_DEBUG || payload->type == SSH_MSG_USERAUTH_BANNER) {

	    process_ssh_message(session, payload);
	    payload=NULL;
	    goto getresponse;

	} else {

	    logoutput("ssh_authentication: got unexpected reply %i", payload->type);
	    session->userauth.status|=SESSION_USERAUTH_STATUS_ERROR;
	    error=EPROTO;

	}

	if (payload) {

	    free(payload);
	    payload=NULL;

	}

    } else {

	session->userauth.status|=SESSION_USERAUTH_STATUS_ERROR;
	error=(session->status.error==0) ? session->status.error : EIO;
	logoutput("ssh_authentication: error %i sending SSH_MSG_USERAUTH_REQUEST (%s)", error, strerror(error));

    }

    if ((session->userauth.status&SESSION_USERAUTH_STATUS_ERROR) ||
	required_methods==SSH_USERAUTH_NONE ||
	(required_methods & SSH_USERAUTH_UNKNOWN)) goto finish;

    /* try publickey first if required
	assume the order of methods does not matter to the server */

    if (required_methods & SSH_USERAUTH_PUBLICKEY) {
	unsigned int methods=0;

	identity=ssh_auth_pubkey(session, ptr, &methods);

	if (identity==NULL) {

	    logoutput("ssh_authentication: publickey auth failed/no identity found");
	    session->userauth.status|=SESSION_USERAUTH_STATUS_ERROR;
	    goto finish;

	}

	if (methods==0) {

	    /* no more methods required: ready */
	    session->userauth.status|=SESSION_USERAUTH_STATUS_SUCCESS;
	    required_methods=0;
	    result=0;

	} else {

	    /* still methods to do */

	    if (methods & (SSH_USERAUTH_PUBLICKEY | SSH_USERAUTH_UNKNOWN)) {

		/* another publickey or unknown is not supported */
		session->userauth.status|=SESSION_USERAUTH_STATUS_ERROR;
		error=EPROTO;
		result=-1;
		goto finish;

	    } else {

		required_methods=methods;

	    }

	}

    }

    if (required_methods & SSH_USERAUTH_HOSTBASED) {
	unsigned int methods=0;
	struct ssh_string_s remote_user;
	struct ssh_string_s hostname;

	localhostname=get_ssh_hostname(session, 0, &error);

	if (localhostname==NULL) {

	    logoutput("ssh_authentication: failed to get local hostname");
	    session->userauth.status|=SESSION_USERAUTH_STATUS_ERROR;
	    goto finish;

	}

	hostname.ptr=localhostname;
	hostname.len=strlen(localhostname);

	logoutput("ssh_authentication: found local host %s", localhostname);

	remote_user.ptr=session->identity.pwd.pw_name;
	if (identity && identity->user) remote_user.ptr=identity->user;
	remote_user.len=strlen(remote_user.ptr);

	result=ssh_auth_hostbased(session, &remote_user, &hostname, &local_user, &methods);

	if (result==0) {

	    if (methods==0) {

		/* no more methods required: ready */
		session->userauth.status|=SESSION_USERAUTH_STATUS_SUCCESS;
		required_methods=0;

	    } else {

		/* still methods to do */

		if (methods & (SSH_USERAUTH_HOSTBASED | SSH_USERAUTH_UNKNOWN)) {

		    /* another hostbased/unknown is not supported */
		    session->userauth.status|=SESSION_USERAUTH_STATUS_ERROR;
		    result=-1;
		    goto finish;

		} else {

		    required_methods=methods;

		}

	    }

	} else {

	    logoutput("ssh_authentication: hostbased auth failed");
	    session->userauth.status|=SESSION_USERAUTH_STATUS_ERROR;
	    result=-1;

	}

    }

    out:

    if (required_methods>0) {

	if (required_methods & SSH_USERAUTH_PUBLICKEY) logoutput("ssh_authentication: failed: publickey required");
	if (required_methods & SSH_USERAUTH_HOSTBASED) logoutput("ssh_authentication: failed: hostbased required");
	if (required_methods & SSH_USERAUTH_PASSWORD) logoutput("ssh_authentication: failed: password required");
	if (required_methods & SSH_USERAUTH_UNKNOWN) logoutput("ssh_authentication: failed: unknown required");
	result=-1;

    } else {

	logoutput("ssh_authentication: no more methods required (result=%s)", result==0 ? "success" : "failed");

    }

    finish:

    if (remotehostname) {

	free(remotehostname);
	remotehostname=NULL;

    }

    if (remoteipv4) {

	free(remoteipv4);
	remoteipv4=NULL;

    }

    if (localhostname) {

	free(localhostname);
	localhostname=NULL;

    }

    if (identity) {

	/* if there is a remote user with this identity take this one
	    otherwise fall back to the local user */

	if (identity->user) {

	    session->identity.remote_user.ptr=identity->user;
	    identity->user=NULL;

	} else {

	    session->identity.remote_user.ptr=local_user.ptr;

	}

	session->identity.remote_user.len=strlen(session->identity.remote_user.ptr);

	free_identity_record(identity);
	identity=NULL;

    }

    if (ptr) {

	finish_identity_records(ptr);
	ptr=NULL;

    }

    return result;

}
