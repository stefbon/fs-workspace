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

#include <utils.h>

#include "ssh-common.h"
#include "ssh-common-protocol.h"

#include "ssh-pubkey.h"

#include "ssh-receive.h"
#include "ssh-queue-payload.h"

#include "ssh-send.h"
#include "ssh-send-userauth.h"
#include "ssh-connection.h"

#include "ssh-utils.h"

#include "userauth/pubkey.h"
#include "userauth/hostbased.h"
#include "userauth/utils.h"

int send_userauth_none(struct ssh_session_s *session, char *user, struct ssh_userauth_s *userauth)
{
    unsigned int error=0;
    unsigned int seq=0;
    int result=-1;

    /* get the list of authemtication 'method name' values
	see https://tools.ietf.org/html/rfc4252#section-5.2: The "none" Authentication Request
	note the remote user is set as the local user since the remote user is not known here */

    logoutput("ssh_userauth_none: send none userauth request");

    if (send_userauth_none_message(session, user, "ssh-connection", &seq)==0) {
	struct ssh_payload_s *payload=NULL;
	struct timespec expire;

	get_session_expire_init(session, &expire);

	getresponse:

	payload=get_ssh_payload(session, &expire, &seq, &error);

	if (! payload) {

	    /* why not receiving payload ? */

	    if (error==EOPNOTSUPP) {

		/* not supported ??
		    protocol error */

		userauth->status|=SSH_USERAUTH_STATUS_DISCONNECT;

	    } else if (error==ETIMEDOUT) {

		/* why timedout ?
		    here analyse why */

		userauth->status|=SSH_USERAUTH_STATUS_DISCONNECT;

	    } else {

		if (error == 0) error=EIO;
		userauth->status|=SSH_USERAUTH_STATUS_FAILURE;

	    }

	    userauth->error=error;
	    logoutput("ssh_userauth_none: error %i waiting for server SSH_MSG_USERAUTH_REQUEST (%s)", error, strerror(error));
	    goto finish;

	}

	if (payload->type == SSH_MSG_USERAUTH_SUCCESS) {

	    /* huhh?? which server allows this weak security? */
	    logoutput("ssh_userauth_none: server accepted none.....");
	    userauth->required_methods=0;
	    result=0;

	} else if (payload->type == SSH_MSG_USERAUTH_FAILURE) {

	    result=handle_userauth_failure(session, payload, userauth);

	} else if (payload->type == SSH_MSG_IGNORE || payload->type == SSH_MSG_DEBUG || payload->type == SSH_MSG_USERAUTH_BANNER) {

	    process_ssh_message(session, payload);
	    payload=NULL;
	    goto getresponse;

	} else {

	    if (payload->type == SSH_MSG_DISCONNECT) {

		logoutput("ssh_userauth_none: received disconnect message");

	    } else {

		logoutput("ssh_userauth_none: got unexpected reply %i", payload->type);
		userauth->error=EPROTO;

	    }

	    userauth->status|=SSH_USERAUTH_STATUS_DISCONNECT;

	}

	if (payload) {

	    free(payload);
	    payload=NULL;

	}

    } else {

	/* why send error ?*/

	error=(session->status.error==0) ? session->status.error : EIO;
	logoutput("ssh_userauth_none: error %i sending SSH_MSG_USERAUTH_REQUEST (%s)", error, strerror(error));
	userauth->error=error;
	userauth->status|=SSH_USERAUTH_STATUS_DISCONNECT;

    }

    finish:
    return result;

}
