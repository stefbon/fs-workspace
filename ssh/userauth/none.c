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

#include "ssh-receive.h"
#include "ssh-send.h"
#include "ssh-connections.h"

#include "ssh-utils.h"

#include "userauth/utils.h"

int send_auth_none(struct ssh_connection_s *connection, char *user, struct ssh_auth_s *auth)
{
    unsigned int error=0;
    unsigned int seq=0;
    int result=-1;

    /* get the list of authemtication 'method name' values
	see https://tools.ietf.org/html/rfc4252#section-5.2: The "none" Authentication Request
    */

    logoutput("send_auth_none: send none userauth request");

    if (send_userauth_none_message(connection, user, "ssh-connection", &seq)==0) {
	struct ssh_payload_s *payload=NULL;

	payload=receive_message_common(connection, handle_auth_reply, &error);
	if (payload==NULL) goto finish;

	if (payload->type == SSH_MSG_USERAUTH_SUCCESS) {

	    /* huhh?? which server allows this weak security? */
	    logoutput("send_auth_none: server accepted none.....");
	    result=0;

	} else if (payload->type == SSH_MSG_USERAUTH_FAILURE) {

	    /* result will always be -1 since "none" will result in success
		override this */
	    handle_auth_failure(payload, auth);
	    result=0;

	} else {

	    logoutput("send_userauth_none: got unexpected reply %i", payload->type);
	    goto finish;

	}

	if (payload) free_payload(&payload);

    } else {

	/* why send error ?*/

	error=EIO;
	logoutput("send_userauth_none: error %i sending SSH_MSG_USERAUTH_REQUEST (%s)", error, strerror(error));

    }

    finish:
    return result;

}
