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

#include "logging.h"
#include "main.h"
#include "beventloop.h"
#include "workerthreads.h"

#include "utils.h"

#include "ssh-common.h"
#include "ssh-common-protocol.h"

#include "ssh-receive.h"
#include "ssh-receive-waitreply.h"

#include "ssh-utils.h"

/*
    handlers for receiving ssh messages:

    - SSH_MSG_USERAUTH_REQUEST
    - SSH_MSG_USERAUTH_FAILURE
    - SSH_MSG_USERAUTH_SUCCESS
    - SSH_MSG_USERAUTH_BANNER

    - SSH_MSG_USERAUTH_PK_OK
    - SSH_MSG_USERAUTH_PASSWD_CHANGEREQ
    - SSH_MSG_USERAUTH_INFO_REQUEST
    - SSH_MSG_USERAUTH_INFO_RESPONSE

*/

static void receive_msg_userauth_failure(struct ssh_session_s *session, struct ssh_payload_s *payload)
{

    /* TODO */

    free(payload);
}

static void receive_msg_userauth_success(struct ssh_session_s *session, struct ssh_payload_s *payload)
{

    /*
	message looks like:
	- byte			SSH_MSG_USERAUTH_SUCCESS
    */

    /* TODO */

    free(payload);
}

static void receive_msg_userauth_pk_ok(struct ssh_session_s *session, struct ssh_payload_s *payload)
{

    /*
	after receiving this reply "the client MAY then send a signature generated using the private key."
	(RFC4252 7.  Public Key Authentication Method: "publickey")
	so the client can leave it here ??
    */

    /*
	message has the form:
	- byte			SSH_MSG_USERAUTH_PK_OK
	- string		algo name
	- string		public key
    */

    /* TODO */

    free(payload);

}

/* banner message
    see: https://tools.ietf.org/html/rfc4252#section-5.4 Banner Message
    This software is running in background, so the message cannot be displayed on screen...
    log it anyway (ignore message)

    message looks like:
    - byte			SSH_MSG_USERAUTH_BANNER
    - string			message in ISO-10646 UTF-8 encoding
    - string			language tag
    */

static void receive_msg_userauth_banner(struct ssh_session_s *session, struct ssh_payload_s *payload)
{
    if (payload->len>9) {
	unsigned int len=get_uint32(&payload->buffer[1]);

	if (payload->len>=9+len) {
	    char banner[len+1];

	    memcpy(banner, &payload->buffer[5], len);
	    banner[len]='\0';

	    logoutput("receive_msg_userauth_banner: received banner %s", banner);

	}

    }

    free(payload);

}

void register_userauth_cb()
{
    register_msg_cb(SSH_MSG_USERAUTH_FAILURE, receive_msg_userauth_failure);
    register_msg_cb(SSH_MSG_USERAUTH_SUCCESS, receive_msg_userauth_success);
    register_msg_cb(SSH_MSG_USERAUTH_BANNER, receive_msg_userauth_banner);
    register_msg_cb(SSH_MSG_USERAUTH_PK_OK, receive_msg_userauth_pk_ok);
}
