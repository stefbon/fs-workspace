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

#include "ssh-receive.h"
#include "ssh-send.h"
#include "ssh-hostinfo.h"
#include "ssh-utils.h"

/*
    generic function to read the comma seperated name list of names of authentications that can continue
    used when processing the MSG_USERAUTH_FAILURE response
*/

static unsigned int get_required_auth_methods(char *namelist, unsigned int len)
{
    unsigned int methods=0;
    char list[len+1];
    char *pos=&list[0];
    char *sep=NULL;

    memcpy(list, namelist, len);
    list[len]='\0';

    logoutput("get_required_auth_methods: %s", list);

    findmethod:

    sep=strchr(pos, ',');
    if (sep) *sep='\0';

    if (strcmp(pos, "publickey")==0) {

	methods|=SSH_USERAUTH_METHOD_PUBLICKEY;

    } else if (strcmp(pos, "password")==0) {

	methods|=SSH_USERAUTH_METHOD_PASSWORD;

    } else if (strcmp(pos, "hostbased")==0) {

	methods|=SSH_USERAUTH_METHOD_HOSTBASED;

    } else {

	methods|=SSH_USERAUTH_METHOD_UNKNOWN;

    }

    if (sep) {

	*sep=',';
	pos=sep+1;
	goto findmethod;

    }

    return methods;

}

/* generic function to handle the userauth failure response
    see: https://tools.ietf.org/html/rfc4252#section-5.1 Responses to Authentication Request

    message looks like:
    - byte			SSH_MSG_USERAUTH_FAILURE
    - name-list			authentications that can continue
    - boolean			partial success

    NOTE:
    if partial success is false then the userauth method offered has failed
*/

int handle_userauth_failure(struct ssh_session_s *session, struct ssh_payload_s *payload, struct ssh_userauth_s *userauth)
{
    unsigned int result=-1;

    if (payload->len>6) {
	unsigned int len=get_uint32(&payload->buffer[1]);

	if (len>0 && payload->len==6+len) {
	    unsigned char partial_success=(unsigned char) payload->buffer[5+len];

	    userauth->required_methods=get_required_auth_methods(&payload->buffer[5], len);
	    result=(partial_success>0) ? 0 : -1;

	}

    }

    logoutput("handle_userauth_failure: result %i", result);

    return result;

}
