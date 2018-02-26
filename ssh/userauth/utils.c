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

#include "ssh-receive.h"
#include "ssh-queue-rawdata.h"

#include "ssh-send.h"
#include "ssh-send-userauth.h"
#include "ssh-hostinfo.h"

#include "ssh-utils.h"
#include "ssh-pubkey-layout.h"

/*
    generic function to read the comma seperated name list of names of authentications that can continue
    used when processing the MSG_USERAUTH_FAILURE response
*/

unsigned int get_required_auth_methods(char *namelist, unsigned int len)
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

	methods|=SSH_USERAUTH_PUBLICKEY;

    } else if (strcmp(pos, "password")==0) {

	methods|=SSH_USERAUTH_PASSWORD;

    } else if (strcmp(pos, "hostbased")==0) {

	methods|=SSH_USERAUTH_HOSTBASED;

    } else {

	methods|=SSH_USERAUTH_UNKNOWN;

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

*/

int handle_userauth_failure(struct ssh_session_s *session, struct ssh_payload_s *payload, unsigned int *methods)
{
    unsigned int result=-1;
    unsigned int len=0;

    if (payload->len<6) return -1;

    len=get_uint32(&payload->buffer[1]);

    if (payload->len==6+len) {
	unsigned char partial_success=(unsigned char) payload->buffer[5+len];

	/* there is a byte for partial success */

	if (partial_success>0) {

	    /* success */

	    if (len>0) {

		*methods=get_required_auth_methods(&payload->buffer[5], len);
		result=0;

	    } else {

		/* partial success and no additional methods is an error
		    there should be send a MSG_USERAUTH_SUCCESS in stead of an MSG_USERAUTH_FAILURE */

		result=-1;

	    }

	} else {

	    /* failed */

	    if (len>0) *methods=get_required_auth_methods(&payload->buffer[5], len);
	    result=-1;

	}

    } else {

	session->userauth.status|=SESSION_USERAUTH_STATUS_ERROR;

    }

    return result;

}

int read_public_key_helper(struct common_identity_s *identity, struct ssh_key_s *key)
{
    unsigned int error=0;
    unsigned int len=get_public_key(identity, NULL, 0);
    char buffer[len];
    struct common_buffer_s data;

    if (len==0) {

	logoutput("read_public_key_helper: error %i reading public key (%s)", error, strerror(error));
	return -1;

    }

    /* use a buffer to read and process the raw key material */

    init_common_buffer(&data);
    data.ptr=buffer;
    data.size=len;
    data.len=len;
    data.pos=data.ptr;

    if (get_public_key(identity, buffer, len)==0) {

	logoutput("read_public_key_helper: error %i reading public key (%s)", error, strerror(error));
	return -1;

    }

    /* read the raw data and get the ssh key
	TODO: add more layouts */

    if (_read_public_key_openssh(&data, key)==-1) {

	logoutput("read_public_key_helper: error reading public key");
	return -1;

    }

    return 0;

}

int read_private_key_helper(struct common_identity_s *identity, struct ssh_key_s *key)
{
    unsigned int error=0;
    unsigned int len=get_private_key(identity, NULL, 0);
    char buffer[len];
    struct common_buffer_s data;

    if (len==0) {

	logoutput("read_private_key_helper: error %i reading public key (%s)", error, strerror(error));
	return -1;

    }

    /* use a buffer to read and process the raw key material */

    init_common_buffer(&data);
    data.ptr=buffer;
    data.size=len;
    data.len=len;
    data.pos=data.ptr;

    if (get_private_key(identity, buffer, len)==0) {

	logoutput("read_private_key_helper: error %i reading public key (%s)", error, strerror(error));
	return -1;

    }

    /* read the raw data and get the ssh key
	TODO: add more layouts */

    if (_read_private_key_openssh(&data, key)==-1) {

	logoutput("read_public_key_helper: error reading public key");
	return -1;

    }

    return 0;

}
