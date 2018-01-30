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
#include "ssh-utils.h"
#include "ssh-send.h"
#include "ssh-pubkey-utils.h"

/*
    take care for userauth for this client
    since this is a fuse fs, the only acceptable methods are
    publickey and hostbased, where publickey is required

    password is not possible since there is no easy method
    available from the fuse fs to provide a user interface
    (maybe kerberos using the ticket is possible)

*/

/*
    send a public key auth request (RFC4252 7. Public Key Authentication Method: "publickey")

    - byte 	SSH_MSG_USERAUTH_REQUEST
    - string	username
    - string	service name
    - string	"publickey"
    - boolean	FALSE or TRUE: true when signature is defined
    - string	public key algorithm name (ssh-rsa, ssh-dss)
    - string	public key
    - string	signature

    signature is as follows:

    - uint32	length of total signature packet
    - uint32	length name signature algorithm name
    - byte[]	name algorithm
    - uint32	length signature blob
    - byte[]	signature blob
*/

struct userauth_pubkey_s {
    struct ssh_string_s		*user;
    const char			*service;
    struct ssh_key_s		*public_key;
    struct ssh_string_s 	*signature;
};

static unsigned int _write_userauth_pubkey_message(struct common_buffer_s *tmp, void *ptr)
{
    struct userauth_pubkey_s *userauth=(struct userauth_pubkey_s *) ptr;
    unsigned int len=0;

    len+=copy_byte_to_buffer(tmp, SSH_MSG_USERAUTH_REQUEST);

    /* user */
    len+=copy_ssh_string_to_buffer(tmp, userauth->user);

    /* service */
    len+=copy_char_to_buffer(tmp, (char *) userauth->service, strlen(userauth->service));

    /* method "publickey" */
    len+=copy_char_to_buffer(tmp, (char *) "publickey", 9);

    /* signature included? */
    len+=copy_byte_to_buffer(tmp, (userauth->signature) ? 1 : 0);

    /* pubkey algo name */
    len+=copy_ssh_pk_algo_to_buffer(tmp, userauth->public_key->type);

    /* pubkey */
    len+=copy_buffer_to_buffer(tmp, &userauth->public_key->data);

    /* copy signature --only-- when signature->ptr is defined */

    if (userauth->signature) {

	if (userauth->signature->ptr) {

	    len += copy_ssh_pk_signature_to_buffer(tmp, userauth->public_key->type, userauth->signature);

	}

    }

    return len;

}

static int _send_userauth_pubkey_message(struct ssh_session_s *session, struct ssh_payload_s *payload, void *ptr)
{
    struct common_buffer_s tmp;

    init_common_buffer(&tmp);

    if (payload) {

	tmp.ptr=(char *) payload->buffer;
	tmp.size=payload->len;

    }

    tmp.pos=tmp.ptr;
    tmp.len=0;

    return _write_userauth_pubkey_message(&tmp, ptr);

}

/* write the userauth request message to a buffer
    used for the creating of a signature with public key auth */

unsigned int write_userauth_pubkey_request(struct common_buffer_s *buffer, struct ssh_string_s *user, const char *service, struct ssh_key_s *public_key)
{
    struct userauth_pubkey_s userauth;
    struct ssh_string_s signature;

    userauth.user=user;
    userauth.service=service;
    userauth.public_key=public_key;
    userauth.signature=&signature;

    signature.ptr=NULL;
    signature.len=0;

    return _write_userauth_pubkey_message(buffer, (void *) &userauth);

}

int send_userauth_pubkey_message(struct ssh_session_s *session, struct ssh_string_s *user, const char *service, struct ssh_key_s *public_key, struct ssh_string_s *signature, unsigned int *seq)
{
    struct userauth_pubkey_s userauth_pubkey;

    userauth_pubkey.user=user;
    userauth_pubkey.service=service;
    userauth_pubkey.public_key=public_key;
    userauth_pubkey.signature=signature;

    if (send_ssh_message(session, _send_userauth_pubkey_message, (void *) &userauth_pubkey, seq)==-1) {
    	unsigned int error=session->status.error;

	session->status.error=0;

	logoutput("send_userauth_pubkey_message: error %i:%s", error, strerror(error));
	return -1;

    }

    return 0;

}

struct userauth_none_s {
    struct ssh_string_s		*user;
    const char			*service;
};

static int _send_userauth_none_message(struct ssh_session_s *session, struct ssh_payload_s *payload, void *ptr)
{
    struct userauth_none_s *userauth=(struct userauth_none_s *) ptr;
    unsigned int len=0;
    struct common_buffer_s tmp;

    init_common_buffer(&tmp);

    if (payload) {

	tmp.ptr=(char *) payload->buffer;
	tmp.size=payload->len;

    }

    tmp.pos=tmp.ptr;
    tmp.len=0;

    len+=copy_byte_to_buffer(&tmp, SSH_MSG_USERAUTH_REQUEST);

    /* user */
    len+=copy_ssh_string_to_buffer(&tmp, userauth->user);

    /* service string */
    len+=copy_char_to_buffer(&tmp, (char *)userauth->service, strlen(userauth->service));

    /* method "none" */
    len+=copy_char_to_buffer(&tmp, "none", 4);

    return len;

}

int send_userauth_none_message(struct ssh_session_s *session, struct ssh_string_s *user, const char *service, unsigned int *seq)
{
    struct userauth_none_s userauth_none;

    userauth_none.user=user;
    userauth_none.service=service;

    if (send_ssh_message(session, _send_userauth_none_message, (void *) &userauth_none, seq)==-1) {
	unsigned int error=session->status.error;

	session->status.error=0;

	logoutput("send_userauth_none_message: error %i:%s", error, strerror(error));
	return -1;

    }

    return 0;

}

/*
    send a hostbased auth request (RFC4252 9. Host-Based Authentication Method: "hostbased")

    - byte 	SSH_MSG_USERAUTH_REQUEST
    - string	username used to connect
    - string	service name
    - string	"hostbased"
    - string	public key algorithm name (ssh-rsa, ssh-dss, ...)
    - string	public host key client host
    - string	client hostname
    - string	local username
    - string	signature
*/

struct userauth_hostbased_s {
    struct ssh_string_s		*r_user;
    const char			*service;
    struct ssh_key_s		*hostkey;
    struct ssh_string_s		*hostname;
    struct ssh_string_s		*l_user;
    struct ssh_string_s 	*signature;
};

static unsigned int _write_userauth_hostbased_message(struct common_buffer_s *tmp, void *ptr)
{
    struct userauth_hostbased_s *userauth=(struct userauth_hostbased_s *) ptr;
    unsigned int len=0;

    len+=copy_byte_to_buffer(tmp, SSH_MSG_USERAUTH_REQUEST);

    /* remote user */
    len+=copy_ssh_string_to_buffer(tmp, userauth->r_user);

    /* service */
    len+=copy_char_to_buffer(tmp, (char *)userauth->service, strlen(userauth->service));

    /* method "hostbased" */
    len+=copy_char_to_buffer(tmp, (char *)"hostbased", 9);

    /* pubkey algo name client public hostkey */
    len+=copy_ssh_pk_algo_to_buffer(tmp, userauth->hostkey->type);

    /* client public hostkey */
    len+=copy_buffer_to_buffer(tmp, &userauth->hostkey->data);

    /* client hostname */
    len+=copy_ssh_string_to_buffer(tmp, userauth->hostname);

    /* local user */
    len+=copy_ssh_string_to_buffer(tmp, userauth->l_user);

    if (userauth->signature) {

	len+=copy_ssh_pk_signature_to_buffer(tmp, userauth->hostkey->type, userauth->signature);

    }

    return len;

}

static int _send_userauth_hostbased_message(struct ssh_session_s *session, struct ssh_payload_s *payload, void *ptr)
{
    struct common_buffer_s tmp;

    init_common_buffer(&tmp);

    if (payload) {

	tmp.ptr=(char *) payload->buffer;
	tmp.size=payload->len;

    }

    tmp.pos=tmp.ptr;
    tmp.len=0;

    return _write_userauth_hostbased_message(&tmp, ptr);
}

unsigned int write_userauth_hostbased_request(struct common_buffer_s *buffer, struct ssh_string_s *r_user, const char *service, struct ssh_key_s *hostkey, struct ssh_string_s *hostname, struct ssh_string_s *l_user)
{
    struct userauth_hostbased_s userauth;

    memset(&userauth, 0, sizeof(struct userauth_hostbased_s));

    userauth.r_user=r_user;
    userauth.service=service;
    userauth.hostkey=hostkey;
    userauth.hostname=hostname;
    userauth.l_user=l_user;
    userauth.signature=NULL;

    return _write_userauth_hostbased_message(buffer, (void *) &userauth);

}

int send_userauth_hostbased_message(struct ssh_session_s *session, struct ssh_string_s *r_user, const char *service, struct ssh_key_s *hostkey, struct ssh_string_s *hostname, struct ssh_string_s *l_user, struct ssh_string_s *signature, unsigned int *seq)
{
    struct userauth_hostbased_s userauth;

    memset(&userauth, 0, sizeof(struct userauth_hostbased_s));

    userauth.r_user=r_user;
    userauth.service=service;
    userauth.hostkey=hostkey;
    userauth.hostname=hostname;
    userauth.l_user=l_user;
    userauth.signature=signature;

    if (send_ssh_message(session, _send_userauth_hostbased_message, (void *) &userauth, seq)==-1) {
	unsigned int error=session->status.error;

	session->status.error=0;

	logoutput("send_userauth_hostbased_message: error %i:%s", error, strerror(error));
	return -1;

    }

    return 0;

}
