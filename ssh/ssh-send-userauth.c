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

static int _write_userauth_pubkey_message(char *buffer, unsigned int size, void *ptr)
{
    struct userauth_pubkey_s *userauth=(struct userauth_pubkey_s *) ptr;

    if (buffer==NULL) {
	unsigned int lenservice=strlen(userauth->service);
	unsigned int lenmethod=strlen("publickey");
	const unsigned char *algo=get_pubkey_name(userauth->public_key->type);
	unsigned int len=0;

	len += 1; /* type byte */
	len += 4 + userauth->user->len;
	len += 4 + lenservice;
	len += 4 + lenmethod;
	len += 1;
	len += 4 + strlen((char *)algo);
	len += 4 + userauth->public_key->data.len;

	if (userauth->signature) {

	    if (userauth->signature->ptr) {

		len += 4 + 4 + strlen((char *)algo) + 4 + userauth->signature->len;

	    }

	}

	return len;

    } else {
	char *pos=buffer;
	const unsigned char *algo=get_pubkey_name(userauth->public_key->type);
	unsigned int lenservice=strlen(userauth->service);
	unsigned int lenmethod=strlen("publickey");
	unsigned int lenalgo=strlen((char *) algo);

	*pos=(unsigned char) SSH_MSG_USERAUTH_REQUEST;
	pos++;

	/* user string */

	store_uint32(pos, userauth->user->len);
	pos+=4;

	memcpy(pos, userauth->user->ptr, userauth->user->len);
	pos+=userauth->user->len;

	/* service string */

	store_uint32(pos, lenservice);
	pos+=4;

	memcpy(pos, userauth->service, lenservice);
	pos+=lenservice;

	/* method "publickey" string */

	store_uint32(pos, lenmethod);
	pos+=4;

	memcpy(pos, "publickey", lenmethod);
	pos+=lenmethod;

	if (userauth->signature) {

	    *pos=1;

	} else {

	    /* boolean FALSE */

	    *pos=0;

	}

	pos++;

	/* pubkey algo name */

	store_uint32(pos, lenalgo);
	pos+=4;

	memcpy(pos, algo, lenalgo);
	pos+=lenalgo;

	/* pubkey */

	store_uint32(pos, userauth->public_key->data.size);
	pos+=4;

	memcpy(pos, userauth->public_key->data.ptr, userauth->public_key->data.size);
	pos+=userauth->public_key->data.size;

	/* copy signature --only-- when signature->ptr is defined */

	if (userauth->signature) {

	    if (userauth->signature->ptr) {
		unsigned int len= 4 + lenalgo + 4 + userauth->signature->len;

		store_uint32(pos, len);
		pos+=4;

		store_uint32(pos, lenalgo);
		pos+=4;

		memcpy(pos, algo, lenalgo);
		pos+=lenalgo;

		/* signature hasn't already a 4-bytes header for length */

		store_uint32(pos, userauth->signature->len);
		pos+=4;

		memcpy(pos, userauth->signature->ptr, userauth->signature->len);
		pos+=userauth->signature->len;

	    }

	}

	return (unsigned int)(pos - buffer);

    }

    return 0;

}

static int _send_userauth_pubkey_message(struct ssh_session_s *session, struct ssh_payload_s *payload, void *ptr)
{
    if (! payload) return _write_userauth_pubkey_message(NULL, 0, ptr);
    return _write_userauth_pubkey_message((char *)payload->buffer, payload->len, ptr);
}

/* write the userauth request message to a buffer
    used for the creating of a signature with public key auth */

unsigned int write_userauth_pubkey_request(char *buffer, unsigned int size, struct ssh_string_s *user, const char *service, struct ssh_key_s *public_key)
{
    struct userauth_pubkey_s userauth;
    struct ssh_string_s signature;

    userauth.user=user;
    userauth.service=service;
    userauth.public_key=public_key;
    userauth.signature=&signature;

    signature.ptr=NULL;
    signature.len=0;

    return _write_userauth_pubkey_message(buffer, size, (void *) &userauth);

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

    if (payload==NULL) {
	unsigned int lenservice=strlen(userauth->service);
	unsigned int lenmethod=strlen("none");
	unsigned int len=0;

	len += 1; /* type byte */
	len += 4 + userauth->user->len;
	len += 4 + lenservice;
	len += 4 + lenmethod;
	return len;

    } else {
	char *pos=payload->buffer;
	unsigned int lenservice=strlen(userauth->service);
	unsigned int lenmethod=strlen("none");

	*pos=(unsigned char) SSH_MSG_USERAUTH_REQUEST;
	pos++;

	/* user string */

	store_uint32(pos, userauth->user->len);
	pos+=4;

	memcpy(pos, userauth->user->ptr, userauth->user->len);
	pos+=userauth->user->len;

	/* service string */

	store_uint32(pos, lenservice);
	pos+=4;

	memcpy(pos, userauth->service, lenservice);
	pos+=lenservice;

	/* method "none" string */

	store_uint32(pos, lenmethod);
	pos+=4;

	memcpy(pos, "none", lenmethod);
	pos+=lenmethod;

	return (unsigned int)(pos - payload->buffer);

    }

    return 0;

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
    struct ssh_string_s		*remote_user;
    const char			*service;
    struct ssh_key_s		*hostkey;
    struct ssh_string_s		*hostname;
    struct ssh_string_s		*local_user;
    struct ssh_string_s 	*signature;
};

static int _write_userauth_hostbased_message(char *buffer, unsigned int size, void *ptr)
{
    struct userauth_hostbased_s *userauth=(struct userauth_hostbased_s *) ptr;

    if (buffer==NULL) {
	unsigned int lenservice=strlen(userauth->service);
	unsigned int lenmethod=strlen("hostbased");
	const unsigned char *algo=get_pubkey_name(userauth->hostkey->type);
	unsigned int len=0;

	len += 1; /* type byte */
	len += 4 + userauth->remote_user->len;
	len += 4 + lenservice;
	len += 4 + lenmethod;
	len += 4 + strlen((char *)algo);
	len += 4 + userauth->hostkey->data.len;
	len += 4 + userauth->hostname->len;
	len += 4 + userauth->local_user->len;

	if (userauth->signature) {

	    len += 4 + 4 + strlen((char *)algo) + 4 + userauth->signature->len;

	}

	return len;

    } else {
	char *pos=buffer;
	const unsigned char *algo=get_pubkey_name(userauth->hostkey->type);
	unsigned int lenservice=strlen(userauth->service);
	unsigned int lenmethod=strlen("hostbased");
	unsigned int lenalgo=strlen((char *) algo);

	*pos=(unsigned char) SSH_MSG_USERAUTH_REQUEST;
	pos++;

	/* remote user string */

	store_uint32(pos, userauth->remote_user->len);
	pos+=4;
	memcpy(pos, userauth->remote_user->ptr, userauth->remote_user->len);
	pos+=userauth->remote_user->len;

	/* service string */

	store_uint32(pos, lenservice);
	pos+=4;
	memcpy(pos, userauth->service, lenservice);
	pos+=lenservice;

	/* method "hostbased" string */

	store_uint32(pos, lenmethod);
	pos+=4;
	memcpy(pos, "hostbased", lenmethod);
	pos+=lenmethod;

	/* pubkey algo name string */

	store_uint32(pos, lenalgo);
	pos+=4;
	memcpy(pos, algo, lenalgo);
	pos+=lenalgo;

	/* pubkey string */

	store_uint32(pos, userauth->hostkey->data.size);
	pos+=4;
	memcpy(pos, userauth->hostkey->data.ptr, userauth->hostkey->data.size);
	pos+=userauth->hostkey->data.size;

	/* hostname string */

	store_uint32(pos, userauth->hostname->len);
	pos+=4;
	memcpy(pos, userauth->hostname->ptr, userauth->hostname->len);
	pos+=userauth->hostname->len;

	/* local user string */

	store_uint32(pos, userauth->local_user->len);
	pos+=4;
	memcpy(pos, userauth->local_user->ptr, userauth->local_user->len);
	pos+=userauth->local_user->len;

	if (userauth->signature) {
	    unsigned int len= 4 + lenalgo + 4 + userauth->signature->len;

	    /* total length of signature */

	    store_uint32(pos, len);
	    pos+=4;

	    /* string of format hostkey identifier */

	    store_uint32(pos, lenalgo);
	    pos+=4;

	    memcpy(pos, algo, lenalgo);
	    pos+=lenalgo;

	    /* signature */

	    store_uint32(pos, userauth->signature->len);
	    pos+=4;

	    memcpy(pos, userauth->signature->ptr, userauth->signature->len);
	    pos+=userauth->signature->len;

	}

	return (unsigned int)(pos - buffer);

    }

    return 0;

}

static int _send_userauth_hostbased_message(struct ssh_session_s *session, struct ssh_payload_s *payload, void *ptr)
{
    if (! payload) return _write_userauth_hostbased_message(NULL, 0, ptr);
    return _write_userauth_hostbased_message(payload->buffer, payload->len, ptr);
}

unsigned int write_userauth_hostbased_request(char *buffer, unsigned int size, struct ssh_string_s *remote_user, const char *service, struct ssh_key_s *hostkey, struct ssh_string_s *hostname, struct ssh_string_s *local_user)
{
    struct userauth_hostbased_s userauth;

    memset(&userauth, 0, sizeof(struct userauth_hostbased_s));

    userauth.remote_user=remote_user;
    userauth.service=service;
    userauth.hostkey=hostkey;
    userauth.hostname=hostname;
    userauth.local_user=local_user;
    userauth.signature=NULL;

    return _write_userauth_hostbased_message(buffer, size, (void *) &userauth);

}

int send_userauth_hostbased_message(struct ssh_session_s *session, struct ssh_string_s *remote_user, const char *service, struct ssh_key_s *hostkey, struct ssh_string_s *hostname, struct ssh_string_s *local_user, struct ssh_string_s *signature, unsigned int *seq)
{
    struct userauth_hostbased_s userauth;

    memset(&userauth, 0, sizeof(struct userauth_hostbased_s));

    userauth.remote_user=remote_user;
    userauth.service=service;
    userauth.hostkey=hostkey;
    userauth.hostname=hostname;
    userauth.local_user=local_user;
    userauth.signature=signature;

    if (send_ssh_message(session, _send_userauth_hostbased_message, (void *) &userauth, seq)==-1) {
	unsigned int error=session->status.error;

	session->status.error=0;

	logoutput("send_userauth_hostbased_message: error %i:%s", error, strerror(error));
	return -1;

    }

    return 0;

}
