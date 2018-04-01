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
#include "pk/pk-types.h"

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

struct userauth_helper_s {
    char			*r_user;
    const char			*service;
    struct ssh_key_s		*pkey;
    char			*l_hostname;
    char			*l_user;
    struct ssh_string_s 	*signature;
};

static unsigned int _write_userauth_pubkey_message(char *buffer, unsigned int size, void *ptr)
{
    struct userauth_helper_s *userauth=(struct userauth_helper_s *) ptr;

    if (buffer==NULL) {
	unsigned int len=32;
	unsigned int error=0;
	struct ssh_string_s *sign=userauth->signature;

	len+=1;
	len+=write_ssh_string(NULL, 0, 'c', (void *) userauth->r_user);
	len+=write_ssh_string(NULL, 0, 'c', (void *) userauth->service);
	len+=write_ssh_string(NULL, 0, 'c', (void *) "publickey");
	len+=1;
	len+=write_pkalgo(NULL, userauth->pkey->algo); /* TODO: use signature algo */
	len+=(* userauth->pkey->write_key)(userauth->pkey, NULL, 0, PK_DATA_FORMAT_SSH_STRING, &error);

	if (sign && sign->ptr) {

	    /* TODO: use signature algo */
	    len+=4 + write_pkalgo(NULL, userauth->pkey->algo) + write_ssh_string(NULL, 0, 's', (void *)sign);

	}

	return len;

    } else {
	unsigned int error = 0;
	struct ssh_string_s *sign=userauth->signature;
	char *pos=buffer;
	unsigned int result=0;
	int left=(int) size;

	*pos=SSH_MSG_USERAUTH_REQUEST;
	pos++;
	left--;

	result=write_ssh_string(pos, left, 'c', (void *) userauth->r_user);
	pos+=result;
	left-=result;

	result=write_ssh_string(pos, left, 'c', (void *) userauth->service);
	pos+=result;
	left-=result;

	result=write_ssh_string(pos, left, 'c', (void *) "publickey");
	pos+=result;
	left-=result;

	*pos=(sign) ? 1 : 0;
	pos++;
	left--;

	result=write_pkalgo(pos, userauth->pkey->algo); /* TODO: use signature algo */
	pos+=result;
	left-=result;

	result=(* userauth->pkey->write_key)(userauth->pkey, pos, left, PK_DATA_FORMAT_SSH_STRING, &error);
	pos+=result;
	left-=result;

	if (sign && sign->ptr) {
	    char *start=pos;

	    pos+=4;

	    result=write_pkalgo(pos, userauth->pkey->algo);
	    pos+=result;
	    left-=result;

	    result=write_ssh_string(pos, left, 's', (void *)sign);
	    pos+=result;
	    left-=result;

	    store_uint32(start, (unsigned int)(pos - (start + 4)));

	}

	log_message((unsigned char*) buffer, (unsigned int)(pos - buffer), userauth->pkey->algo->name, 0);

	return (unsigned int)(pos - buffer);

    }

    return 0;

}

static int _send_userauth_pubkey_message(struct ssh_session_s *session, struct ssh_payload_s *payload, void *ptr)
{
    char *buffer = NULL;
    unsigned int size = 0;

    if (payload) {

	buffer=(char *) payload->buffer;
	size=payload->len;

    }

    return _write_userauth_pubkey_message(buffer, size, ptr);

}

/* write the userauth request message to a buffer
    used for the creating of a signature with public key auth */

unsigned int write_userauth_pubkey_request(char *buffer, unsigned int size, char *r_user, const char *service, struct ssh_key_s *pkey)
{
    struct userauth_helper_s userauth;
    struct ssh_string_s signature;

    memset(&userauth, 0, sizeof(struct userauth_helper_s));

    signature.ptr=NULL;
    signature.len=0;

    userauth.r_user=r_user;
    userauth.service=service;
    userauth.pkey=pkey;
    userauth.l_hostname=NULL;
    userauth.l_user=NULL;
    userauth.signature=&signature;

    return _write_userauth_pubkey_message(buffer, size, (void *) &userauth);

}

int send_userauth_pubkey_message(struct ssh_session_s *session, char *r_user, const char *service, struct ssh_key_s *pkey, struct ssh_string_s *signature, unsigned int *seq)
{
    struct userauth_helper_s userauth;

    memset(&userauth, 0, sizeof(struct userauth_helper_s));

    userauth.r_user=r_user;
    userauth.service=service;
    userauth.pkey=pkey;
    userauth.signature=signature;

    if (send_ssh_message(session, _send_userauth_pubkey_message, (void *) &userauth, seq)==-1) {
    	unsigned int error=session->status.error;

	session->status.error=0;

	logoutput("send_userauth_pubkey_message: error %i:%s", error, strerror(error));
	return -1;

    }

    return 0;

}

static int _send_userauth_none_message(struct ssh_session_s *session, struct ssh_payload_s *payload, void *ptr)
{
    struct userauth_helper_s *userauth=(struct userauth_helper_s *) ptr;

    if (payload==NULL) {
	unsigned int len=0;

	len+=1;
	len+=write_ssh_string(NULL, 0, 'c', (void *) userauth->r_user);
	len+=write_ssh_string(NULL, 0, 'c', (void *) userauth->service);
	len+=write_ssh_string(NULL, 0, 'c', (void *) "none");

	return len;

    } else {
	char *pos = payload->buffer;
	int left = payload->len;
	unsigned int result=0;

	*pos=SSH_MSG_USERAUTH_REQUEST;
	pos++;
	left--;

	result+=write_ssh_string(pos, left, 'c', (void *) userauth->r_user);
	pos+=result;
	left-=result;

	result+=write_ssh_string(pos, left, 'c', (void *) userauth->service);
	pos+=result;
	left-=result;

	result+=write_ssh_string(pos, left, 'c', (void *) "none");
	pos+=result;
	left-=result;

	return (unsigned int)(pos - payload->buffer);

    }

    return 0;

}

int send_userauth_none_message(struct ssh_session_s *session, char *r_user, const char *service, unsigned int *seq)
{
    struct userauth_helper_s userauth;

    memset(&userauth, 0, sizeof(struct userauth_helper_s));

    userauth.r_user=r_user;
    userauth.service=service;

    if (send_ssh_message(session, _send_userauth_none_message, (void *) &userauth, seq)==-1) {
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

static unsigned int _write_userauth_hostbased_message(char *buffer, unsigned int size, void *ptr)
{
    struct userauth_helper_s *userauth=(struct userauth_helper_s *) ptr;

    if (buffer==NULL) {
	unsigned int len=0;
	unsigned int error=0;
	struct ssh_string_s *sign=userauth->signature;

	len+=1;
	len+=write_ssh_string(NULL, 0, 'c', (void *) userauth->r_user);
	len+=write_ssh_string(NULL, 0, 'c', (void *) userauth->service);
	len+=write_ssh_string(NULL, 0, 'c', (void *) "hostbased");
	len+=write_pkalgo(NULL, userauth->pkey->algo); /* TODO: use signature algo */
	len+=(* userauth->pkey->write_key)(userauth->pkey, NULL, 0, PK_DATA_FORMAT_SSH_STRING, &error);
	len+=write_ssh_string(NULL, 0, 'c', (void *) userauth->l_hostname);
	len+=write_ssh_string(NULL, 0, 'c', (void *) userauth->l_user);

	if (sign && sign->ptr) {

	    /* TODO: use signature algo */
	    len+=4 + write_pkalgo(NULL, userauth->pkey->algo) + write_ssh_string(NULL, 0, 's', (void *)sign);

	}

	return len;

    } else {
	unsigned int error=0;
	struct ssh_string_s *sign=userauth->signature;
	char *pos = buffer;
	unsigned int result=0;
	int left = (int) size;

	*pos = SSH_MSG_USERAUTH_REQUEST;
	pos++;
	left--;

	result = write_ssh_string(pos, left, 'c', (void *) userauth->r_user);
	pos += result;
	left -= result;

	result = write_ssh_string(pos, left, 'c', (void *) userauth->service);
	pos+=result;
	left-=result;

	result = write_ssh_string(pos, left, 'c', (void *) "hostbased");
	pos+=result;
	left-=result;

	result=write_pkalgo(pos, userauth->pkey->algo); /* TODO: use signature algo */
	pos+=result;
	left-=result;

	result=(* userauth->pkey->write_key)(userauth->pkey, pos, left, PK_DATA_FORMAT_SSH_STRING, &error);
	pos+=result;
	left-=result;

	result = write_ssh_string(pos, left, 'c', (void *) userauth->l_hostname);
	pos+=result;
	left-=result;

	result = write_ssh_string(pos, left, 'c', (void *) userauth->l_user);
	pos+=result;
	left-=result;

	if (sign && sign->ptr) {
	    char *start=pos;

	    pos+=4;

	    result=write_pkalgo(pos, userauth->pkey->algo);
	    pos+=result;
	    left-=result;

	    result=write_ssh_string(pos, left, 's', (void *)sign);
	    pos+=result;
	    left-=result;

	    store_uint32(start, (unsigned int)(pos - (start + 4)));

	}

	return (unsigned int)(pos - buffer);

    }

    return 0;

}

static int _send_userauth_hostbased_message(struct ssh_session_s *session, struct ssh_payload_s *payload, void *ptr)
{
    char *buffer=NULL;
    unsigned int size=0;

    if (payload) {

	buffer=(char *) payload->buffer;
	size=payload->len;

    }

    return _write_userauth_hostbased_message(buffer, size, ptr);
}

unsigned int write_userauth_hostbased_request(char *buffer, unsigned int size, char *r_user, const char *service, struct ssh_key_s *pkey, char *l_hostname, char *l_user)
{
    struct userauth_helper_s userauth;

    memset(&userauth, 0, sizeof(struct userauth_helper_s));

    userauth.r_user=r_user;
    userauth.service=service;
    userauth.pkey=pkey;
    userauth.l_hostname=l_hostname;
    userauth.l_user=l_user;
    userauth.signature=NULL;

    return _write_userauth_hostbased_message(buffer, size, (void *) &userauth);

}

int send_userauth_hostbased_message(struct ssh_session_s *session, char *r_user, const char *service, struct ssh_key_s *pkey, char *l_hostname, char *l_user, struct ssh_string_s *signature, unsigned int *seq)
{
    struct userauth_helper_s userauth;

    memset(&userauth, 0, sizeof(struct userauth_helper_s));

    userauth.r_user=r_user;
    userauth.service=service;
    userauth.pkey=pkey;
    userauth.l_hostname=l_hostname;
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
