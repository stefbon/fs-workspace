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

static void _msg_write_userauth_pubkey_message(struct msg_buffer_s *mb, char *r_user, const char *service, struct ssh_key_s *pkey, struct ssh_pksign_s *pksign, struct ssh_string_s *signature)
{
    msg_write_byte(mb, SSH_MSG_USERAUTH_REQUEST);
    msg_write_ssh_string(mb, 'c', (void *) r_user);
    msg_write_ssh_string(mb, 'c', (void *) service);
    msg_write_ssh_string(mb, 'c', (void *) "publickey");
    msg_write_byte(mb, (signature) ? 1 : 0);
    msg_write_pksign(mb, pksign);
    msg_write_pkey(mb, pkey, PK_DATA_FORMAT_SSH_STRING);
    msg_write_pksignature(mb, pksign, signature);
}

static unsigned int _write_userauth_pubkey_message(struct msg_buffer_s *mb, char *r_user, const char *service, struct ssh_key_s *pkey, struct ssh_pksign_s *pksign, struct ssh_string_s *signature)
{
    _msg_write_userauth_pubkey_message(mb, r_user, service, pkey, pksign, signature);
    return mb->pos;
}

/* write the userauth request message to a buffer
    used for the creating of a signature with public key auth */

void msg_write_userauth_pubkey_request(struct msg_buffer_s *mb, char *r_user, const char *service, struct ssh_key_s *pkey, struct ssh_pksign_s *pksign, struct ssh_string_s *signature)
{
    _msg_write_userauth_pubkey_message(mb, r_user, service, pkey, pksign, signature);
}

int send_userauth_pubkey_message(struct ssh_session_s *session, char *r_user, const char *service, struct ssh_key_s *pkey, struct ssh_pksign_s *pksign, struct ssh_string_s *signature, unsigned int *seq)
{
    struct msg_buffer_s mb=INIT_SSH_MSG_BUFFER;
    unsigned int len=_write_userauth_pubkey_message(&mb, r_user, service, pkey, pksign, signature) + 64;
    char buffer[sizeof(struct ssh_payload_s) + len];
    struct ssh_payload_s *payload=(struct ssh_payload_s *) buffer;

    init_ssh_payload(payload, len);
    payload->type=SSH_MSG_USERAUTH_REQUEST;
    set_msg_buffer_payload(&mb, payload);
    payload->len=_write_userauth_pubkey_message(&mb, r_user, service, pkey, pksign, signature);

    return write_ssh_packet(session, payload, seq);

}

/*
    send a hostbased auth request (RFC4252 5.2. The "none" Authentication Request)

    - byte 	SSH_MSG_USERAUTH_REQUEST
    - string	username used to connect
    - string	service name
    - string	"none"
*/


static void _msg_write_userauth_none_message(struct msg_buffer_s *mb, char *r_user, char *service)
{
    msg_write_byte(mb, SSH_MSG_USERAUTH_REQUEST);
    msg_write_ssh_string(mb, 'c', (void *) r_user);
    msg_write_ssh_string(mb, 'c', (void *) service);
    msg_write_ssh_string(mb, 'c', (void *) "none");
}

static unsigned int _write_userauth_none_message(struct msg_buffer_s *mb, char *r_user, char *service)
{
    _msg_write_userauth_none_message(mb, r_user, service);
    return mb->pos;
}

void msg_write_userauth_none_message(struct msg_buffer_s *mb, char *r_user, char *service)
{
    _msg_write_userauth_none_message(mb, r_user, service);
}

int send_userauth_none_message(struct ssh_session_s *session, char *r_user, const char *service, unsigned int *seq)
{
    struct msg_buffer_s mb=INIT_SSH_MSG_BUFFER;
    unsigned int len=_write_userauth_none_message(&mb, r_user, (char *) service);
    char buffer[sizeof(struct ssh_payload_s) + len];
    struct ssh_payload_s *payload=(struct ssh_payload_s *) buffer;

    init_ssh_payload(payload, len);
    payload->type=SSH_MSG_USERAUTH_REQUEST;
    set_msg_buffer_payload(&mb, payload);
    payload->len=_write_userauth_none_message(&mb, r_user, (char *) service);

    return write_ssh_packet(session, payload, seq);

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

static void _msg_write_userauth_hostbased_message(struct msg_buffer_s *mb, char *r_user, const char *service, struct ssh_key_s *pkey, char *l_hostname, char *l_user, struct ssh_string_s *signature)
{
    struct ssh_pksign_s *pksign=get_default_pksign(pkey->algo);

    msg_write_byte(mb, SSH_MSG_USERAUTH_REQUEST);
    msg_write_ssh_string(mb, 'c', (void *) r_user);
    msg_write_ssh_string(mb, 'c', (void *) service);
    msg_write_ssh_string(mb, 'c', (void *) "hostbased");
    msg_write_pksign(mb, pksign);
    msg_write_pkey(mb, pkey, PK_DATA_FORMAT_SSH_STRING);
    msg_write_ssh_string(mb, 'c', (void *) l_hostname);
    msg_write_ssh_string(mb, 'c', (void *) l_user);
    msg_write_pksignature(mb, pksign, signature);

}

static unsigned int _write_userauth_hostbased_message(struct msg_buffer_s *mb, char *r_user, const char *service, struct ssh_key_s *pkey, char *l_hostname, char *l_user, struct ssh_string_s *signature)
{
    _msg_write_userauth_hostbased_message(mb, r_user, service, pkey, l_hostname, l_user, signature);
    return mb->pos;
}

void msg_write_userauth_hostbased_request(struct msg_buffer_s *mb, char *r_user, const char *service, struct ssh_key_s *pkey, char *l_hostname, char *l_user)
{
    _msg_write_userauth_hostbased_message(mb, r_user, service, pkey, l_hostname, l_user, NULL);
}

int send_userauth_hostbased_message(struct ssh_session_s *session, char *r_user, const char *service, struct ssh_key_s *pkey, char *l_hostname, char *l_user, struct ssh_string_s *signature, unsigned int *seq)
{
    struct msg_buffer_s mb=INIT_SSH_MSG_BUFFER;
    unsigned int len=_write_userauth_hostbased_message(&mb, r_user, service, pkey, l_hostname, l_user, signature) + 64;
    char buffer[sizeof(struct ssh_payload_s) + len];
    struct ssh_payload_s *payload=(struct ssh_payload_s *) buffer;

    init_ssh_payload(payload, len);
    payload->type=SSH_MSG_USERAUTH_REQUEST;
    set_msg_buffer_payload(&mb, payload);
    payload->len=_write_userauth_hostbased_message(&mb, r_user, service, pkey, l_hostname, l_user, signature);

    return write_ssh_packet(session, payload, seq);

}

/*
    send a password auth request (RFC4252 8. Password Authentication Method: "password")

    - byte 	SSH_MSG_USERAUTH_REQUEST
    - string	username used to connect
    - string	service name
    - string	"password"
    - boolean	FALSE
    - string	plaintext password

*/

static void _msg_write_userauth_password_message(struct msg_buffer_s *mb, char *user, char *pw, const char *service)
{
    // logoutput("_msg_write_userauth_password_message");
    msg_write_byte(mb, SSH_MSG_USERAUTH_REQUEST);
    // logoutput("_msg_write_userauth_password_message: A1");
    msg_write_ssh_string(mb, 'c', (void *) user);
    // logoutput("_msg_write_userauth_password_message: A2");
    msg_write_ssh_string(mb, 'c', (void *) service);
    // logoutput("_msg_write_userauth_password_message: A3");
    msg_write_ssh_string(mb, 'c', (void *) "password");
    // logoutput("_msg_write_userauth_password_message: A4");
    msg_write_byte(mb, 0);
    // logoutput("_msg_write_userauth_password_message: A5");
    msg_write_ssh_string(mb, 'c', (void *) pw);
    // logoutput("_msg_write_userauth_password_message: A6");
}

static unsigned int _write_userauth_password_message(struct msg_buffer_s *mb, char *user, char *pw, const char *service)
{
    logoutput("_write_userauth_password_message: user %s pw %s", user, pw);
    _msg_write_userauth_password_message(mb, user, pw, service);
    return mb->pos;
}

int send_userauth_password_message(struct ssh_session_s *session, char *user, char *pw, const char *service, unsigned int *seq)
{
    struct msg_buffer_s mb=INIT_SSH_MSG_BUFFER;
    unsigned int len=_write_userauth_password_message(&mb, user, pw, service) + 64;
    char buffer[sizeof(struct ssh_payload_s) + len];
    struct ssh_payload_s *payload=(struct ssh_payload_s *) buffer;

    if (user==NULL || pw==NULL) {

	logoutput("send_userauth_password_message: user and/or pw NULL");
	return -1;

    }

    init_ssh_payload(payload, len);
    payload->type=SSH_MSG_USERAUTH_REQUEST;
    set_msg_buffer_payload(&mb, payload);
    payload->len=_write_userauth_password_message(&mb, user, pw, service);

    return write_ssh_packet(session, payload, seq);

}
