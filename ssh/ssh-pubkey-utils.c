/*
  2010, 2011, 2012, 2103, 2014, 2015, 2016, 2017 Stef Bon <stefbon@gmail.com>

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

#include "logging.h"
#include "main.h"
#include "utils.h"

#include "ssh-common.h"
#include "ssh-utils.h"

static const char *ssh_rsa_name="ssh-rsa";
static const char *ssh_dss_name="ssh-dss";
static const char *ssh_ed25519_name="ssh-ed25519";
static const char *ssh_unknown_name="";

/* translate the name of an pubkey algo into internal code */

unsigned char get_pubkey_type(unsigned char *algo, unsigned int len)
{

    if (len==strlen(ssh_dss_name) && strncmp((char *)algo, ssh_dss_name, len)==0) {

	return _PUBKEY_METHOD_SSH_DSS;

    } else if (len==strlen(ssh_rsa_name) && strncmp((char *)algo, ssh_rsa_name, len)==0) {

	return _PUBKEY_METHOD_SSH_RSA;

    } else if (len==strlen(ssh_ed25519_name) && strncmp((char *)algo, ssh_ed25519_name, len)==0) {

	return _PUBKEY_METHOD_SSH_ED25519;

    }

    return 0;
}

const unsigned char *get_pubkey_name(unsigned char type)
{

    if (type==_PUBKEY_METHOD_SSH_RSA) {

	return (unsigned char *)ssh_rsa_name;

    } else if (type==_PUBKEY_METHOD_SSH_DSS) {

	return (unsigned char *)ssh_dss_name;

    } else if (type==_PUBKEY_METHOD_SSH_ED25519) {

	return (unsigned char *)ssh_ed25519_name;

    }

    return (unsigned char *) ssh_unknown_name;

}

/* read the key type from a buffer
    very often in the communicatuion between server and client, but also with keys stored on disk (or another backend)
    the type of the key is part of the format. For example a public key looks like:
    ssh-rsa AAAA..... sbon@example
    this function reads this type and updates the pointer in the buffer
*/

unsigned int read_ssh_type_pubkey_buffer(struct common_buffer_s *message, unsigned char *type, unsigned int *error)
{
    unsigned int left=0;
    unsigned int len=0;

    left=(unsigned int) (message->ptr + message->len - message->pos);

    if (left>4) {

	len=get_uint32(message->pos);
	message->pos+=4;
	left-=4;

    } else {

	*error=ENOBUFS;
	goto error;

    }

    if (len<left) {

	*type=get_pubkey_type(message->pos, len);
	message->pos+=len;

    } else {

	*error=ENOBUFS;
	goto error;

    }

    return (int)(len+4); /* how may bytes read */

    error:

    logoutput("read_ssh_type_pubkey_buffer: error %i reading public key (%s)", *error, strerror(*error));
    return 0;

}

static void free_ptr_dummy(struct ssh_key_s *key)
{
    /* does nothing */
}

void init_ssh_key(struct ssh_key_s *key)
{
    memset(key, 0, sizeof(struct ssh_key_s));
    key->type=0;
    key->format=0;
    init_common_buffer(&key->data);
    key->ptr=NULL;
    key->free_ptr=free_ptr_dummy;
}

void free_ssh_key(struct ssh_key_s *key)
{
    free_common_buffer(&key->data);
    (* key->free_ptr)(key);
    init_ssh_key(key);
}
