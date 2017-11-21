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
#include "ssh-pubkey-utils.h"

static const char *openssh_rsa_private_header="-----BEGIN RSA PRIVATE KEY-----";
static const char *openssh_rsa_private_footer="-----END RSA PRIVATE KEY-----";
static const char *openssh_dss_private_header="-----BEGIN DSA PRIVATE KEY-----";
static const char *openssh_dss_private_footer="-----END DSA PRIVATE KEY-----";
static const char *openssh_key_private_header="-----BEGIN OPENSSH PRIVATE KEY-----";
static const char *openssh_key_private_footer="-----END OPENSSH PRIVATE KEY-----";

/* read a public key from a buffer
    for openssh this looks like for example:
    ssh-rsa AAAA....... sbon@host */

int _read_public_key_openssh(struct common_buffer_s *data, struct ssh_key_s *key)
{
    char *sep=NULL;
    unsigned int left=data->len;
    unsigned int len=0;
    unsigned int error=0;

    data->pos=data->ptr;

    /* first field is the type */

    sep=memchr(data->pos, ' ', left);

    if (sep) {

	len=(unsigned int) (sep - data->pos);

	key->type=get_pubkey_type(data->pos, len);
	if (key->type==0) goto error;

    } else {

	goto error;

    }

    len=(unsigned int) (sep + 1 - data->ptr);

    if (left<=len) {

	error=EINVAL;
	goto error;

    }

    left-=len;
    data->pos=sep + 1;

    /* second field is key material */

    sep=memchr(data->pos, ' ', left);
    if (sep==NULL) sep=data->pos + left;

    if (sep) {
	struct common_buffer_s second;

	init_common_buffer(&second);
	second.ptr=data->pos;
	second.size=(unsigned int)(sep - data->pos);
	second.len=second.size;
	second.pos=second.ptr;

	key->data.ptr=decode_base64(&second, &len);

	if (key->data.ptr) {

	    key->data.size=len;
	    key->data.len=len;
	    key->data.pos=key->data.ptr;
	    key->format=_PUBKEY_FORMAT_SSH;

	} else {

	    error=ENOMEM;
	    goto error;

	}

	data->pos+=second.size;
	left-=second.size;

    }

    return 0;

    error:

    if (error==0) error=EIO;
    logoutput("_read_public_key_openssh: error %i reading public key (%s)", error, strerror(error));
    return -1;

}

static char *compare_header_buffer(struct common_buffer_s *data, const char *header)
{
    unsigned int len=strlen(header);
    unsigned int size=data->size;

    if (len<size) {

	if (strncmp(data->ptr, header, len)==0) return data->ptr;

    }

    return NULL;
}

static char *compare_footer_buffer(struct common_buffer_s *data, const char *footer)
{
    unsigned int len=strlen(footer);
    unsigned int size=data->size;

    if (len<size) {

	/* it's possible that the footer is not exactly at the end of the file: walk back */

	while (size>len) {

	    if (strncmp(data->ptr + size - len, footer, len)==0) return (char *) (data->ptr + size - len);
	    size--;

	}

    }

    return NULL;
}

/* read a (private) key
    leave out the header and the footer, decode the relevant part */

int _read_private_key_openssh(struct common_buffer_s *data, struct ssh_key_s *key)
{
    unsigned char format=_PUBKEY_FORMAT_NONE;
    char *header=NULL;
    char *footer=NULL;
    unsigned int len=0;
    unsigned int error=0;

    logoutput("_read_private_key_openssh");

    /* first try the new openssh format: it can store any method */

    header=compare_header_buffer(data, openssh_key_private_header);
    if (header) footer=compare_footer_buffer(data, openssh_key_private_footer);
    len=strlen(openssh_key_private_header);

    if (header && footer) {

	format=_PUBKEY_FORMAT_OPENSSH_KEY;
	logoutput("_read_private_key_openssh: found openssh format");

    } else {

	/* try older formats
	    it's obvious that the rsa header matches the rsa type key and the dss header matches the dss type */

	header=NULL;
	footer=NULL;

	if (key->type & _PUBKEY_METHOD_SSH_RSA) {

	    header=compare_header_buffer(data, openssh_rsa_private_header);
	    if (header) footer=compare_footer_buffer(data, openssh_rsa_private_footer);
	    len=strlen(openssh_rsa_private_header);
	    format=_PUBKEY_FORMAT_DER;
	    logoutput("_read_private_key_openssh: found rsa format");

	} else if (key->type & _PUBKEY_METHOD_SSH_DSS) {

	    header=compare_header_buffer(data, openssh_dss_private_header);
	    if (header) footer=compare_footer_buffer(data, openssh_dss_private_footer);
	    len=strlen(openssh_dss_private_header);
	    format=_PUBKEY_FORMAT_DER;
	    logoutput("_read_private_key_openssh: found dss format");

	}

    }

    /* which layout is used: the key material is encoded */

    if (header && footer) {
	struct common_buffer_s buffer;

	init_common_buffer(&buffer);
	buffer.ptr=header + len;
	buffer.size=(unsigned int)(footer - buffer.ptr);
	buffer.len=buffer.size;
	buffer.pos=buffer.ptr;

	key->data.ptr=decode_base64(&buffer, &len);

	if (key->data.ptr) {

	    key->data.size=len;
	    key->data.len=len;
	    key->data.pos=key->data.ptr;
	    key->format=format;

	} else {

	    error=ENOMEM;
	    goto error;

	}

    } else {

	if (header==NULL) {

	    logoutput("_read_private_key_openssh: no header found");

	}

	if (footer==NULL) {

	    logoutput("_read_private_key_openssh: no footer found");

	}

	error=EINVAL;
	goto error;

    }

    return 0;

    error:

    if (error==0) error=EIO;
    logoutput("_read_private_key_openssh: error %i reading private key (%s)", error, strerror(error));
    return -1;

}
