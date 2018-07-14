/*
  2017, 2018 Stef Bon <stefbon@gmail.com>

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
#include <ctype.h>
#include <inttypes.h>

#include <sys/param.h>
#include <sys/types.h>

#include <logging.h>
#include <utils.h>

#include "ssh-datatypes.h"
#include "pk-keys.h"
#include "pk-types.h"
#include "pk-utils.h"

/* different headers for the files with private keys */

static const char *openssh_rsa_private_header="-----BEGIN RSA PRIVATE KEY-----";
static const char *openssh_rsa_private_footer="-----END RSA PRIVATE KEY-----";
static const char *openssh_dss_private_header="-----BEGIN DSA PRIVATE KEY-----";
static const char *openssh_dss_private_footer="-----END DSA PRIVATE KEY-----";
static const char *openssh_key_private_header="-----BEGIN OPENSSH PRIVATE KEY-----";
static const char *openssh_key_private_footer="-----END OPENSSH PRIVATE KEY-----";

/* read keymaterial from buffer which is encoded
    for openssh a ssh-rsa looks for example :
    ssh-rsa AAAA....... sbon@host */

int get_pkey_material_openssh(struct ssh_key_s *key, char *buffer, unsigned int size, struct ssh_string_s *result, unsigned int *format)
{
    char *sep=NULL;
    char *pos=buffer;
    struct ssh_pkalgo_s *algo=NULL;
    int left=size;

    logoutput("get_pkey_material_openssh");

    /* first field is the algo */

    sep=memchr(pos, ' ', left);

    if (sep) {
	unsigned int len = (unsigned int) (sep - pos);

	algo = get_pkalgo(pos, len, NULL);

	if (algo == NULL) {

	    *sep='\0';
	    logoutput("get_pkey_material_openssh: algo %s not supported/reckognized (l=%i)", pos, len);
	    goto error;

	}

    } else {

	logoutput("get_pkey_material_openssh: no space seperator found");
	goto error;

    }

    if (key->algo) {

	if (key->algo != algo) {

	    logoutput_warning("get_pkey_material_openssh: expecting algo %s, found algo %s", key->algo->name, algo->name);
	    (* key->set_algo)(key, algo);

	}

    } else {

	(* key->set_algo)(key, algo);

    }

    /* second field is key material */

    pos = sep + 1;
    left = (int)(buffer + size - pos);

    if (left < 4) {

	logoutput("get_pkey_material_openssh: not enough data");
	goto error;

    }

    sep = memchr(pos, ' ', left);
    if ( sep == NULL) sep = pos + left;

    if (algo->id == SSH_PKALGO_ID_DSS || algo->id == SSH_PKALGO_ID_RSA || algo->id == SSH_PKALGO_ID_ED25519) {
	unsigned int len = (unsigned int) (sep - pos);

	/* key material is base64 encoded
	    and result is in ssh format */

	*format = PK_DATA_FORMAT_SSH;
	return decode_buffer_base64(pos, len, result);

    }

    error:

    return -1;

}

static char *compare_header_buffer(char *buffer, unsigned int size, const char *header)
{
    unsigned int len=strlen(header);

    if (len<size) {

	if (strncmp(buffer, header, len)==0) return buffer;

    }

    return NULL;
}

static char *compare_footer_buffer(char *buffer, unsigned int size, const char *footer)
{
    unsigned int len=strlen(footer);

    if (len<size) {
	char *pos=buffer + size - len;

	/* it's possible that the footer is not exactly at the end of the file: walk back */

	while (pos > buffer) {

	    if (strncmp(pos, footer, len)==0) return pos;
	    pos--;

	}

    }

    return NULL;
}

/* get the (private) key material
    leave out the header and the footer, decode the relevant part */

static int get_skey_material_openssh(struct ssh_key_s *key, char *buffer, unsigned int size, struct ssh_string_s *result, unsigned int *format)
{
    char *header=NULL;
    char *footer=NULL;
    unsigned int len=0;

    logoutput("get_skey_material_openssh");

    /* first try the new openssh format: it can store any method */

    header=compare_header_buffer(buffer, size, openssh_key_private_header);
    if (header) footer=compare_footer_buffer(buffer, size, openssh_key_private_footer);

    if (header && footer) {

	*format=PK_DATA_FORMAT_OPENSSH_KEY;
	len=strlen(openssh_key_private_header);
	logoutput("get_skey_material_openssh: found openssh key format");
	goto found;

    }

    /* try older formats
	it's obvious that the rsa header matches the rsa type key and the dss header matches the dss type */

    header=NULL;
    footer=NULL;

    if (key->algo->id == SSH_PKALGO_ID_RSA) {

	header=compare_header_buffer(buffer, size, openssh_rsa_private_header);
	if (header) footer=compare_footer_buffer(buffer, size, openssh_rsa_private_footer);

	if (header && footer) {

	    len=strlen(openssh_rsa_private_header);
	    *format=PK_DATA_FORMAT_DERASN1;
	    logoutput("get_skey_material_openssh: found rsa format");

	}

    } else if (key->algo->id == SSH_PKALGO_ID_DSS) {

	header=compare_header_buffer(buffer, size, openssh_dss_private_header);
	if (header) footer=compare_footer_buffer(buffer, size, openssh_dss_private_footer);

	if (header && footer) {

	    len=strlen(openssh_dss_private_header);
	    *format=PK_DATA_FORMAT_DERASN1;
	    logoutput("get_skey_material_openssh: found dss format");

	}

    }

    found:

    /* which layout is used: the key material is encoded */

    if (header && footer) {
	char *pos = header + len;
	unsigned int len = (unsigned int)(footer - pos);

	return decode_buffer_base64(pos, len, result);

    } else {

	if (header==NULL) logoutput("get_skey_material_openssh: no header found");
	if (footer==NULL) logoutput("get_skey_material_openssh: no footer found");

    }

    error:

    return -1;

}

/* key is stored in buffer
   the parameter layout decribes the to be expected layout; openssh stores the keys a specfic way */

int get_pkey_material(struct ssh_key_s *key, char *buffer, unsigned int size, unsigned int layout, struct ssh_string_s *result, unsigned int *format)
{

    switch (layout) {

    case PK_DATA_LAYOUT_OPENSSH:

	return get_pkey_material_openssh(key, buffer, size, result, format);

    default:

	logoutput("read_public_key: layout %i not supported", layout);

    }

    return -1;
}

int get_skey_material(struct ssh_key_s *key, char *buffer, unsigned int size, unsigned int layout, struct ssh_string_s *result, unsigned int *format)
{

    switch (layout) {

    case PK_DATA_LAYOUT_OPENSSH:

	return get_skey_material_openssh(key, buffer, size, result, format);

    default:

	logoutput("read_private_key: layout %i not supported", layout);

    }

    return -1;
}

int get_key_material(struct ssh_key_s *key, char *buffer, unsigned int size, unsigned int layout, struct ssh_string_s *result, unsigned int *format)
{
    logoutput("get_key_material: layout %i secret %i size %i", layout, key->secret, size);
    return (key->secret>0) ? get_skey_material(key, buffer, size, layout, result, format) : get_pkey_material(key, buffer, size, layout, result, format);
}
