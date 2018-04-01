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
#include <sys/syscall.h>
#include <sys/fsuid.h>

#include "logging.h"
#include "utils.h"
#include "simple-list.h"

#include "ssh-datatypes.h"
#include "pk-types.h"
#include "pk-keys.h"
#include "pk-keystore.h"
#include "pk-keystore-openssh.h"
#include "pk-layout.h"

static struct pk_identity_s *get_container_pk_identity(struct list_element_s *list)
{
    return (struct pk_identity_s *) ( ((char *) list) - offsetof(struct pk_identity_s, list));
}

struct pk_identity_s *create_pk_identity(struct pk_list_s *pkeys, unsigned char source, unsigned char scope, unsigned int size)
{
    struct pk_identity_s *identity=NULL;

    if ((scope != PK_IDENTITY_SCOPE_HOST) && (scope != PK_IDENTITY_SCOPE_USER)) return NULL;

    identity=malloc(sizeof(struct pk_identity_s) + size);

    if (identity) {

	memset(identity, '\0', sizeof(struct pk_identity_s) + size);

	identity->source=source;
	identity->scope=scope;

	identity->list.next=NULL;
	identity->list.prev=NULL;
	identity->pk_list=pkeys;

	identity->size=size;

	if (scope==PK_IDENTITY_SCOPE_HOST) {

	    add_list_element_last(&pkeys->host_list_header.head, &pkeys->host_list_header.tail, &identity->list);

	} else {

	    add_list_element_last(&pkeys->user_list_header.head, &pkeys->user_list_header.tail, &identity->list);

	}

    }

    return identity;

}

static void free_list_pk_identities(struct list_header_s *header)
{
    struct list_element_s *list = get_list_head(&header->head, &header->tail);
    struct pk_identity_s *identity = NULL;

    while (list) {

	identity = get_container_pk_identity(list);
	free(identity);
	list = get_list_head(&header->head, &header->tail);

    }

}

void free_lists_public_keys(struct pk_list_s *pkeys)
{
    free_list_pk_identities(&pkeys->user_list_header);
    free_list_pk_identities(&pkeys->host_list_header);
}

void init_list_public_keys(struct passwd *pwd, struct pk_list_s *pkeys)
{

    memset(pkeys, 0, sizeof(struct pk_list_s));
    pkeys->pwd=pwd;
    pkeys->user_list_header.head=NULL;
    pkeys->user_list_header.tail=NULL;
    pkeys->host_list_header.head=NULL;
    pkeys->host_list_header.tail=NULL;

}

int populate_list_public_keys(struct pk_list_s *pkeys, unsigned char source, const char *what)
{
    unsigned int error=0;
    int result = 0;

    switch (source) {

    case PK_IDENTITY_SOURCE_OPENSSH_LOCAL:

	logoutput("populate_list_public_keys: look for public %s keys", what);

	result = get_identity_records_openssh(pkeys, what, &error);
	break;

    default:

	logoutput("populate_list_public_keys: source %i not reckognized", source);

    }

    if (result==0) {

	if (error>0) {

	    logoutput("populate_list_public_keys: error %i (%s)", error, strerror(error));

	} else {

	    logoutput("populate_list_public_keys: no public %s keys found", what);

	}

    } else {

	logoutput("populate_list_public_keys: %i public %s key(s) found", result, what);

    }

    return result;

}

struct pk_identity_s *get_next_pk_identity(struct pk_list_s *pkeys, const char *what)
{
    struct list_header_s *header=(strcmp(what, "host")==0) ? &pkeys->host_list_header : &pkeys->user_list_header;
    struct list_element_s *list=get_list_head(&header->head, &header->tail);
    return (list) ? get_container_pk_identity(list) : NULL;
}

static int get_key_rawdata(struct pk_identity_s *identity, char *buffer, unsigned int size, unsigned char secret)
{

    switch (identity->source) {

    case PK_IDENTITY_SOURCE_OPENSSH_LOCAL:

	return get_key_file_openssh(identity, buffer, size, secret);

    default:

	logoutput("get_key_rawdata: source %i not reckognized", identity->source);

    }

    return 0;

}

char *get_pk_identity_file(struct pk_identity_s *identity)
{
    char *file=NULL;

    if (identity->source == PK_IDENTITY_SOURCE_OPENSSH_LOCAL) {

	file = identity->pk.openssh_local.file;

    }

    return file;

}

char *get_pk_identity_user(struct pk_identity_s *identity)
{
    char *user=NULL;

    if (identity->source == PK_IDENTITY_SOURCE_OPENSSH_LOCAL) {

	user = identity->pk.openssh_local.user;

    }

    return user;

}

int read_key_param(struct pk_identity_s *identity, struct ssh_key_s *key)
{
    unsigned int layout=0;
    unsigned int format=0;
    unsigned int len = get_key_rawdata(identity, NULL, 0, key->secret);
    char buffer[len];
    struct ssh_string_s keymaterial;
    unsigned int error=0;

    if (len == 0) {

	logoutput_warning("read_key_param: no data read");
	return -1;

    }

    if (get_key_rawdata(identity, buffer, len, key->secret) == 0) {

	logoutput_warning("read_key_param: error reading data");
	return -1;

    }

    /* what is the layout of the data? (headers and footers, encryption, ....)
	at this moment only supported openssh */

    switch (identity->source) {

    case PK_IDENTITY_SOURCE_OPENSSH_LOCAL:

	layout=PK_DATA_LAYOUT_OPENSSH;
	break;

    default:

	logoutput_warning("read_key_param: layout %i identity not known", identity->source);
	return -1;

    }

    /* extract */

    init_ssh_string(&keymaterial);

    if (get_key_material(key, buffer, len, layout, &keymaterial, &format)==-1) {

	logoutput_warning("read_key_param: error getting key material");
	free_ssh_string(&keymaterial);
	return -1;

    } else if (keymaterial.len==0) {

	logoutput_warning("read_key_param: no key material");
	return -1;

    } else if (format==0) {

	logoutput_warning("read_key_param: format not specified");
	return -1;

    }

    /* read param */

    if ((* key->read_key)(key, keymaterial.ptr, keymaterial.len, format, &error)==-1) {

	logoutput_warning("read_key_param: error %i reading key parameters (%s)", error, strerror(error));
	free_ssh_string(&keymaterial);
	return -1;

    }

    free_ssh_string(&keymaterial);
    return 0;

}
