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
#include <sys/vfs.h>

#include "main.h"
#include "logging.h"
#include "pathinfo.h"
#include "common-utils/utils.h"
#include "workerthreads.h"

#include "ssh-common-protocol.h"
#include "ssh-common.h"
#include "ssh-channel.h"
#include "ssh-utils.h"
#include "ssh-send.h"
#include "ssh-receive.h"

#include "common-protocol.h"
#include "common.h"

#define NAME_MAPEXTENSION_DEFAULT	"mapextension@bononline.nl"

void init_sftp_extensions(struct sftp_subsystem_s *sftp)
{
    struct sftp_extensions_s *extensions=&sftp->extensions;
    init_list_header(&extensions->header, SIMPLE_LIST_TYPE_EMPTY, NULL);
    extensions->count=0;
    extensions->mapped=SSH_FXP_EXTENDED_MAPPED;
}

void clear_sftp_extensions(struct sftp_subsystem_s *sftp)
{
    struct sftp_extensions_s *extensions=&sftp->extensions;
    struct list_element_s *list=NULL;

    list=get_list_head(&extensions->header, SIMPLE_LIST_FLAG_REMOVE);

    while(list) {
	struct sftp_protocolextension_s *extension=(struct sftp_protocolextension_s *)(((char *) list) - offsetof(struct sftp_protocolextension_s, list));

	free(extension);
	list=get_list_head(&extensions->header, SIMPLE_LIST_FLAG_REMOVE);

    }

    extensions->count=0;

}

struct sftp_protocolextension_s *add_sftp_extension(struct sftp_subsystem_s *sftp, struct ssh_string_s *name, struct ssh_string_s *data)
{
    struct sftp_protocolextension_s *extension=NULL;

    if (name->len==0 || name->ptr==NULL) return NULL;

    extension=malloc(sizeof(struct sftp_protocolextension_s) + name->len + data->len);

    if (extension) {
	struct sftp_extensions_s *extensions=&sftp->extensions;
	unsigned int pos=0;

	memset(extension, 0, sizeof(struct sftp_protocolextension_s) + name->len + data->len);
	extension->flags=0;
	init_list_element(&extension->list, NULL);
	memcpy(&extension->buffer[pos], name->ptr, name->len);
	extension->name.ptr=&extension->buffer[pos];
	extension->name.len=name->len;
	pos+=name->len;

	if (data->len>0) {

	    memcpy(&extension->buffer[pos], data->ptr, data->len);
	    extension->data.ptr=&extension->buffer[pos];
	    extension->data.len=name->len;

	}

	add_list_element_last(&extensions->header, &extension->list);
	extension->nr=extensions->count;
	extensions->count++;
	logoutput("add_sftp_extension: added %.*s", name->len, name->ptr);

    }

    return extension;

}

static int match_extension(struct list_element_s *list, void *ptr)
{
    struct ssh_string_s *name=(struct ssh_string_s *) ptr;
    struct sftp_protocolextension_s *extension=(struct sftp_protocolextension_s *)(((char *) list) - offsetof(struct sftp_protocolextension_s, list));
    if (name->len==extension->name.len && strncmp(name->ptr, extension->name.ptr, extension->name.len)==0) return 0;
    return -1;
}

struct sftp_protocolextension_s *lookup_sftp_extension(struct sftp_subsystem_s *sftp, struct ssh_string_s *name)
{
    struct list_element_s *list=NULL;

    list=search_list_element_forw(&sftp->extensions.header, match_extension, (void *) name);
    if (list) return (struct sftp_protocolextension_s *)(((char *) list) - offsetof(struct sftp_protocolextension_s, list));
    return NULL;

}

int test_extension_supported(struct sftp_subsystem_s *sftp, char *name)
{
    struct ssh_string_s tmp = { .ptr=name, .len=strlen(name), };
    struct list_element_s *list=search_list_element_forw(&sftp->extensions.header, match_extension, (void *) &tmp);
    return (list) ? 0 : -1;
}

int test_extension_supported_ctx(void *ptr, char *name)
{
    struct sftp_subsystem_s *sftp=(struct sftp_subsystem_s *) ptr;
    return test_extension_supported(sftp, name);
}

void *lookup_sftp_extension_ctx(void *ptr, char *name)
{
    struct sftp_subsystem_s *sftp=(struct sftp_subsystem_s *) ptr;
    struct ssh_string_s tmp = { .ptr=name, .len=strlen(name), };

    struct list_element_s *list=search_list_element_forw(&sftp->extensions.header, match_extension, (void *) &tmp);
    return (void *)(list);
}
