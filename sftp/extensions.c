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
#include "request-hash.h"
#include "fuse-sftp-common.h"

#define NAME_MAPEXTENSION_DEFAULT	"mapextension@bononline.nl"

void init_sftp_extensions(struct sftp_subsystem_s *sftp)
{
    struct sftp_extensions_s *extensions=&sftp->extensions;
    init_list_header(&extensions->header, SIMPLE_LIST_TYPE_EMPTY, NULL);
    extensions->count=0;
    extensions->mapped=SSH_FXP_MAPPING_MIN;
    extensions->mapextension=NULL;
    extensions->fsync=NULL;
    extensions->statvfs=NULL;
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
    extensions->mapextension=NULL;

}

static int handle_sftp_reply(struct sftp_request_s *sftp_r, struct sftp_reply_s *reply, unsigned int *error)
{
    int result=0;

    reply->type=sftp_r->reply.type;

    if (reply->type==SSH_FXP_STATUS) {

	reply->response.status.code=sftp_r->reply.response.status.code;
	reply->response.status.linux_error=sftp_r->reply.response.status.linux_error;
	reply->response.status.buff=sftp_r->reply.response.status.buff;
	reply->response.status.size=sftp_r->reply.response.status.size;
	sftp_r->reply.response.status.buff=NULL;
	sftp_r->reply.response.status.size=0;

    } else if (reply->type==SSH_FXP_HANDLE) {

	reply->response.handle.name=sftp_r->reply.response.handle.name;
	reply->response.handle.len=sftp_r->reply.response.handle.len;
	sftp_r->reply.response.handle.name=NULL;
	sftp_r->reply.response.handle.len=0;

    } else if (reply->type==SSH_FXP_DATA) {

	reply->response.data.data=sftp_r->reply.response.data.data;
	reply->response.data.size=sftp_r->reply.response.data.size;
	reply->response.data.eof=sftp_r->reply.response.data.eof;
	sftp_r->reply.response.data.data=NULL;
	sftp_r->reply.response.data.size=0;

    } else if (reply->type==SSH_FXP_NAME) {

	reply->response.names.count=sftp_r->reply.response.names.count;
	reply->response.names.size=sftp_r->reply.response.names.size;
	reply->response.names.eof=sftp_r->reply.response.names.eof;
	reply->response.names.buff=sftp_r->reply.response.names.buff;
	reply->response.names.pos=sftp_r->reply.response.names.pos;
	sftp_r->reply.response.names.buff=NULL;
	sftp_r->reply.response.names.size=0;

    } else if (reply->type==SSH_FXP_ATTRS) {

	reply->response.attr.buff=sftp_r->reply.response.attr.buff;
	reply->response.attr.size=sftp_r->reply.response.attr.size;
	sftp_r->reply.response.attr.buff=NULL;
	sftp_r->reply.response.attr.size=0;

    } else if (reply->type==SSH_FXP_EXTENDED_REPLY) {

	reply->response.extension.buff=sftp_r->reply.response.extension.buff;
	reply->response.extension.size=sftp_r->reply.response.extension.size;
	sftp_r->reply.response.extension.buff=NULL;
	sftp_r->reply.response.extension.size=0;

    } else {

	*error=EPROTO;
	result=-1;

    }

    reply->error=sftp_r->reply.error;

    return result;

}

static int _send_sftp_extension_compat(struct sftp_subsystem_s *sftp, struct ssh_string_s *name, struct ssh_string_s *data, struct sftp_reply_s *reply, unsigned int *error)
{
    struct sftp_request_s sftp_r;
    int result=-1;

    init_sftp_request(&sftp_r);
    *error=EIO;

    sftp_r.id=0;

    sftp_r.call.extension.len=name->len;
    sftp_r.call.extension.name=(unsigned char *) name->ptr;
    sftp_r.call.extension.size=data->len;
    sftp_r.call.extension.data=(unsigned char *) data->ptr;
    sftp_r.fuse_request=NULL;

    if ((* sftp->send_ops->extension)(sftp, &sftp_r)==0) {
	void *request=NULL;

	request=create_sftp_request(&sftp->send_hash, &sftp_r, error);

	if (request) {
	    struct timespec timeout;

	    get_sftp_request_timeout(&timeout);

	    if (wait_sftp_response_simple(sftp, request, &timeout, error)==1) {

		result=handle_sftp_reply(&sftp_r, reply, error);

	    }

	}

    } else {

	*error=sftp_r.reply.error;

    }

    return result;
}

static int _send_sftp_extension_default(struct sftp_subsystem_s *sftp, struct sftp_protocolextension_s *extension, struct ssh_string_s *data, struct sftp_reply_s *reply, unsigned int *error)
{
    return _send_sftp_extension_compat(sftp, &extension->name, &extension->data, reply, error);
}

static int _send_sftp_extension_custom(struct sftp_subsystem_s *sftp, struct sftp_protocolextension_s *extension, struct ssh_string_s *data, struct sftp_reply_s *reply, unsigned int *error)
{
    struct sftp_request_s sftp_r;
    int result=-1;

    init_sftp_request(&sftp_r);
    *error=EIO;

    sftp_r.id=0;

    sftp_r.call.custom.nr=extension->mapped;
    sftp_r.call.custom.size=data->len;
    sftp_r.call.custom.data=(unsigned char *) data->ptr;
    sftp_r.fuse_request=NULL;

    if ((* sftp->send_ops->custom)(sftp, &sftp_r)==0) {
	void *request=NULL;

	request=create_sftp_request(&sftp->send_hash, &sftp_r, error);

	if (request) {
	    struct timespec timeout;

	    get_sftp_request_timeout(&timeout);

	    if (wait_sftp_response_simple(sftp, request, &timeout, error)==1) {

		result=handle_sftp_reply(&sftp_r, reply, error);

	    }

	}

    } else {

	*error=sftp_r.reply.error;

    }

    return result;

}

static int _send_sftp_extension_notsupp(struct sftp_subsystem_s *sftp, struct sftp_protocolextension_s *extension, struct ssh_string_s *data, struct sftp_reply_s *reply, unsigned int *error)
{
    *error=EOPNOTSUPP;
    return -1;
}

static void dummy_event_cb(struct ssh_string_s *name, struct ssh_string_s *data, void *ptr, unsigned int event)
{
}

static struct sftp_protocolextension_s *_add_sftp_extension(struct sftp_subsystem_s *sftp, struct ssh_string_s *name, struct ssh_string_s *data, unsigned int flags)
{
    struct sftp_protocolextension_s *extension=NULL;

    if (name->len==0 || name->ptr==NULL) return NULL;

    extension=malloc(sizeof(struct sftp_protocolextension_s) + name->len + ((data) ? data->len : 0));

    if (extension) {
	struct sftp_extensions_s *extensions=&sftp->extensions;
	unsigned int pos=0;
	unsigned int len=name->len + (data ? data->len : 0);

	memset(extension, 0, sizeof(struct sftp_protocolextension_s) + len);
	extension->flags=0;
	extension->mapped=0;
	extension->ptr=NULL;
	extension->event_cb=dummy_event_cb;
	extension->send_extension=_send_sftp_extension_notsupp;
	init_list_element(&extension->list, NULL);
	memcpy(&extension->buffer[pos], name->ptr, name->len);
	extension->name.ptr=&extension->buffer[pos];
	extension->name.len=name->len;
	pos+=name->len;

	if (data && data->len>0) {

	    memcpy(&extension->buffer[pos], data->ptr, data->len);
	    extension->data.ptr=&extension->buffer[pos];
	    extension->data.len=data->len;

	} else {

	    extension->data.ptr=NULL;
	    extension->data.len=0;

	}

	if (flags & SFTP_EXTENSION_FLAG_SUPPORTED) {

	    extension->flags|=SFTP_EXTENSION_FLAG_SUPPORTED;
	    extension->send_extension=_send_sftp_extension_default;

	}

	add_list_element_last(&extensions->header, &extension->list);
	extension->nr=extensions->count;
	extensions->count++;
	logoutput("add_sftp_extension: added %.*s", name->len, name->ptr);

	if (compare_ssh_string(name, 'c', "statvfs@openssh.com")==0) extensions->statvfs=extension;
	if (compare_ssh_string(name, 'c', "fsync@openssh.com")==0) extensions->fsync=extension;

    }

    return extension;

}

static int match_extension_byname(struct list_element_s *list, void *ptr)
{
    struct ssh_string_s *name=(struct ssh_string_s *) ptr;
    struct sftp_protocolextension_s *extension=(struct sftp_protocolextension_s *)(((char *) list) - offsetof(struct sftp_protocolextension_s, list));
    if (name->len==extension->name.len && memcmp(name->ptr, extension->name.ptr, extension->name.len)==0) return 0;
    return -1;
}

static int compare_extension_data(struct ssh_string_s *e, struct ssh_string_s *d)
{
    int result=-1;

    if (d==NULL || d->len==0) {

	result=(e->len==0) ? 0 : -1;

    } else if (d->len==e->len) {

	result=memcmp(d->ptr, e->ptr, d->len);

    }

    return result;
}

static struct sftp_protocolextension_s *lookup_sftp_extension(struct sftp_subsystem_s *sftp, struct ssh_string_s *name, struct ssh_string_s *data, unsigned int flags)
{
    struct list_element_s *list=NULL;
    struct sftp_protocolextension_s *extension=NULL;

    list=search_list_element_forw(&sftp->extensions.header, match_extension_byname, (void *) name);

    if (list) {

	extension=(struct sftp_protocolextension_s *)(((char *) list) - offsetof(struct sftp_protocolextension_s, list));

	if (flags & SFTP_EXTENSION_FLAG_SUPPORTED) {

	    (* extension->event_cb)(&extension->name, &extension->data, extension->ptr, SFTP_EXTENSION_EVENT_SUPPORTED);
	    extension->send_extension=_send_sftp_extension_default;

	}

	if (compare_extension_data(&extension->data, data)==-1 && (flags & SFTP_EXTENSION_FLAG_OVERRIDE_DATA)) {
	    unsigned int len=name->len + (data) ? data->len : 0;
	    struct list_element_s *prev=get_prev_element(list);

	    if (extension->data.len != ((data) ? data->len : 0)) {

		remove_list_element(list);

		/* realloc the extension to create/remove space for the data */

		extension=realloc(extension, sizeof(struct sftp_protocolextension_s) + len);

		if (extension) {

		    if (data) {
			char *pos=&extension->buffer[name->len];

			memcpy(pos, data->ptr, data->len);
			extension->data.ptr=pos;
			extension->data.len=data->len;

		    } else {

			extension->data.ptr=NULL;
			extension->data.len=0;

		    }

		    list=&extension->list; /* address can be changed by realloc*/

		    /* put back on list after prev
			this also works when prev is empty */

		    add_list_element_after(&sftp->extensions.header, prev, list);
		    (* extension->event_cb)(&extension->name, &extension->data, extension->ptr, SFTP_EXTENSION_EVENT_DATA);

		} else {

		    (* extension->event_cb)(&extension->name, &extension->data, extension->ptr, SFTP_EXTENSION_EVENT_ERROR);
		    return NULL;

		}

	    } else if (extension->data.len>0) {

		memcpy(extension->data.ptr, data->ptr, data->len);

	    }

	}

	if (flags & SFTP_EXTENSION_FLAG_SUPPORTED) extension->flags|=SFTP_EXTENSION_FLAG_SUPPORTED;

    } else if (flags & SFTP_EXTENSION_FLAG_CREATE) {

	extension=_add_sftp_extension(sftp, name, data, flags);

    }

    return extension;
}

static struct sftp_protocolextension_s *register_sftp_protocolextension(struct sftp_subsystem_s *sftp, struct ssh_string_s *name, struct ssh_string_s *data,
				    void (* event_cb)(struct ssh_string_s *name, struct ssh_string_s *data, void *ptr, unsigned int event), void *ptr2)
{
    struct sftp_protocolextension_s *extension=lookup_sftp_extension(sftp, name, data, SFTP_EXTENSION_FLAG_CREATE);

    if (extension) {

	extension->event_cb=event_cb;
	extension->ptr=ptr2;

    }

    return extension;
}

void *register_sftp_protocolextension_ctx(void *ptr, struct ssh_string_s *name, struct ssh_string_s *data,
				    void (* event_cb)(struct ssh_string_s *name, struct ssh_string_s *data, void *ptr, unsigned int event), void *ptr2)
{
    return (void *) register_sftp_protocolextension((struct sftp_subsystem_s *) ptr, name, data, event_cb, ptr2);
}

struct sftp_protocolextension_s *add_sftp_protocolextension(struct sftp_subsystem_s *sftp, struct ssh_string_s *name, struct ssh_string_s *data)
{
    return lookup_sftp_extension(sftp, name, data, SFTP_EXTENSION_FLAG_CREATE | SFTP_EXTENSION_FLAG_SUPPORTED | SFTP_EXTENSION_FLAG_OVERRIDE_DATA);
}

static int map_sftp_protocolextension(struct sftp_subsystem_s *sftp, struct sftp_protocolextension_s *mapextension, struct sftp_protocolextension_s *extension)
{
    unsigned int error=0;
    struct sftp_reply_s reply;
    int result=-1;

    memset(&reply, 0, sizeof(struct sftp_reply_s));

    /* test the map extension by mapping itself */

    if ((* mapextension->send_extension)(sftp, mapextension, &extension->name, &reply, &error)==0) {

	if (reply.type==SSH_FXP_EXTENDED_REPLY) {

	    if (reply.response.extension.size>=4) {
		unsigned int mapped=get_uint32((char *) reply.response.extension.buff);

		/* only range 210-255 is allowed */

		if (mapped>=210 && mapped<=255) {

		    extension->mapped=mapped;
		    extension->send_extension=_send_sftp_extension_custom;
		    logoutput("map_sftp_protocolextension: %.*s mapped to nr %i", extension->name.len, extension->name.ptr, mapped);
		    result=0;

		} else {

		    logoutput("map_sftp_protocolextension: received illegal nr %i", mapped);
		    error=EPROTO;

		}

	    } else {

		logoutput("map_sftp_protocolextension: response size too small: %i", reply.response.extension.size);
		error=EPROTO;

	    }

	} else if (reply.type==SSH_FXP_STATUS) {

	    logoutput("map_sftp_protocolextension: error response : %i (%s)", reply.response.status.linux_error, strerror(reply.response.status.linux_error));
	    error=reply.response.status.linux_error;

	}

    }

    return result;
}

static void complete_sftp_protocolextensions(struct sftp_subsystem_s *sftp, char *mapextensionname)
{
    struct ssh_string_s tmp;
    struct list_element_s *list=NULL;
    struct sftp_protocolextension_s *mapextension=NULL;

    /* is mapping supported by server ? 
	are there well known mapping extensions?
	which mappings to try */

    if (mapextensionname==NULL) mapextensionname=NAME_MAPEXTENSION_DEFAULT;

    tmp.ptr=mapextensionname;
    tmp.len=strlen(mapextensionname);
    list=search_list_element_forw(&sftp->extensions.header, match_extension_byname, (void *) &tmp);

    if (list) {
	struct sftp_protocolextension_s *extension=(struct sftp_protocolextension_s *)(((char *) list) - offsetof(struct sftp_protocolextension_s, list));

	if (map_sftp_protocolextension(sftp, extension, extension)==0) {

	    logoutput("complete_sftp_protocolextension: mapping success");
	    sftp->extensions.mapextension=extension;
	    mapextension=extension;

	} else {

	    logoutput("complete_sftp_protocolextension: mapping failed");

	}

    }

    if (mapextension) {

	/* map all other extensions */

	list=get_list_head(&sftp->extensions.header, 0);

	while (list) {

	    struct sftp_protocolextension_s *extension=(struct sftp_protocolextension_s *)(((char *) list) - offsetof(struct sftp_protocolextension_s, list));

	    if (extension != mapextension) {

		if (map_sftp_protocolextension(sftp, extension, extension)==0) {

		    logoutput("complete_sftp_protocolextension: mapping of %.*s success to %i", extension->name.len, extension->name.ptr, extension->mapped);
		    (* extension->event_cb)(&extension->name, &extension->data, extension->ptr, SFTP_EXTENSION_EVENT_MAPPED);

		} else {

		    logoutput("complete_sftp_protocolextension: mapping of %.*s failed", extension->name.len, extension->name.ptr);

		}

	    }

	    list=get_next_element(list);

	}

    }

}

void complete_sftp_protocolextensions_ctx(void *ptr, char *mapextensionname)
{
    complete_sftp_protocolextensions((struct sftp_subsystem_s *) ptr, mapextensionname);
}

int send_sftp_extension_ctx(void *ptr, char *data, unsigned int size, struct sftp_reply_s *reply, unsigned int *error)
{
    struct sftp_protocolextension_s *extension=(struct sftp_protocolextension_s *) ptr;
    struct list_header_s *header=extension->list.h;
    struct sftp_extensions_s *extensions=(struct sftp_extensions_s *)(((char *) header) - offsetof(struct sftp_extensions_s, header));
    struct sftp_subsystem_s *sftp=(struct sftp_subsystem_s *)(((char *) extensions) - offsetof(struct sftp_subsystem_s, extensions));
    struct ssh_string_s tmp={.len=size, .ptr=data};

    return (* extension->send_extension)(sftp, extension, &tmp, reply, error);
}

int send_sftp_extension_compat_ctx(void *ptr, struct ssh_string_s *name, struct ssh_string_s *data, struct sftp_reply_s *reply, unsigned int *error)
{
    struct sftp_subsystem_s *sftp=(struct sftp_subsystem_s *) ptr;

    return _send_sftp_extension_compat(sftp, name, data, reply, error);
}

int send_sftp_extension_statvfs_ctx(void *ptr, struct ssh_string_s *data, struct sftp_reply_s *reply, unsigned int *error)
{
    struct sftp_subsystem_s *sftp=(struct sftp_subsystem_s *) ptr;
    struct sftp_protocolextension_s *extension=sftp->extensions.statvfs;

    if (extension==NULL) {

	*error=EOPNOTSUPP;
	return -1;

    }

    return (* extension->send_extension)(sftp, extension, data, reply, error);
}

int send_sftp_extension_fsync_ctx(void *ptr, struct ssh_string_s *data, struct sftp_reply_s *reply, unsigned int *error)
{
    struct sftp_subsystem_s *sftp=(struct sftp_subsystem_s *) ptr;
    struct sftp_protocolextension_s *extension=sftp->extensions.fsync;

    if (extension==NULL) {

	*error=EOPNOTSUPP;
	return -1;

    }

    return (* extension->send_extension)(sftp, extension, data, reply, error);
}
