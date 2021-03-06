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
#include "common-admin.h"
#include "common-utils.h"

#include "request-hash.h"

#include "attr-common.h"
#include "attr-v03.h"
#include "attr-v04.h"
#include "attr-v05.h"
#include "attr-v06.h"

#include "recv-common.h"
#include "recv-v03.h"
#include "recv-v04.h"
#include "recv-v05.h"
#include "recv-v06.h"

#include "send-common.h"
#include "send-v03.h"
#include "send-v04.h"
#include "send-v05.h"
#include "send-v06.h"

#include "time.h"
#include "usermapping.h"
#include "extensions.h"
#include "fuse-sftp-statfs.h"
#include "fuse-sftp-extensions.h"

extern int test_valid_sftp_readdir(struct context_interface_s *interface, void *ptr, unsigned int *len);

static void read_default_features_v06(struct sftp_subsystem_s *sftp, struct ssh_string_s *data)
{
    struct sftp_supported_s *supported=&sftp->supported;
    unsigned int pos=0;
    unsigned int size=data->len;
    char *buff=data->ptr;

    if (size < 32) {

	logoutput_warning("read_default_features_v06: data too small (size=%i)", size);
	return;

    }

    supported->version.v06.attribute_mask=get_uint32(&buff[pos]);
    pos+=4;
    supported->version.v06.attribute_bits=get_uint32(&buff[pos]);
    pos+=4;
    supported->version.v06.open_flags=get_uint32(&buff[pos]);
    pos+=4;
    supported->version.v06.access_mask=get_uint32(&buff[pos]);
    pos+=4;
    supported->version.v06.max_read_size=get_uint32(&buff[pos]);
    pos+=4;
    supported->version.v06.open_block_vector=get_uint16(&buff[pos]);
    pos+=2;
    supported->version.v06.block_vector=get_uint16(&buff[pos]);
    pos+=2;
    supported->version.v06.attrib_extension_count=get_uint32(&buff[pos]);
    pos+=4;

    for (unsigned int i=0; i<supported->version.v06.attrib_extension_count; i++) {

	logoutput_debug("read_default_features_v06: %i pos %i size %i", i, pos, size);

	if (pos<size) {
	    struct ssh_string_s attrib;

	    init_ssh_string(&attrib);
	    pos+=read_ssh_string(&buff[pos], size-pos, &attrib);

	    if (attrib.len>0 && attrib.ptr) {

		logoutput_debug("read_default_features_v06: (%i - %i) found attrib extension %.*s", i, supported->version.v06.attrib_extension_count, attrib.len, attrib.ptr);

	    } else {

		goto error;

	    }

	} else {

	    goto error;

	}

    }

    supported->version.v06.extension_count=get_uint32(&buff[pos]);
    pos+=4;

    for (unsigned int i=0; i<supported->version.v06.extension_count; i++) {

	logoutput_debug("read_default_features_v06: %i pos %i size %i", i, pos, size);

	if (pos<size) {
	    struct ssh_string_s name;

	    init_ssh_string(&name);
	    pos+=read_ssh_string(&buff[pos], size-pos, &name);

	    if (name.len>0 && name.ptr) {
		struct sftp_protocolextension_s *extension=add_sftp_protocolextension(sftp, &name, NULL);

		if (extension) {

		    logoutput("read_default_features_v06: (%i - %i) found extension %.*s", i, supported->version.v06.extension_count, name.len, name.ptr);

		} else {

		    logoutput("read_default_features_v06: (%i - %i) extension %.*s not found", i, supported->version.v06.extension_count, name.len, name.ptr);

		}

	    } else {

		goto error;

	    }

	} else {

	    goto error;

	}

    }

    return;

    error:

    logoutput("read_default_features_v06: failed");


}

/*	process extensions part of the init verson message
	well known extensions are:
	- supported (used at version 5)
	- supported2 (used at version 6
	- acl-supported
	- text-seek
	- versions, version-select
	- filename-charset, filename-translation-control
	- newline
	- vendor-id
	- md5-hash. md5-hash-handle
	- check-file-handle, check-file-name
	- space-available
	- home-directory
	- copy-file, copy-data
	- get-temp-folder, make-temp-folder
	- */

static void process_sftp_extension(struct sftp_subsystem_s *sftp, struct ssh_string_s *name, struct ssh_string_s *data)
{

    if (compare_ssh_string(name, 'c', "newline")==0)  {

	logoutput("process_sftp_extension: received newline extension");

    } else if (compare_ssh_string(name, 'c', "supported")==0) {

	logoutput("process_sftp_extension: received supported extension");

    } else if (compare_ssh_string(name, 'c', "supported2")==0) {

	if (sftp->server_version>=6) {

	    read_default_features_v06(sftp, data);

	} else {

	    logoutput("process_sftp_extension: ignoring received supported2 extension (sftp version is %i, supported2 is used in version 6");

	}

    } else {

	logoutput("process_sftp_extension: ignoring received %.*s extension", name->len, name->ptr);

    }

}

/*

    for sftp init data looks like:

    - 4 bytes				len sftp packet excl this field l2
    - byte				sftp type
    - 4 bytes				sftp version server
    - extension-pair			extension[0..n]

    where one extension has the form:
    - string name
    - string data

    TODO: specific extensions handlers per version

*/

static int process_sftp_version(struct sftp_subsystem_s *sftp, char *buffer, unsigned int size)
{
    unsigned int len=0;
    unsigned int server_version=0;
    unsigned int pos=0;
    unsigned int name_len=0;
    unsigned int data_len=0;

    len=get_uint32(&buffer[pos]);

    if (len + 4 != size) {

	logoutput("process_sftp_version: length sftp init (%i + 4) not equal to size %i", len, size);
	return -1;

    }

    pos+=4;

    if ((unsigned char) buffer[pos] != SSH_FXP_VERSION) {

	logoutput("process_sftp_version: error received sftp %i, expecting %i", buffer[pos], SSH_FXP_VERSION);
	return -1;

    }

    pos++;
    server_version=get_uint32(&buffer[pos]);
    pos+=4;

    logoutput("process_sftp_version: received server sftp version %i", server_version);
    set_sftp_server_version(sftp, server_version);

    /* check there is enough space for 2 uint and minimal 1 name */

    while (pos + 9 < size) {
	struct ssh_string_s name;
	struct ssh_string_s data;

	init_ssh_string(&name);
	init_ssh_string(&data);

	pos+=read_ssh_string(&buffer[pos], size-pos, &name);
	if (name.ptr) {

	    logoutput("process_sftp_version: received extension %.*s", name.len, name.ptr);
	    pos+=read_ssh_string(&buffer[pos], size-pos, &data);
	    process_sftp_extension(sftp, &name, &data);

	}

    }

    return 0;

}

/*
    assign the sftp functions to use after version negotiation
    and the server has send the supported extensions

    - send
    - recv
    - extensions
    - attr

*/

static int set_sftp_protocol(struct sftp_subsystem_s *sftp)
{
    int result=-1;

    logoutput("set_sftp_protocol: use server version %i", sftp->server_version);

    if (sftp->server_version==3) {

	use_sftp_send_v03(sftp);
	use_sftp_recv_v03(sftp);
	use_sftp_attr_v03(sftp);
	result=3;

    } else if (sftp->server_version==4) {

	use_sftp_send_v04(sftp);
	use_sftp_recv_v04(sftp);
	use_sftp_attr_v04(sftp);
	result=4;

    } else if (sftp->server_version==5) {

	use_sftp_send_v05(sftp);
	use_sftp_recv_v05(sftp);
	use_sftp_attr_v05(sftp);
	result=5;

    } else if (sftp->server_version==6) {

	use_sftp_send_v06(sftp);
	use_sftp_recv_v06(sftp);
	use_sftp_attr_v06(sftp);
	result=6;

    } else {

	logoutput("set_sftp_protocol: version %i not supported", sftp->server_version);

    }

    if (result>0) (* sftp->attr_ops->read_sftp_features)(sftp);
    return result;

}
unsigned int get_sftp_version(struct sftp_subsystem_s *sftp)
{

    /* TODO ... */

    if (sftp && sftp->server_version>0) return sftp->server_version;
    return 6; /* preferred version */

}
unsigned int get_sftp_version_ctx(void *ptr)
{
    struct sftp_subsystem_s *sftp=(struct sftp_subsystem_s *) ptr;
    return get_sftp_version(sftp);
}
void set_sftp_server_version(struct sftp_subsystem_s *sftp, unsigned int version)
{
    sftp->server_version=version;
}
unsigned int get_sftp_request_id(struct sftp_subsystem_s *sftp)
{
    struct sftp_send_hash_s *send_hash=&sftp->send_hash;
    unsigned int id=0;

    pthread_mutex_lock(&send_hash->mutex);
    id=send_hash->sftp_request_id;
    send_hash->sftp_request_id++;
    pthread_mutex_unlock(&send_hash->mutex);
    return id;
}

void get_sftp_request_timeout(struct timespec *timeout)
{

    /* make this configurable */

    timeout->tv_sec=4;
    timeout->tv_nsec=0;

}

static int init_sftp_subsystem(struct sftp_subsystem_s *sftp, unsigned int *error)
{
    struct sftp_supported_s *supported=&sftp->supported;

    sftp->flags=0;
    sftp->status=0;
    sftp->refcount=0;
    sftp->server_version=0;

    memset(supported, 0, sizeof(struct sftp_supported_s));
    supported->fuse_attr_supported=0;
    init_sftp_extensions(sftp);

    sftp->send_ops=NULL;
    sftp->recv_ops=NULL;
    sftp->attr_ops=NULL;

    return init_send_hash(&sftp->send_hash, error);
}

static void clear_sftp_subsystem(struct sftp_subsystem_s *sftp)
{
    clear_ssh_channel(&sftp->channel);
    free_send_hash(&sftp->send_hash);
    clear_sftp_extensions(sftp);
    pthread_mutex_destroy(&sftp->mutex);
}

static void free_sftp_subsystem(struct sftp_subsystem_s *sftp)
{
    clear_sftp_subsystem(sftp);
    free(sftp);
}

static void remove_sftp_channel(struct ssh_channel_s *channel)
{
    struct sftp_subsystem_s *sftp=(struct sftp_subsystem_s *) (((char *) channel) - offsetof(struct sftp_subsystem_s, channel));

    remove_channel(channel, CHANNEL_FLAG_CLIENT_CLOSE | CHANNEL_FLAG_SERVER_CLOSE);
    clear_ssh_channel(channel);
    free_sftp_subsystem(sftp);
}

/* create a new sftp subsystem - it's basically a container of a channel */

static struct sftp_subsystem_s *new_sftp_subsystem(struct ssh_session_s *session, char *uri)
{
    struct sftp_subsystem_s *sftp=NULL;
    struct ssh_channel_s *channel=NULL;
    unsigned int error=0;

    sftp=malloc(sizeof(struct sftp_subsystem_s));

    if (sftp==NULL) {

	error=ENOMEM;
	goto error;

    }

    memset(sftp, 0, sizeof(struct sftp_subsystem_s));
    pthread_mutex_init(&sftp->mutex, NULL);
    init_ssh_string(&sftp->remote_home);
    channel=&sftp->channel;
    init_ssh_channel(session, session->connections.main, channel, _CHANNEL_TYPE_SFTP_SUBSYSTEM);
    channel->free=remove_sftp_channel;

    if (uri) {

	logoutput("new_sftp_subsystem: translating uri %s to channel", uri);
	if (translate_channel_uri(channel, uri, &error)==-1) goto error;

    }

    logoutput("new_sftp_subsystem: initializing sftp");
    if (init_sftp_subsystem(sftp, &error)==-1) goto error;
    return sftp;

    error:

    logoutput("new_sftp_subsystem: error %i initializing sftp subsystem (%s)", error, strerror(error));

    clear_sftp_subsystem(sftp);
    free(sftp);
    sftp=NULL;
    return NULL;

}

/*	callback when the backend (=sftp_subsystem) is "unmounted" by fuse
	this callback is used for the "main" interface pointing to the home
	directory on the server */

void signal_sftp_interface(struct context_interface_s *interface, const char *what)
{
    struct sftp_subsystem_s *sftp=(struct sftp_subsystem_s *) interface->ptr;

    logoutput("signal_sftp_interface: what %s", what);

    if (sftp==NULL) return;

    if (strcmp(what, "disconnecting")==0) {


    } else if (strcmp(what, "close")==0) {

    } else if (strcmp(what, "free")==0) {
	struct ssh_channel_s *channel=NULL;

	if (interface->backend.sftp.prefix.path) {

	    free(interface->backend.sftp.prefix.path);
	    interface->backend.sftp.prefix.path=NULL;
	    interface->backend.sftp.prefix.len=0;

	}

	channel=&sftp->channel;

	pthread_mutex_lock(&sftp->mutex);
	sftp->refcount--;
	if (sftp->refcount==0) remove_channel(&sftp->channel, CHANNEL_FLAG_CLIENT_CLOSE);
	pthread_mutex_unlock(&sftp->mutex);

	if (sftp->refcount==0) {

	    logoutput("signal_sftp_interface: refcount sftp zero");
	    clear_sftp_subsystem(sftp);
	    free(sftp);

	}

	interface->ptr=NULL;

    }

}

static int get_sftp_server_type_info(struct ssh_session_s *session, char *name, char **prefix, char **uri)
{
    struct common_buffer_s buffer;
    char *sep=NULL;
    char *pos=NULL;
    unsigned int left=0;

    /* get prefix from server and optional the socket */

    init_common_buffer(&buffer);

    if (get_sftp_sharedmap(session, name, &buffer)==0) {

	logoutput("get_sftp_server_type_info: no prefix found for %s", name);
	return -1;

    }

    /* 	output looks like:

	when dealing with sftp server using socket and reachable through direct-streamlocal:
	/home/public|socket://run/bfileserver/sock|software-version

	when dealing with a sftp-subsystem the second part is empty
	/home/public:
    */

    pos=buffer.ptr;
    left=buffer.size;
    sep=memchr(pos, '|', left);
    if (! sep) goto error;

    *sep='\0';
    *prefix=strdup(pos);
    if (! *prefix) goto error;

    *sep='|';
    left-=(sep + 1 - pos);
    pos=sep+1;

    /* get the optional uri */

    sep=memchr(pos, '|', left);
    if (sep==NULL) goto out;

    *sep='\0';
    *uri=strdup(pos);
    if (! *uri) goto error;

    *sep='|';
    pos=sep+1;
    left-=(sep + 1 - pos);

    if (buffer.ptr) free(buffer.ptr);

    out:

    return 0;

    error:

    if (buffer.ptr) free(buffer.ptr);

    if (*prefix) {

	free(*prefix);
	*prefix=NULL;

    }

    if (*uri) {

	free(*uri);
	*uri=NULL;

    }

    return -1;

}

/* create a new sftp subsystem using existing interface to a ssh server */

int connect_sftp_common(uid_t uid, struct context_interface_s *interface, struct context_address_s *address, unsigned int *error)
{
    struct context_interface_s *ssh_interface=NULL;
    struct ssh_session_s *session=NULL;
    struct sftp_subsystem_s *sftp_subsystem=NULL;
    struct ssh_channel_s *channel=NULL;
    struct channel_table_s *table=NULL;
    struct simple_lock_s rlock;
    char *prefix=NULL;
    char *uri=NULL;
    unsigned char type=0;

    logoutput("connect_sftp_common");

    if (! interface) {

	logoutput_warning("connect_sftp_common: interface not defined");
	*error=EINVAL;
	return -1;

    }

    ssh_interface=(* interface->get_parent)(interface);

    if (! ssh_interface) {

	logoutput("connect_sftp_common: parent interface not defined");
	*error=EINVAL;
	return -1;

    }

    session=(struct ssh_session_s *) ssh_interface->ptr;

    if (! session) {

	logoutput("connect_sftp_common: session not defined");
	*error=EINVAL;
	return -1;

    }

    if (! address) {

	logoutput("connect_sftp_common: address not defined");
	*error=EINVAL;
	return -1;

    }

    if (address->service.type != _INTERFACE_SERVICE_SFTP || strlen(address->service.target.sftp.name)==0) {

	logoutput("connect_sftp_common: service wrong format");
	*error=EINVAL;
	return -1;

    }

    /* get the full prefix and the method to connect:
	- remote sftp server listens to local unix socket
	- remote sftp server listens to network address
	- remote sftp server as subsystem of ssh */

    if (get_sftp_server_type_info(session, address->service.target.sftp.name, &prefix, &uri)==0) {

	if (uri) {

	    logoutput("connect_sftp_common: found prefix %s uri %s", prefix, uri);
	    type=get_channel_type_uri(uri);

	    if (type==0) {

		logoutput("connect_sftp_common: found uri %s not reckognized", uri);
		*error=EINVAL;
		goto error;

	    }

	} else {

	    /* no uri: just the normal sftp subsystem*/

	    logoutput("connect_sftp_common: found prefix %s", prefix);
	    type=_CHANNEL_TYPE_SFTP_SUBSYSTEM;

	}

    } else {

	logoutput("connect_sftp_common: no sftp server info received");
	type=_CHANNEL_TYPE_SFTP_SUBSYSTEM;

    }

    table=&session->channel_table;
    channeltable_readlock(table, &rlock);

    channel=get_next_channel(session, NULL);
    while (channel) {

	if (channel->type==type) {

	    if (type==_CHANNEL_TYPE_SFTP_SUBSYSTEM) {

		break;

	    } else {

		if (reverse_check_channel_uri(channel, uri)==0) break;

	    }

	}

	channel=get_next_channel(session, channel);

    }

    if (channel==NULL) {

	/* create new */

	sftp_subsystem=new_sftp_subsystem(session, uri);

	if (sftp_subsystem) {

	    channel=&sftp_subsystem->channel;

	    channeltable_upgrade_readlock(table, &rlock);
	    table_add_channel(channel);
	    channeltable_unlock(table, &rlock);

	    sftp_subsystem->status=SFTP_STATUS_INIT;
	    sftp_subsystem->refcount=1;
	    interface->signal_interface=signal_sftp_interface;

	    if (start_channel(channel, error)==-1) {

		logoutput("connect_sftp_common: unable to start channel for sftp subsystem");
		pthread_mutex_unlock(&channel->mutex);
		goto error;

	    }

	} else {

	    channeltable_unlock(table, &rlock);
	    logoutput("connect_sftp_common: no sftp subsystem created");
	    goto error;

	}

    } else {

	/* existing channel found */

	sftp_subsystem=(struct sftp_subsystem_s *) (((char *) channel) - offsetof(struct sftp_subsystem_s, channel));
	sftp_subsystem->refcount++;
	channeltable_unlock(table, &rlock);

    }

    if (sftp_subsystem) {

	interface->ptr=(void *) sftp_subsystem;

	if (strcmp(address->service.target.sftp.name, "home")==0) {

	    /* the remote folder is the home directory of the connecting user
		- paths startiing without slash are relative to home */

	    logoutput("connect_sftp_common: home, name is %s", address->service.target.sftp.name);

	    interface->backend.sftp.complete_path=complete_path_sftp_home;
	    interface->backend.sftp.get_complete_pathlen=get_complete_pathlen_home;
	    interface->backend.sftp.prefix.type=CONTEXT_INTERFACE_BACKEND_SFTP_PREFIX_HOME;
	    interface->backend.sftp.prefix.path=NULL;
	    interface->backend.sftp.prefix.len=0;

	    if (prefix) {

		free(prefix);
		prefix=NULL;

	    }

	} else if (prefix==NULL || strlen(prefix)==0) {

	    logoutput("connect_sftp_common: root, prefix is empty");

	    interface->backend.sftp.complete_path=complete_path_sftp_root;
	    interface->backend.sftp.get_complete_pathlen=get_complete_pathlen_root;
	    interface->backend.sftp.prefix.type=CONTEXT_INTERFACE_BACKEND_SFTP_PREFIX_ROOT;
	    interface->backend.sftp.prefix.path=NULL;
	    interface->backend.sftp.prefix.len=0;

	    if (prefix) {

		free(prefix);
		prefix=NULL;

	    }

	} else {

	    /* custom prefix */

	    logoutput("connect_sftp_common: custom, using prefix %s", prefix);

	    interface->backend.sftp.complete_path=complete_path_sftp_custom;
	    interface->backend.sftp.get_complete_pathlen=get_complete_pathlen_custom;
	    interface->backend.sftp.prefix.type=CONTEXT_INTERFACE_BACKEND_SFTP_PREFIX_CUSTOM;
	    interface->backend.sftp.prefix.path=prefix;
	    interface->backend.sftp.prefix.len=strlen(prefix);

	    prefix=NULL;

	}

	interface->backend.sftp.flags=0;
	interface->backend.sftp.ptr_statfs=0;
	interface->backend.sftp.ptr_fsync=0;

    } else {

	if (prefix) {

	    free(prefix);
	    prefix=NULL;

	}

    }


    if (uri) {

	free(uri);
	uri=NULL;

    }


    return 0;

    error:

    if (interface->backend.sftp.prefix.path) {

	free(interface->backend.sftp.prefix.path);
	interface->backend.sftp.prefix.path=NULL;
	interface->backend.sftp.prefix.len=0;

    }

    if (prefix) {

	free(prefix);
	prefix=NULL;

    }

    if (channel) {

	remove_sftp_channel(channel);
	channel=NULL;

    }

    return -1;

}

static int _start_sftp_common(struct context_interface_s *interface)
{
    struct sftp_subsystem_s *sftp_subsystem=(struct sftp_subsystem_s *) interface->ptr;
    struct ssh_channel_s *channel=&sftp_subsystem->channel;
    struct ssh_connection_s *connection=channel->connection;
    struct ssh_session_s *session=channel->session;
    struct channel_table_s *table=&session->channel_table;
    unsigned int seq=0;
    struct fuse_sftp_attr_s attr;
    unsigned int lenreaddir=0;

    logoutput("_start_sftp_common: channel %i session %i", channel->local_channel, session->config.unique);

    if (channel->type==_CHANNEL_TYPE_SFTP_SUBSYSTEM) {
	struct ssh_payload_s *payload=NULL;

	/* start the sftp subsystem on the channel
	    only required for the default sftp subsytem */

	logoutput("_start_sftp_common: send start sftp subsystem");

	if (send_start_command_message(channel, "subsystem", "sftp", 1, &seq)==0) {
	    struct timespec expire;
	    unsigned int error=0;

	    get_channel_expire_init(channel, &expire);
	    payload=get_ssh_payload_channel(channel, &expire, NULL, &error);

	    if (! payload) {

		logoutput("_start_sftp_common: error waiting for packet");
		goto error;

	    }

	    if (payload->type==SSH_MSG_CHANNEL_SUCCESS) {

		/* ready: channel ready to use */

		logoutput("_start_sftp_common: server started sftp");

	    } else if (payload->type==SSH_MSG_CHANNEL_FAILURE) {

		logoutput("_start_sftp_common: server failed to start sftp");
		free_payload(&payload);
		goto error;

	    } else {

		logoutput("_start_sftp_common: got unexpected reply %i", payload->type);
		free_payload(&payload);
		goto error;

	    }

	    free_payload(&payload);

	} else {

	    logoutput("_start_sftp_common: error sending sftp subsystem request");
	    goto error;

	}

    }

    logoutput("_start_sftp_common: send sftp init");
    set_sftp_server_version(sftp_subsystem, 6);
    set_sftp_protocol(sftp_subsystem);
    init_fuse_sftp_extensions(interface);

    /* start the sftp init negotiation */

    if ((* sftp_subsystem->send_ops->init)(sftp_subsystem, &seq)==0) {
	struct ssh_payload_s *payload=NULL;
	struct timespec expire;
	unsigned int error=0;

	get_channel_expire_init(channel, &expire);
	payload=get_ssh_payload_channel(channel, &expire, NULL, &error);

	if (! payload) {

	    logoutput("start_sftp_subsystem: error waiting for packet");
	    goto error;

	}

	/* wait for a SSH_MSG_CHANNEL_DATA message */

	if (payload->type==SSH_MSG_CHANNEL_DATA) {

	    /*
		payload should be at least:
		- 1 byte				SSH_MSG_CHANNEL_DATA
		- 4 bytes				recipient channel
		- 4 bytes				len data l1
		- bytes[l1]				data

	    */

	    if (process_sftp_version(sftp_subsystem, payload->buffer + 9, payload->len - 9)==0) {

		logoutput("_start_sftp_subsystem: server sftp version processed");

	    } else {

		logoutput("_start_sftp_subsystem: error processing server sftp init");
		free_payload(&payload);
		goto error;

	    }

	} else {

	    logoutput("_start_sftp_subsystem: unexpected message from server: %i", payload->type);
	    free_payload(&payload);
	    goto error;

	}

	free_payload(&payload);
	payload=NULL;

    } else {

	logoutput("_start_sftp_subsystem: error sending sftp init");
	goto error;

    }

    if (set_sftp_protocol(sftp_subsystem)==-1) {

	logoutput("_start_sftp_subsystem: error setting version");
	goto error;

    }

    /* connect the data transfer with the sftp subssytem */

    switch_channel_receive_data(channel, "subsystem", receive_sftp_reply);

    if (table) {

	if (table->shell) clean_ssh_channel_queue(table->shell);

    } else {

	logoutput("_start_sftp_subsystem: table not defined");

    }

    if (init_time_correction(interface, sftp_subsystem)>0) {

	get_timeinfo_sftp_server(sftp_subsystem);

    }

    if (init_sftp_usermapping(interface, sftp_subsystem)==0) {

	logoutput("_start_sftp_subsystem: initialized sftp usermapping");

    } else {

	logoutput("_start_sftp_subsystem: failed initializing sftp usermapping");
	goto error;

    }

    /* get sftp info */

    memset(&attr, 0, sizeof(struct fuse_sftp_attr_s));
    if (test_valid_sftp_readdir(interface, (void *)&attr, &lenreaddir)==0) {

	if (attr.type > 0 && (attr.received & (FUSE_SFTP_INDEX_SIZE | FUSE_SFTP_INDEX_PERMISSIONS | FUSE_SFTP_INDEX_MTIME | FUSE_SFTP_INDEX_CTIME | FUSE_SFTP_INDEX_USER | FUSE_SFTP_INDEX_GROUP))) {

	    logoutput("_start_sftp_subsystem: received enough to use readdirplus");
	    sftp_subsystem->flags |= SFTP_SUBSYSTEM_FLAG_READDIRPLUS;

	} else {

	     logoutput("_start_sftp_subsystem: not received enough to use readdirplus");

	}

	if (lenreaddir<=54) {

	    logoutput("_start_sftp_subsystem: found readdir length %i, old style", lenreaddir);

	} else {

	    logoutput("_start_sftp_subsystem: found readdir length %i, new style", lenreaddir);
	    sftp_subsystem->flags |= SFTP_SUBSYSTEM_FLAG_NEWREADDIR;

	}

    }

    complete_fuse_sftp_extensions(interface);

    return 0;

    error:

    if (channel) remove_sftp_channel(channel);
    interface->ptr=NULL;
    return -1;

}

int start_sftp_common(struct context_interface_s *interface, int fd, void *data)
{
    struct sftp_subsystem_s *sftp_subsystem=NULL;

    logoutput("start_sftp_common");

    if (! interface->ptr) {

	/* ptr must have a value
	    ptr is assigned when connecting */

	return -1;

    }

    sftp_subsystem=(struct sftp_subsystem_s *) interface->ptr;

    if (sftp_subsystem->status==SFTP_STATUS_INIT) {

	if (_start_sftp_common(interface)==0) {

	    logoutput("start_sftp_common: sftp started");
	    sftp_subsystem->status=SFTP_STATUS_UP;

	} else {

	    logoutput("start_sftp_common: error starting sftp");
	    return -1;

	}

    }

    return 0;

}

unsigned char get_sftp_features(void *ptr)
{
    struct sftp_subsystem_s *sftp=(struct sftp_subsystem_s *) ptr;
    struct sftp_supported_s *supported=&sftp->supported;
    return (supported->fuse_attr_supported);
}
