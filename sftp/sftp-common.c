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
#include <sys/vfs.h>

#include "main.h"
#include "logging.h"
#include "pathinfo.h"
#include "utils.h"
#include "workerthreads.h"

#include "workspace-interface.h"
#include "ssh-common-protocol.h"
#include "ssh-common.h"
#include "ssh-common-list.h"
#include "ssh-channel.h"
#include "ssh-channel-utils.h"
#include "ssh-admin-channel.h"
#include "ssh-utils.h"

#include "ssh-send-channel.h"
#include "ssh-receive-channel.h"

#include "sftp-common-protocol.h"
#include "sftp-common.h"
#include "sftp-common-admin.h"
#include "sftp-common-utils.h"

#include "sftp-request-hash.h"

#include "sftp-attr-common.h"
#include "sftp-attr-v03.h"
#include "sftp-attr-v04.h"
#include "sftp-attr-v05.h"
#include "sftp-attr-v06.h"

#include "sftp-recv-common.h"
#include "sftp-recv-v03.h"
#include "sftp-recv-v04.h"
#include "sftp-recv-v05.h"
#include "sftp-recv-v06.h"

#include "sftp-send-common.h"
#include "sftp-send-v03.h"
#include "sftp-send-v04.h"
#include "sftp-send-v05.h"
#include "sftp-send-v06.h"

#include "sftp-usermapping.h"

extern void set_fallback_statfs_sftp(struct statfs *fallback);

static void read_supported_extension(struct sftp_subsystem_s *sftp, char *name, char *data)
{
    struct sftp_supported_s *supported=&sftp->supported;

    if (strcmp(name, "statvfs@openssh.com")==0) {

	supported->extensions |= FUSE_SFTP_EXT_STATVFS_OPENSSH_COM;

    } else if (strcmp(name, "fstatvfs@openssh.com")==0) {

	supported->extensions |= FUSE_SFTP_EXT_FSTATVFS_OPENSSH_COM;

    } else if (strcmp(name, "posix-rename@openssh.com")==0) {

	supported->extensions |= FUSE_SFTP_EXT_POSIXRENAME_OPENSSH_COM;

    } else if (strcmp(name, "hardlink@openssh.com")==0) {

	supported->extensions |= FUSE_SFTP_EXT_HARDLINK_OPENSSH_COM;

    } else if (strcmp(name, "fsync@openssh.com")==0) {

	supported->extensions |= FUSE_SFTP_EXT_FSYNC_OPENSSH_COM;

    } else if (strcmp(name, "fsnotify@bononline.nl")==0) {

	supported->extensions |= FUSE_SFTP_EXT_FSNOTIFY_BONONLINE_NL;

    }

}

static void read_default_features_v06(struct sftp_subsystem_s *sftp, char *data, unsigned int len)
{
    struct sftp_supported_s *supported=&sftp->supported;
    unsigned int pos=0;

    if (pos + 4 < len) {

	supported->version.v06.attribute_mask=get_uint32(&data[pos]);

	logoutput("read_default_features_v06: attribute mask %i", supported->version.v06.attribute_mask);

    } else { 

	logoutput("read_default_features_v06: error reading attribute mask");

    }

}

/*
    process extensions like statvfs@openssh.com
*/

static void process_sftp_extension(struct sftp_subsystem_s *sftp, char *name, unsigned int name_len, char *data, unsigned int data_len)
{
    logoutput("process_sftp_extension: found extension %s", name);

    if (sftp->server_version==6) {

	if (strcmp(name, "supported2")==0) {

	    read_default_features_v06(sftp, data, data_len);
	    return;

	}

    }

    read_supported_extension(sftp, name, data);
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

static int process_sftp_version(struct sftp_subsystem_s *sftp, unsigned char *buffer, unsigned int size)
{
    unsigned int len=0;
    unsigned int server_version=0;
    unsigned int pos=0;
    unsigned int name_len=0;
    unsigned int data_len=0;
    char name[size-4];
    char data[size-4];

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

	/* read the extention */

	memset(name, '\0', size-4);
	memset(data, '\0', size-4);

	/* name */

	name_len=get_uint32(&buffer[pos]);
	pos+=4;
	memcpy(name, &buffer[pos], name_len);
	pos+=name_len;

	/* data */

	data_len=get_uint32(&buffer[pos]);
	pos+=4;

	if (data_len>0) {

	    memcpy(data, &buffer[pos], data_len);
	    pos+=data_len;

	}

	process_sftp_extension(sftp, name, name_len, data, data_len);

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

void set_sftp_protocol(struct sftp_subsystem_s *sftp_subsystem)
{

    logoutput("set_sftp_protocol: use version %i and extensions %i", sftp_subsystem->server_version, sftp_subsystem->supported.extensions);

    if (sftp_subsystem->server_version==3) {

	use_sftp_send_v03(sftp_subsystem);
	use_sftp_recv_v03(sftp_subsystem);
	use_sftp_attr_v03(sftp_subsystem);

    } else if (sftp_subsystem->server_version==4) {

	use_sftp_send_v04(sftp_subsystem);
	use_sftp_recv_v04(sftp_subsystem);
	use_sftp_attr_v04(sftp_subsystem);

    } else if (sftp_subsystem->server_version==5) {

	use_sftp_send_v05(sftp_subsystem);
	use_sftp_recv_v05(sftp_subsystem);
	use_sftp_attr_v05(sftp_subsystem);

    } else if (sftp_subsystem->server_version==6) {

	use_sftp_send_v06(sftp_subsystem);
	use_sftp_recv_v06(sftp_subsystem);
	use_sftp_attr_v06(sftp_subsystem);

    } else {

	logoutput("set_sftp_protocol: version not supported");
	return;

    }

    (* sftp_subsystem->attr_ops->read_sftp_features)(sftp_subsystem);

}

unsigned int get_sftp_version(struct sftp_subsystem_s *sftp)
{

    /* TODO ... */

    return 6;

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

    sftp->status=0;
    sftp->refcount=0;
    sftp->client_version=0;
    sftp->server_version=0;

    memset(supported, 0, sizeof(struct sftp_supported_s));
    supported->extensions=0;
    supported->fuse_attr_supported=0;

    sftp->send_ops=NULL;
    sftp->recv_ops=NULL;
    sftp->attr_ops=NULL;

    return init_send_hash(&sftp->send_hash, error);

}

static void clear_sftp_subsystem(struct sftp_subsystem_s *sftp)
{
    free_send_hash(&sftp->send_hash);
}

static void free_sftp_subsystem(struct sftp_subsystem_s *sftp_subsystem)
{
    struct ssh_channel_s *channel=&sftp_subsystem->channel;
    struct ssh_session_s *session=channel->session;
    struct channel_table_s *table=&session->channel_table;

    logoutput("free_sftp_subsystem");

    clear_sftp_subsystem(sftp_subsystem);
    free(sftp_subsystem);
    sftp_subsystem=NULL;

}

static void remove_sftp_channel(struct ssh_channel_s *channel)
{
    struct sftp_subsystem_s *sftp=(struct sftp_subsystem_s *) (((char *) channel) - offsetof(struct sftp_subsystem_s, channel));
    struct ssh_session_s *session=channel->session;

    remove_channel_table_locked(session, channel, 0);
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

    channel=&sftp->channel;
    channel->type=_CHANNEL_TYPE_SFTP_SUBSYSTEM; /* default */
    channel->session=session;
    init_ssh_channel(channel);
    channel->free=remove_sftp_channel;

    if (uri) {

	if (translate_channel_uri(channel, uri, &error)==-1) goto error;

    }

    if (init_sftp_subsystem(sftp, &error)==-1) goto error;

    return sftp;

    error:

    logoutput("new_sftp_subsystem: error %i initializing sftp subsystem (%s)", error, strerror(error));

    pthread_mutex_destroy(&channel->mutex);
    free_sftp_subsystem(sftp);
    sftp=NULL;

    return NULL;

}

/*	callback when the backend (=sftp_subsystem) is "unmounted" by fuse
	this callback is used for the "main" interface pointing to the home
	directory on the server */

void umount_sftp_subsystem(struct context_interface_s *interface)
{
    struct sftp_subsystem_s *sftp_subsystem=NULL;
    struct ssh_channel_s *channel=NULL;
    struct ssh_session_s *session=NULL;
    struct channel_table_s *table=NULL;

    if (interface->backend.sftp.prefix.path) {

	free(interface->backend.sftp.prefix.path);
	interface->backend.sftp.prefix.path=NULL;
	interface->backend.sftp.prefix.len=0;

    }

    if (interface->ptr==NULL) return;

    sftp_subsystem=(struct sftp_subsystem_s *) interface->ptr;
    channel=&sftp_subsystem->channel;
    session=channel->session;
    table=&session->channel_table;

    logoutput("umount_sftp_subsystem");

    // pthread_mutex_lock(&table->mutex);

    /* which lock ??*/

    sftp_subsystem->refcount--;
    if (sftp_subsystem->refcount==0) remove_sftp_channel(&sftp_subsystem->channel);

    // pthread_mutex_unlock(&table->mutex);

    interface->ptr=NULL;

}

static int get_sftp_server_type_info(struct ssh_session_s *session, char *name, char **prefix, char **uri)
{
    char buffer[1024];
    char *pos=NULL;
    char *sep=NULL;
    unsigned int error=0;

    /* get prefix from server and optional the socket */

    memset(buffer, '\0', 1024);

    if (get_sftp_sharedmap(session, name, buffer, 1024, &error)==0) {

	logoutput("get_sftp_server_type_info: no prefix found for %s", name);
	return -1;

    }

    /* 	output looks like:

	when dealing with sftp server using socket and reachable through direct-streamlocal:
	/home/public|socket://run/bfileserver/sock|software-version

	when dealing with a sftp-subsystem the second part is empty
	/home/public:
    */

    pos=buffer;
    sep=memchr(pos, '|', 1024);
    if (! sep) return -1;

    *sep='\0';
    *prefix=strdup(pos);
    if (! *prefix) return -1;

    *sep='|';
    pos=sep+1;

    /* get the optional uri */

    sep=memchr(pos, '|', buffer + 1024 - pos);
    if (sep==NULL) return 0;

    *sep='\0';
    *uri=strdup(pos);
    if (! *uri) goto error;

    *sep='|';
    pos=sep+1;

    return 0;

    error:

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

void *connect_sftp_common(uid_t uid, struct context_interface_s *interface, struct context_address_s *address, unsigned int *error)
{
    struct context_interface_s *ssh_interface=NULL;
    struct ssh_session_s *session=NULL;
    struct sftp_subsystem_s *sftp_subsystem=NULL;
    struct ssh_channel_s *channel=NULL;
    struct channel_table_s *table=NULL;
    char *prefix=NULL;
    char *uri=NULL;
    unsigned char type=0;

    logoutput("connect_sftp_common");

    if (! interface) {

	*error=EINVAL;
	return NULL;

    }

    ssh_interface=(* interface->get_parent)(interface);

    if (! ssh_interface) {

	*error=EINVAL;
	return NULL;

    }

    session=(struct ssh_session_s *) ssh_interface->ptr;

    if (! session) {

	*error=EINVAL;
	return NULL;

    }

    if (! address) {

	*error=EINVAL;
	return NULL;

    }

    if (address->type!=_INTERFACE_SFTP_SERVER || address->target.sftp.name==NULL) {

	*error=EINVAL;
	return NULL;

    }

    /* get the full prefix and the method to connect:
	- sftp server listens to socket
	- sftp server listens to ip address
	- sftp server as subsystem of ssh */

    if (get_sftp_server_type_info(session, address->target.sftp.name, &prefix, &uri)==0) {

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

	logoutput("connect_sftp_common: error getting sftp server info");
	*error=EIO;
	goto error;

    }

    table=&session->channel_table;

    /* protect the handling of adding/removing channels */

    pthread_mutex_lock(&table->mutex);

    while (table->lock & TABLE_LOCK_LOCKED) {

	pthread_cond_wait(&table->cond, &table->mutex);

    }

    table->lock|=TABLE_LOCK_OPENCHANNEL;
    pthread_mutex_unlock(&table->mutex);

    /* check the channel to the same target does already exist
	TODO: depending on the subsystem */

    for (unsigned int i=0; i<table->table_size; i++) {
	struct list_element_s *list=NULL;

	list=table->hash[i].head;

	while (list) {

	    channel=get_containing_channel(list);

	    if (channel->type==type) {

		if (type==_CHANNEL_TYPE_SFTP_SUBSYSTEM) {

		    goto found;

		} else {

		    if (reverse_check_channel_uri(channel, uri)==0) goto found;

		}

	    }

	    list=list->next;
	    channel=NULL;

	}

    }

    found:

    pthread_mutex_lock(&table->mutex);

    if (channel) {

	/* existing sftp found */

	sftp_subsystem=(struct sftp_subsystem_s *) (((char *) channel) - offsetof(struct sftp_subsystem_s, channel));
	sftp_subsystem->refcount++;

    } else {

	/* create new */

	sftp_subsystem=new_sftp_subsystem(session, uri);

	if (sftp_subsystem) {

	    add_channel_table(&sftp_subsystem->channel);
	    sftp_subsystem->status=SFTP_STATUS_INIT;
	    sftp_subsystem->refcount=1;
	    interface->free=umount_sftp_subsystem;

	}

    }

    if (table->lock & TABLE_LOCK_OPENCHANNEL) {

	/* release the lock */

	table->lock -= TABLE_LOCK_OPENCHANNEL;
	pthread_cond_broadcast(&table->cond);

    }

    if (sftp_subsystem) {

	if (prefix==NULL || strlen(prefix)==0) {

	    interface->backend.sftp.complete_path=complete_path_sftp_root;
	    interface->backend.sftp.get_complete_pathlen=get_complete_pathlen_root;
	    interface->backend.sftp.prefix.path=NULL;
	    interface->backend.sftp.prefix.len=0;

	    if (prefix) {

		free(prefix);
		prefix=NULL;

	    }

	} else if (strcmp(address->target.sftp.name, "home")==0) {

	    interface->backend.sftp.complete_path=complete_path_sftp_home;
	    interface->backend.sftp.get_complete_pathlen=get_complete_pathlen_home;
	    interface->backend.sftp.prefix.path=NULL;
	    interface->backend.sftp.prefix.len=0;

	    free(prefix);
	    prefix=NULL;

	} else {

	    interface->backend.sftp.complete_path=complete_path_sftp_custom;
	    interface->backend.sftp.get_complete_pathlen=get_complete_pathlen_custom;
	    interface->backend.sftp.prefix.path=prefix;
	    interface->backend.sftp.prefix.len=strlen(prefix);

	    prefix=NULL;

	}

    } else {

	if (prefix) {

	    free(prefix);
	    prefix=NULL;

	}

    }

    pthread_mutex_unlock(&table->mutex);

    if (uri) {

	free(uri);
	uri=NULL;

    }

    if (channel==NULL && sftp_subsystem) {

	/* no existing channel found start the channel */

	channel=&sftp_subsystem->channel;

	if (start_new_channel(channel)==0) {

	    logoutput("connect_sftp_common: started channel for sftp subsystem");

	} else {

	    logoutput("connect_sftp_common: unable to start channel for sftp subsystem");
	    goto error;

	}

    }

    return (void *) sftp_subsystem;

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

    return NULL;

}

static int _start_sftp_common(struct context_interface_s *interface)
{
    struct sftp_subsystem_s *sftp_subsystem=(struct sftp_subsystem_s *) interface->ptr;
    struct ssh_channel_s *channel=&sftp_subsystem->channel;
    struct ssh_session_s *session=channel->session;
    struct channel_table_s *table=&session->channel_table;
    unsigned int seq=0;

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

		if (session->status.error==0) session->status.error=(error>0) ? error : EIO;
		logoutput("_start_sftp_common: error %i waiting for packet (%s)", session->status.error, strerror(session->status.error));
		goto error;

	    }

	    if (payload->type==SSH_MSG_CHANNEL_SUCCESS) {

		/* ready: channel ready to use */

		logoutput("_start_sftp_common: server started sftp");

	    } else if (payload->type==SSH_MSG_CHANNEL_FAILURE) {

		logoutput("_start_sftp_common: server failed to start sftp");
		free(payload);
		goto error;

	    } else {

		logoutput("_start_sftp_common: got unexpected reply %i", payload->type);
		free(payload);
		goto error;

	    }

	    free(payload);
	    payload=NULL;

	} else {

	    logoutput("_start_sftp_common: error sending sftp subsystem request");
	    goto error;

	}

    }

    /* start the sftp init negotiation */

    logoutput("_start_sftp_common: send sftp init");
    set_sftp_server_version(sftp_subsystem, 6);
    set_sftp_protocol(sftp_subsystem);

    if ((* sftp_subsystem->send_ops->init)(sftp_subsystem, &seq)==0) {
	struct ssh_payload_s *payload=NULL;
	struct timespec expire;
	unsigned int error=0;

	get_channel_expire_init(channel, &expire);
	payload=get_ssh_payload_channel(channel, &expire, NULL, &error);

	if (! payload) {

	    if (session->status.error==0) session->status.error=(error>0) ? error : EIO;
	    logoutput("start_sftp_subsystem: error %i waiting for packet (%s)", session->status.error, strerror(session->status.error));
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
		if (session->status.error==0) session->status.error=EIO;
		free(payload);
		goto error;

	    }

	} else {

	    logoutput("_start_sftp_subsystem: unexpected message from server: %i", payload->type);
	    free(payload);
	    goto error;

	}

	free(payload);
	payload=NULL;

    } else {

	logoutput("_start_sftp_subsystem: error sending sftp init");
	goto error;

    }

    set_sftp_protocol(sftp_subsystem);

    if (statfs_support(sftp_subsystem)==0) {
	struct statfs local_statfs;

	/* TODO:
	    since a channel to run commands remote is available get the default values via a remote statfs */

	if (statfs("/", &local_statfs)==-1) {

	    local_statfs.f_blocks=1000000;
	    local_statfs.f_bfree=1000000;
	    local_statfs.f_bavail=local_statfs.f_bfree;
	    local_statfs.f_bsize=4096;

	}

	set_fallback_statfs_sftp(&local_statfs);

    }

    /* connect the data transfer with the sftp subssytem */

    switch_channel_receive_data(channel, "subsystem", receive_sftp_reply);

    /* get basic info from server like time */

    clean_ssh_channel_queue(table->admin);
    get_timeinfo_sftp_server(sftp_subsystem);

    if (init_sftp_usermapping(sftp_subsystem)==0) {

	logoutput("_start_sftp_subsystem: initialized sftp usermapping");

    } else {

	logoutput("_start_sftp_subsystem: failed initializing sftp usermapping");
	goto error;

    }

    return 0;

    error:

    if (channel) remove_sftp_channel(channel);
    interface->ptr=NULL;
    return -1;

}

int start_sftp_common(struct context_interface_s *interface, void *data)
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

unsigned char statfs_support(struct sftp_subsystem_s *sftp)
{
    return (sftp->supported.extensions & FUSE_SFTP_EXT_STATVFS_OPENSSH_COM) ? 1 : 0;
}
