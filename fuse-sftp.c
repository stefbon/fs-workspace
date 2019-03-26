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
#include <sys/stat.h>
#include <sys/syscall.h>

#ifndef ENOATTR
#define ENOATTR ENODATA        /* No such attribute */
#endif

#define LOGGING
#include "logging.h"

#include "main.h"
#include "pathinfo.h"
#include "common-utils/utils.h"
#include "fuse-dentry.h"
#include "fuse-directory.h"
#include "fuse-utils.h"
#include "fuse-fs.h"

#include "workspaces.h"
#include "workspace-context.h"
#include "workspace-interface.h"

#include "path-caching.h"
#include "options.h"

#include "ssh/ssh-utils.h"

#include "fuse-fs-common.h"
#include "fuse-fs-virtual.h"
#include "fuse-fs-special.h"
#include "fuse-context-fs-root.h"
#include "fuse-network.h"
#include "fuse-backup.h"

#define _SFTP_NETWORK_NAME			"SFTP_Network"
#define _SFTP_HOME_MAP				"home"

extern struct fs_options_s fs_options;

extern void init_ssh_interface(struct context_interface_s *interface);
extern void init_sftp_filesystem_context(struct service_context_s *context);

/* callback for the ssh/sftp backend to get options from fs-workspace */

static unsigned int get_ssh_context_option(struct context_interface_s *interface, const char *name, struct context_option_s *option)
{
    struct service_context_s *context=get_service_context(interface);

    logoutput_info("get_ssh_context_option: name %s", name);

    if (strcmp(name, "option:ssh.crypto.cipher.algos")==0) {

	option->type=_INTERFACE_OPTION_PCHAR;
	option->value.ptr=fs_options.ssh.crypto_cipher_algos;

    } else if (strcmp(name, "option:ssh.crypto.hmac.algos")==0) {

	option->type=_INTERFACE_OPTION_PCHAR;
	option->value.ptr=fs_options.ssh.crypto_mac_algos;

    } else if (strcmp(name, "option:ssh.compression.algos")==0) {

	option->type=_INTERFACE_OPTION_PCHAR;
	option->value.ptr=fs_options.ssh.compression_algos;

    } else if (strcmp(name, "option:ssh.keyx.algos")==0) {

	option->type=_INTERFACE_OPTION_PCHAR;
	option->value.ptr=fs_options.ssh.keyx_algos;

    } else if (strcmp(name, "option:ssh.pubkey.algos")==0) {

	option->type=_INTERFACE_OPTION_PCHAR;
	option->value.ptr=fs_options.ssh.pubkey_algos;

    } else if (strcmp(name, "option:ssh.init_timeout")==0) {

	option->type=_INTERFACE_OPTION_INT;
	option->value.number=(unsigned int) fs_options.ssh.init_timeout;

    } else if (strcmp(name, "option:ssh.session_timeout")==0) {

	option->type=_INTERFACE_OPTION_INT;
	option->value.number=(unsigned int) fs_options.ssh.session_timeout;

    } else if (strcmp(name, "option:ssh.exec_timeout")==0) {

	option->type=_INTERFACE_OPTION_INT;
	option->value.number=(unsigned int) fs_options.ssh.exec_timeout;

    } else if (strcmp(name, "io:shared-mutex")==0) {
	struct service_context_s *root_context=get_root_context(context);

	/* get the "root" shared mutex from fuse */

	option->type=_INTERFACE_OPTION_PVOID;
	option->value.data=(void *) get_fuse_pthread_mutex(&root_context->interface);

    } else if (strcmp(name, "io:shared-cond")==0) {
	struct service_context_s *root_context=get_root_context(context);

	/* get the "root" shared cond from fuse */

	option->type=_INTERFACE_OPTION_PVOID;
	option->value.data=(void *) get_fuse_pthread_cond(&root_context->interface);

    }

    return (unsigned int) option->type;
}

static unsigned int get_sftp_context_option(struct context_interface_s *interface, const char *name, struct context_option_s *option)
{
    struct service_context_s *context=get_service_context(interface);

    logoutput_info("get_sftp_context_option: name %s", name);

    if (strcmp(name, "option:sftp.usermapping.user-unknown")==0) {

	option->type=_INTERFACE_OPTION_PCHAR;
	option->value.ptr=fs_options.sftp.usermapping_user_unknown;

    } else if (strcmp(name, "option:sftp.usermapping.user-nobody")==0) {

	option->type=_INTERFACE_OPTION_PCHAR;
	option->value.ptr=fs_options.sftp.usermapping_user_nobody;

    } else if (strcmp(name, "option:sftp.usermapping.type")==0) {

	option->type=_INTERFACE_OPTION_PCHAR;

	if (fs_options.sftp.usermapping_type==_OPTIONS_SFTP_USERMAPPING_NONE) {

	    option->value.ptr="none";

	} else if (fs_options.sftp.usermapping_type==_OPTIONS_SFTP_USERMAPPING_MAP) {

	    option->value.ptr="map";

	} else if (fs_options.sftp.usermapping_type==_OPTIONS_SFTP_USERMAPPING_FILE) {

	    option->value.ptr="file";

	}

    } else if (strcmp(name, "option:sftp.usermapping.file")==0) {

	option->type=_INTERFACE_OPTION_PCHAR;
	option->value.ptr=fs_options.sftp.usermapping_file;

    } else if (strcmp(name, "option:sftp.packet.maxsize")==0) {

	option->type=_INTERFACE_OPTION_INT;
	option->value.number=fs_options.sftp.packet_maxsize;

    } else if (strcmp(name, "option:sftp:correcttime")==0) {

	option->type=_INTERFACE_OPTION_INT;
	option->value.number=1;

    }

    return (unsigned int) option->type;
}

static unsigned int get_backup_context_option(struct context_interface_s *interface, const char *name, struct context_option_s *option)
{
    struct service_context_s *context=get_service_context(interface);

    logoutput_info("get_backup_context_option: name %s", name);

    if (strcmp(name, "option:sftp.usermapping.user-unknown")==0) {

	option->type=_INTERFACE_OPTION_PCHAR;
	option->value.ptr=fs_options.sftp.usermapping_user_unknown;

    } else if (strcmp(name, "option:sftp.usermapping.user-nobody")==0) {

	option->type=_INTERFACE_OPTION_PCHAR;
	option->value.ptr=fs_options.sftp.usermapping_user_nobody;

    } else if (strcmp(name, "option:sftp.usermapping.type")==0) {

	option->type=_INTERFACE_OPTION_PCHAR;

	if (fs_options.sftp.usermapping_type==_OPTIONS_SFTP_USERMAPPING_NONE) {

	    option->value.ptr="none";

	} else if (fs_options.sftp.usermapping_type==_OPTIONS_SFTP_USERMAPPING_MAP) {

	    option->value.ptr="map";

	} else if (fs_options.sftp.usermapping_type==_OPTIONS_SFTP_USERMAPPING_FILE) {

	    option->value.ptr="file";

	}

    } else if (strcmp(name, "option:sftp.usermapping.file")==0) {

	option->type=_INTERFACE_OPTION_PCHAR;
	option->value.ptr=fs_options.sftp.usermapping_file;

    } else if (strcmp(name, "option:sftp.packet.maxsize")==0) {

	option->type=_INTERFACE_OPTION_INT;
	option->value.number=fs_options.sftp.packet_maxsize;

    } else if (strcmp(name, "option:sftp:correcttime")==0) {

	option->type=_INTERFACE_OPTION_INT;
	option->value.number=0; /* no correction of timestamps due to clock skew */

    }

    return (unsigned int) option->type;
}

/* add a sftp shared map */

static void add_shared_map_sftp(struct service_context_s *ssh_context, struct inode_s *inode, char *name)
{
    struct workspace_mount_s *workspace=ssh_context->workspace;
    struct entry_s *parent=inode->alias;
    struct service_context_s *context=NULL;
    struct context_address_s address;
    struct entry_s *entry=NULL;
    struct directory_s *directory=NULL;
    struct name_s xname;
    unsigned int error=0;
    unsigned int len=strlen(name);
    unsigned int count=0;

    logoutput("add_shared_map_sftp: name %s", name);

    replace_cntrl_char(name, len, REPLACE_CNTRL_FLAG_TEXT);
    count=skip_heading_spaces(name, len);
    if (count>0) len-=count;
    count=skip_trailing_spaces(name, len, SKIPSPACE_FLAG_REPLACEBYZERO);
    if (count>0) len-=count;

    if (strcmp(name, "home")==0 && (fs_options.sftp.flags & _OPTIONS_SFTP_FLAG_HOME_USE_REMOTENAME)) {
	struct common_buffer_s buffer;
	int size=0;

	init_common_buffer(&buffer);
	size=(* ssh_context->interface.get_interface_info)(&ssh_context->interface, "remoteusername", NULL, &buffer);

	if (size>0) {
	    char tmp[size + 1];
	    struct simple_lock_s wlock1;

	    memcpy(tmp, buffer.ptr, size);
	    tmp[size]='\0';

	    logoutput("add_shared_map_sftp: replace home by remote username %s", tmp);

	    replace_cntrl_char(tmp, size, REPLACE_CNTRL_FLAG_TEXT);
	    count=skip_heading_spaces(tmp, size);
	    if (count>0) size-=count;
	    count=skip_trailing_spaces(tmp, size, SKIPSPACE_FLAG_REPLACEBYZERO);
	    if (count>0) size-=count;

	    xname.name=tmp;
	    xname.len=strlen(tmp);
	    calculate_nameindex(&xname);
	    directory=get_directory(inode);

	    if (wlock_directory(directory, &wlock1)==0) {

		entry=create_network_map_entry(ssh_context, directory, &xname, &error);

		if (entry) {

		    logoutput("add_shared_map_sftp: created shared map %s", entry->name.name);
		    parent=entry;

		} else {

		    logoutput("add_shared_map_sftp: failed to create map %s, error %i (%s)", buffer.ptr, error, strerror(error));

		}

		unlock_directory(directory, &wlock1);

	    }

	}

	if (buffer.ptr) free(buffer.ptr);

    }

    if (entry==NULL) {
	struct simple_lock_s wlock2;
	unsigned int count=0;

	replace_cntrl_char(name, len, REPLACE_CNTRL_FLAG_TEXT);
	count=skip_heading_spaces(name, len);

	if (count>0) {

	    logoutput("add_shared_map_sftp: skipped heading %i spaces name");
	    len-=count;

	}

	count=skip_trailing_spaces(name, len, SKIPSPACE_FLAG_REPLACEBYZERO);

	if (count>0) {

	    logoutput("add_shared_map_sftp: skipped trailing %i spaces name");
	    len-=count;

	}

	xname.name=name;
	xname.len=strlen(name);
	calculate_nameindex(&xname);
	directory=get_directory(parent->inode);

	if (wlock_directory(directory, &wlock2)==0) {

	    directory=get_directory(parent->inode);
	    entry=create_network_map_entry(ssh_context, directory, &xname, &error);
	    if (entry) logoutput("add_shared_map_sftp: created shared map %s", name);
	    unlock_directory(directory, &wlock2);

	}

    }

    /* entry created and no error (no EEXIST!) */

    if (entry==NULL || error>0) {

	/* TODO: when entry already exists (error==EEXIST) continue */

	if (entry && error==EEXIST) {

	    logoutput("add_shared_map_sftp: directory %s does already exist", name);
	    error=0;

	} else {

	    if (error==0) error=EIO;
	    logoutput("add_shared_map_sftp: error %i creating directory %s (%s)", error, name, strerror(error));

	}

	goto out;

    }

    inode=entry->inode;
    directory=get_directory(inode);
    context=create_service_context(workspace, SERVICE_CTX_TYPE_FILESYSTEM);

    if (context==NULL) {

	logoutput("add_shared_map_sftp: error allocating context");
	goto error;

    }

    memset(&address, 0, sizeof(struct context_address_s));
    address.network.type=_INTERFACE_ADDRESS_NONE;
    address.service.type=_INTERFACE_SERVICE_SFTP;
    address.service.target.sftp.name=name;
    strcpy(context->name, "sftp");
    context->service.filesystem.inode=inode;
    context->parent=ssh_context;
    ssh_context->refcount++;

    if (strcmp(name, "backup")==0) {

	context->interface.get_context_option=get_backup_context_option;

    } else {

	context->interface.get_context_option=get_sftp_context_option;

    }

    init_sftp_filesystem_context(context);

    if ((* context->interface.connect)(workspace->user->uid, &context->interface, &address, &error)==-1) {

	logoutput("add_shared_map_sftp: error %i connecting sftp (%s)", error, strerror(error));
	goto error;

    }

    if ((* context->interface.start)(&context->interface, 0, NULL)==0) {
	struct simple_lock_s wlock3;

	/* create a desktp entry only if it does not exist on the server/share
	    lock first to ensure the directory exists (and is not the dummy) */

	directory=get_directory(inode);

	if (wlock_directory(directory, &wlock3)==0) {
	    struct inode_link_s link;

	    use_service_root_fs(inode);
	    link.type=INODE_LINK_TYPE_CONTEXT;
	    link.link.ptr= (void *) context;
	    set_inode_link_directory(inode, &link);
	    inode->nlookup=1;
	    init_pathcalls_root(&directory->pathcalls);

	    logoutput("add_shared_map_sftp: added sftp directory %s", name);

	    unlock_directory(directory, &wlock3);

	}

    } else {

	logoutput("add_shared_map_sftp: unable to start sftp");
	use_virtual_fs(NULL, inode); /* entry may exist, but has not connection */
	goto error;

    }

    if (fs_options.network.share_icon & (_OPTIONS_NETWORK_ICON_OVERRULE)) {
	struct simple_lock_s wlock4;

	/* create a desktp entry only if it does not exist on the server/share */

	directory=get_directory(entry->inode);

	if (wlock_directory(directory, &wlock4)==0) {

	    create_desktopentry_file("/etc/fs-workspace/desktopentry.sharedmap", entry, workspace);
	    unlock_directory(directory, &wlock4);

	}

    }

    /* when dealing with backup start backup service */

    if (strcmp(name, "backup")==0) {

	start_backup_service(context);

    } else if (strcmp(name, "backupscript")==0) {

	start_backupscript_service(context);

    }

    out:
    return;

    error:

    logoutput("add_shared_map_sftp: error");

}

static void add_net_transport(struct service_context_s *ssh_context, char *name)
{
    unsigned int error=0;
    unsigned int len=strlen(name);
    unsigned int count=0;

    logoutput("add_net_transport: name %s", name);

    replace_cntrl_char(name, len, REPLACE_CNTRL_FLAG_TEXT);
    count=skip_heading_spaces(name, len);

    if (count>0) {

	logoutput("add_net_transport: skipped heading %i spaces name");
	len-=count;

    }

    count=skip_trailing_spaces(name, len, SKIPSPACE_FLAG_REPLACEBYZERO);

    if (count>0) {

	logoutput("add_net_transport: skipped trailing %i spaces name");
	len-=count;

    }

    logoutput("add_net_transport: %s not supported");

}

/* connect to ssh server
    at inode of virtual map */

static struct service_context_s *connect_ssh_server(struct workspace_mount_s *workspace, struct host_address_s *host, struct service_address_s *service, struct inode_s *inode, unsigned int *error)
{
    struct service_context_s *context=NULL;
    struct context_address_s address;
    struct context_interface_s *interface=NULL;
    int fd=-1;
    char *target=NULL;
    unsigned int port=0;

    logoutput("connect_ssh_server");

    *error=ENOMEM;
    context=create_service_context(workspace, SERVICE_CTX_TYPE_CONNECTION);
    if (context==NULL) return NULL;
    interface=&context->interface;

    init_ssh_interface(interface);
    context->interface.get_context_option=get_ssh_context_option;
    memset(&address, 0, sizeof(struct context_address_s));
    address.network.type=_INTERFACE_ADDRESS_NETWORK;
    memcpy(&address.network.target.host, host, sizeof(struct host_address_s));
    memcpy(&address.service, service, sizeof(struct service_address_s));
    *error=EIO;

    logoutput("connect_ssh_server: connect");

    fd=(* interface->connect)(workspace->user->uid, interface, &address, error);
    if (fd<0) {

	translate_context_address_network(&address, &target, &port, NULL);
	logoutput("connect_ssh_server: failed to connect to %s:%i : error %i (%s)", target, port, *error, strerror(*error));
	goto error;

    }

    translate_context_address_network(&address, &target, &port, NULL);

    logoutput("connect_ssh_server: start");

    if ((* interface->start)(interface, fd, NULL)==0) {

	logoutput("connect_ssh_server: started ssh connection to %s:%i", target, port);
	*error=0;
	return context;

    }

    error:

    remove_list_element(&context->list);
    free_service_context(context);
    logoutput("connect_ssh_server: failed to start ssh connection to %s:%i", target, port);
    return NULL;

}

static void get_remote_supported_services(struct service_context_s *context, struct inode_s *inode)
{
    struct common_buffer_s buffer;
    unsigned int size=0;
    unsigned int count=0;
    char *sep=NULL;
    char *service=NULL;
    char *name=NULL;
    unsigned int left=0;

    logoutput_info("get_remote_supported_services");

    init_common_buffer(&buffer);

    size=(* context->interface.get_interface_info)(&context->interface, "supportedservices", NULL, &buffer);
    if (size==0) goto trydefault;
    service=(char *) buffer.ptr;
    left=size;

    findservice:

    sep=memchr(service, '=', left);

    if (sep) {

	*sep='\0';
	sep++;

	name=sep;
	left=(unsigned int)((char *)(buffer.ptr + size) - sep);

	sep=memchr(name, '|', left);

	if (sep) {

	    *sep='\0';

	    if (strcmp(service, "sftp.sharedmap")==0) {

		logoutput("get_remote_supported_services: service %s type %s", service, name);

		/* add sftp shared map */

		add_shared_map_sftp(context, inode, name);
		count++;

	    } else {

		logoutput("get_remote_supported_services: service %s type %s not supported", service, name);

	    }

	    *sep='|';
	    sep++;

	    if (sep < (char *) (buffer.ptr + size)) {

		left=(unsigned int)((char *)(buffer.ptr + size) - sep);
		service=sep;
		goto findservice;

	    }

	}

    }

    trydefault:

    if (count==0) {

	logoutput("get_remote_supported_services: no services foudn, try the default (home)");
	add_shared_map_sftp(context, inode, _SFTP_HOME_MAP);

    }

    if (buffer.ptr) free(buffer.ptr);

}

static int test_buffer_ip(struct common_buffer_s *buffer)
{
    char tmp[buffer->size + 1];

    memcpy(tmp, buffer->ptr, buffer->size);
    tmp[buffer->size]='\0';
    if (check_family_ip_address(tmp, "ipv4")==1) return 0;
    if (check_family_ip_address(tmp, "ipv6")==1) return 0;
    return -1;
}

/*
    connect to ssh server and use the sftp subsystem to browse
    - connect to the server and the home directory
    - create a "server" entry with the name of the address
    - rename this "server" entry to a more human readable name (unique??)
    - add this entry to the SSH network map
    note the directory of parent is already excl locked
*/

static int install_ssh_server(struct workspace_mount_s *workspace, struct entry_s *parent, struct host_address_s *host, struct service_address_s *service, unsigned int *error)
{
    struct service_context_s *context=NULL;
    int result=-1;
    struct common_buffer_s buffer;
    unsigned int port=0;
    char *target=NULL;
    struct inode_s *inode=NULL;
    struct directory_s *directory=NULL;
    struct simple_lock_s wlock2;

    logoutput("install_ssh_server");

    context=connect_ssh_server(workspace, host, service, NULL, error);
    if (! context) return -1;
    strcpy(context->name, "ssh");
    init_common_buffer(&buffer);

    /*
	a domain name is requested? test the options
	if so the path to server will start with domainname like:

	/example.nl/

    */

    if (fs_options.sftp.flags & _OPTIONS_SFTP_FLAG_SHOW_DOMAINNAME) {
	unsigned int size=0;
	char *domain=NULL;
	struct fs_connection_s *connection=context->service.connection;

	/* get full name including domain from server */

	size=(* context->interface.get_interface_info)(&context->interface, "servername", connection->io.socket.xdata.data, &buffer);

	if (size==0) {

	    if (host->flags & HOST_ADDRESS_FLAG_HOSTNAME) {

		buffer.ptr=strdup(host->hostname);
		if (buffer.ptr) {

		    buffer.size=strlen(buffer.ptr);
		    size=buffer.size;

		}

	    }

	    if (size==0) size=(* context->interface.get_interface_info)(&context->interface, "hostname", connection->io.socket.xdata.data, &buffer);

	}

	logoutput("install_ssh_server: servername size %i len %i", size, buffer.size);

	if (size>0 && test_buffer_ip(&buffer)==-1) {
	    char *sep=NULL;

	    /* look for the second name (seperated with a dot) */

	    sep=memchr(buffer.ptr, '.', size);

	    if (sep) {
		unsigned int count=0;
		unsigned int len=0;

		target=buffer.ptr;
		*sep='\0';
		domain=sep+1;
		len=(unsigned int)(buffer.ptr + size - domain);

		replace_cntrl_char(domain, len, REPLACE_CNTRL_FLAG_TEXT);
		count=skip_heading_spaces(domain, len);
		if (count>0) len-=count;
		count=skip_trailing_spaces(domain, len, SKIPSPACE_FLAG_REPLACEBYZERO);
		if (count>0) len-=count;

		logoutput("install_ssh_server: found domain %s", domain);

	    }

	}

	if (domain) {
	    struct simple_lock_s wlock1;
	    struct directory_s *directory=NULL;

	    /* install the domain name */

	    directory=get_directory(parent->inode);

	    if (wlock_directory(directory, &wlock1)==0) {
		struct name_s xname;
		struct entry_s *entry=NULL;

		xname.name=domain;
		xname.len=strlen(domain);
		xname.index=0;
		calculate_nameindex(&xname);

		entry=find_entry_batch(directory, &xname, error);

		if (! entry) {

		    entry=create_network_map_entry(context, directory, &xname, error);

		    if (! entry) {

			logoutput("install_ssh_server: unable to create domain map %s", domain);
			unlock_directory(directory, &wlock1);
			free_common_buffer(&buffer);
			goto error;

		    } else {

			logoutput("install_ssh_server: created domain map %s", domain);

		    }

		    parent=entry;
		    entry->inode->nlookup++;

		}

		if (fs_options.network.domain_icon & (_OPTIONS_NETWORK_ICON_SHOW | _OPTIONS_NETWORK_ICON_OVERRULE))
		    create_desktopentry_file("/etc/fs-workspace/desktopentry.netgroup", entry, workspace);

		unlock_directory(directory, &wlock1);

	    }

	}

    }

    logoutput("install_ssh_server: install server map");

    /* install the server map */

    if (target==NULL) translate_context_host_address(host, &target, NULL);
    if (target==NULL) goto error;

    directory=get_directory(parent->inode);

    if (wlock_directory(directory, &wlock2)==0) {
	struct name_s xname;
	struct directory_s *server_directory=NULL;
	struct simple_lock_s wlock3;
	struct entry_s *entry=NULL;

	xname.name=target;
	xname.len=strlen(target);
	xname.index=0;
	calculate_nameindex(&xname);

	entry=find_entry_batch(directory, &xname, error);

	if (! entry) {

	    /* install the server name */

	    *error=0;
	    entry=create_network_map_entry(context, directory, &xname, error);

	    if (entry) {

		logoutput_info("install_ssh_server: created server map %.*s", xname.len, xname.name);

	    } else {

		logoutput_warning("install_ssh_server: unable to create server map %.*s", xname.len, xname.name);
		unlock_directory(directory, &wlock2);
		goto error;

	    }

	} else {

	    logoutput_info("install_ssh_server: server map %.*s already exists", xname.len, xname.name);
	    unlock_directory(directory, &wlock2);
	    goto out;

	}

	inode=entry->inode;
	server_directory=get_directory(inode);

	if (wlock_directory(server_directory, &wlock3)==0) {
	    struct inode_link_s link;

	    link.type=INODE_LINK_TYPE_DATA; /* not a context but additional data */
	    link.link.ptr=(void *) context;
	    set_inode_link_directory(inode, &link);
	    result=0;
	    inode->nlookup=1;

	    if (fs_options.network.server_icon & (_OPTIONS_NETWORK_ICON_SHOW | _OPTIONS_NETWORK_ICON_OVERRULE))
		create_desktopentry_file("/etc/fs-workspace/desktopentry.netserver", entry, workspace);

	    unlock_directory(server_directory, &wlock3);

	}

	unlock_directory(directory, &wlock2);

    }

    /* create sftp shared directories in server map */

    if (inode) get_remote_supported_services(context, inode);

    out:

    free_common_buffer(&buffer);
    return result;

    error:

    free_common_buffer(&buffer);
    return -1;

}

int install_ssh_server_context(struct workspace_mount_s *workspace, struct entry_s *parent, struct host_address_s *host, struct service_address_s *service, unsigned int *error)
{

    logoutput("install_ssh_server_context");

    /*

	required to install the network map like .../SFTP/...?

	*/

    if ((fs_options.fuse.flags & _OPTIONS_FUSE_FLAG_NETWORK_IGNORE_SERVICE)==0) {
        struct name_s xname;
        struct simple_lock_s wlock;
        struct directory_s *directory=NULL;

	/* create sftp network name entry */

	if (fs_options.sftp.network_name) {

	    xname.name=fs_options.sftp.network_name;

	} else {

	    xname.name=_OPTIONS_SFTP_NETWORK_NAME_DEFAULT;

	}

	xname.len=strlen(xname.name);
	calculate_nameindex(&xname);
	directory=get_directory(parent->inode);

	if (wlock_directory(directory, &wlock)==0) {
	    struct entry_s *entry=NULL;

	    entry=create_network_map_entry(workspace->context, directory, &xname, error);
	    if (entry) parent=entry;

	    unlock_directory(directory, &wlock);

	}

    }

    return install_ssh_server(workspace, parent, host, service, error);

}
