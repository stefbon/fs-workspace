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

#include "logging.h"

#include "main.h"
#include "pathinfo.h"
#include "entry-management.h"
#include "directory-management.h"
#include "entry-utils.h"
#include "fuse-fs.h"

#include "workspaces.h"
#include "workspace-context.h"
#include "workspace-interface.h"

#include "path-caching.h"

#include "utils.h"
#include "options.h"

#include "fuse-fs-common.h"
#include "fuse-fs-virtual.h"
#include "fuse-context-fs-root.h"
#include "fuse-network.h"

#define _SFTP_NETWORK_NAME			"SFTP_Network"
#define _SFTP_HOME_MAP				"home"

extern struct fs_options_struct fs_options;

extern void init_ssh_interface(struct context_interface_s *interface);
extern void init_sftp_subsystem_interface(struct context_interface_s *interface);

/* callback for the ssh/sftp backend to get options from fs-workspace
*/

static unsigned int get_option_network_ssh(struct context_interface_s *interface, const char *name, struct context_option_s *option)
{
    struct service_context_s *context=get_service_context(interface);

    logoutput("get_option_network_ssh: name %s", name);

    if (strcmp(name, "cipher")==0) {

	option->type=_INTERFACE_OPTION_PCHAR;
	option->value.ptr=fs_options.ssh_ciphers;

    } else if (strcmp(name, "hmac")==0) {

	option->type=_INTERFACE_OPTION_PCHAR;
	option->value.ptr=fs_options.ssh_mac;

    } else if (strcmp(name, "compression")==0) {

	option->type=_INTERFACE_OPTION_PCHAR;
	option->value.ptr=fs_options.ssh_compression;

    } else if (strcmp(name, "keyx")==0) {

	option->type=_INTERFACE_OPTION_PCHAR;
	option->value.ptr=fs_options.ssh_keyx;

    } else if (strcmp(name, "pubkey")==0) {

	option->type=_INTERFACE_OPTION_PCHAR;
	option->value.ptr=fs_options.ssh_pubkeys;

    } else if (strcmp(name, "user-unknown")==0) {

	option->type=_INTERFACE_OPTION_PCHAR;
	option->value.ptr=fs_options.user_unknown;

    } else if (strcmp(name, "user-nobody")==0) {

	option->type=_INTERFACE_OPTION_PCHAR;
	option->value.ptr=fs_options.user_nobody;

    } else if (strcmp(name, "shared-mutex")==0) {
	struct service_context_s *context=get_service_context(interface);
	struct service_context_s *root_context=get_root_context(context);

	/* get the "root" shared mutex from fuse */

	option->type=_INTERFACE_OPTION_PVOID;
	option->value.data=(void *) get_fuse_pthread_mutex(&root_context->interface);

    } else if (strcmp(name, "shared-cond")==0) {
	struct service_context_s *context=get_service_context(interface);
	struct service_context_s *root_context=get_root_context(context);

	/* get the "root" shared cond from fuse */

	option->type=_INTERFACE_OPTION_PVOID;
	option->value.data=(void *) get_fuse_pthread_cond(&root_context->interface);

    }

    return (unsigned int) option->type;
}

static struct context_interface_s *get_sftp_parent_interface(struct context_interface_s *interface)
{

    if (interface) {
	struct service_context_s *context=get_service_context(interface);

	if (context->parent) {
	    struct service_context_s *ssh_context=context->parent;

	    return &ssh_context->interface;

	}

    }

    return NULL;

}

/* add a sftp shared map */

static void add_shared_map_sftp(struct service_context_s *ssh_context, char *name)
{
    struct workspace_mount_s *workspace=ssh_context->workspace;
    struct directory_s *directory=get_directory(ssh_context->inode);
    struct service_context_s *context=NULL;
    struct context_address_s address;
    struct entry_s *entry=NULL;
    struct inode_s *inode=NULL;
    struct name_s xname;
    unsigned int error=0;

    logoutput("add_shared_map_sftp: directory %s", name);

    xname.name=name;
    xname.len=strlen(name);
    calculate_nameindex(&xname);

    entry=create_network_map_entry(workspace, directory, &xname, &error);

    /* entry created and no error (no EEXIST!) */

    if (entry==NULL || error>0) {

	/* TODO: when entry already exists (error==EEXIST) continue */

	if (error==EEXIST) {

	    logoutput("add_shared_map_sftp: directory %s does already exist", name);

	} else {

	    if (error==0) error=EIO;
	    logoutput("add_shared_map_sftp: error %i creating directory %s (%s)", error, name, strerror(error));

	}

	return;

    }

    inode=entry->inode;

    if (lock_directory_excl(inode)==-1) {

	logoutput("add_shared_map_sftp: error locking directory");
	return;

    }

    context=create_service_context(workspace, SERVICE_CTX_TYPE_SERVICE);

    if (context==NULL) {

	logoutput("add_shared_map_sftp: error allocating context");
	goto errorunlock;

    }

    memset(&address, 0, sizeof(struct context_address_s));
    address.type=_INTERFACE_SFTP_SERVER;
    address.target.sftp.name=name;

    strcpy(context->name, "sftp");
    context->inode=inode;
    context->parent=ssh_context;
    ssh_context->refcount++;
    init_sftp_subsystem_interface(&context->interface);

    context->interface.get_parent=get_sftp_parent_interface;
    context->interface.ptr=(* context->interface.connect)(workspace->user->uid, &context->interface, &address, &error);

    if (context->interface.ptr==NULL) {

	logoutput("add_shared_map_sftp: error connect sftp");
	goto errorunlock;

    }

    if ((* context->interface.start)(&context->interface, NULL)==0) {
	union datalink_u link;
	struct directory_s *directory=get_directory(inode);

	use_service_root_fs(inode);
	link.data=(void *) context;
	set_datalink(inode, &link);
	init_pathcalls_root(&directory->pathcalls);

	logoutput("add_shared_map_sftp: added sftp directory %s", name);

	// create_desktopentry_file("/etc/fs-workspace/desktopentry.sharedmap", entry, context->workspace);

    } else {

	logoutput("add_shared_map_sftp: unable to start sftp");
	goto errorunlock;

    }

    unlock_directory_excl(inode);
    return;

    errorunlock:

    if (context) {

	if (context->interface.ptr) {

	    (* context->interface.free)(&context->interface);

	}

	if (context->parent) context->parent->refcount--;
	free_service_context(context);

    }

    unlock_directory_excl(inode);

}

/* connect to ssh server
    at inode of virtual map */

static struct service_context_s *connect_ssh_server(struct workspace_mount_s *workspace, const char *address, unsigned int port, struct inode_s *inode, unsigned int *error)
{
    struct service_context_s *context=NULL;

    context=create_service_context(workspace, SERVICE_CTX_TYPE_SERVICE);

    if (context) {
	struct context_address_s ssh_address;

    	context->inode=inode;
    	context->interface.get_interface_option=get_option_network_ssh;

	init_ssh_interface(&context->interface);

	ssh_address.type=_INTERFACE_NETWORK_IPV4;
	ssh_address.target.network.address=(char *) address;
	ssh_address.target.network.port=port;

	context->interface.ptr=(* context->interface.connect)(workspace->user->uid, &context->interface, &ssh_address, error);

	if (context->interface.ptr) {

	    if ((* context->interface.start)(&context->interface, context->xdata.data)==0) {

		logoutput("connect_ssh_server: started ssh connection to %s:%i", address, port);

	    } else {

		logoutput("connect_ssh_server: failed to start ssh connection to %s:%i", address, port);

	    }

	} else {

	    logoutput("connect_ssh_server: failed to connect to %s:%i : error %i (%s)", address, port, *error, strerror(*error));
	    free_service_context(context);
	    context=NULL;

	}

    } else {

	*error=ENOMEM;

    }

    return context;

}

static void get_remote_supported_services(struct service_context_s *context)
{
    unsigned char buffer[1024];
    unsigned int error=0;
    unsigned int size=0;

    size=(* context->interface.get_interface_info)(&context->interface, "services", NULL, buffer, 1024, &error);

    if (size>0) {
	char *sep=NULL;
	char *service=(char *) buffer;
	char *name=NULL;
	unsigned int left=size;

	findservice:

	sep=memchr(service, '=', left);

	if (sep) {

	    *sep='\0';
	    sep++;

	    name=sep;
	    left=(unsigned int)((char *)(buffer + size) - sep);

	    sep=memchr(name, '|', left);

	    if (sep) {

		*sep='\0';

		logoutput("get_remote_supported_services: service %s type %s", service, name);

		if (strcmp(service, "sftp.sharedmap")==0) {

		    /* add sftp shared map */

		    add_shared_map_sftp(context, name);

		} else {

		    logoutput("get_remote_supported_services: service %s type %s not supported", service, name);

		}

		*sep='|';
		sep++;

		if (sep < (char *) (buffer + size)) {

		    left=(unsigned int)((char *)(buffer + size) - sep);
		    service=sep;
		    goto findservice;

		}

	    }

	}

    }

}

/*
    connect to ssh server and use the sftp subsystem to browse

    - connect to the server and the home directory
    - create a "server" entry with the name of the address
    - rename this "server" entry to a more human readable name (unique??)
    - add this entry to the SSH network map

    note the directory of parent is already excl locked
*/

static int install_ssh_server(struct workspace_mount_s *workspace, struct entry_s *parent, char *address, unsigned int port, unsigned int *error)
{
    struct service_context_s *context=NULL;
    struct directory_s *directory=NULL;
    struct entry_s *entry=NULL;
    struct name_s xname;
    unsigned char servername[128];
    unsigned int size=0;
    char *domain=NULL;
    union datalink_u link;
    int result=-1;

    logoutput("install_ssh_server");

    context=connect_ssh_server(workspace, address, port, NULL, error);
    if (! context) return -1;
    strcpy(context->name, "ssh");

    /* get full name including domain*/

    memset(servername, '\0', 128);
    size=(* context->interface.get_interface_info)(&context->interface, "servername", context->xdata.data, servername, 127, error);

    if (size>0 && size<128) {
	char *sep=NULL;

	/* look for the first name (seperated with a dot) */

	sep=memchr(servername, '.', size);

	if (sep) {

	    *sep='\0';
	    domain=sep+1;
	    logoutput("install_sftp_server: found domain %s", domain);

	}

    }

    if (domain) {

	/* install the domain name */

	lock_directory_excl(parent->inode);

	directory=get_directory(parent->inode);

	xname.name=domain;
	xname.len=strlen(domain);
	xname.index=0;
	calculate_nameindex(&xname);

	parent=find_entry_batch(directory, &xname, error);

	if (! parent) {

	    parent=create_network_map_entry(workspace, directory, &xname, error);

	    if (! parent) {

		logoutput("install_sftp_server: unable to create server map %s", domain);
		unlock_directory_excl(directory->inode);
		return -1;

	    }

	}

	unlock_directory_excl(directory->inode);

    }

    /* install the server map */

    lock_directory_excl(parent->inode);

    directory=get_directory(parent->inode);

    xname.name=NULL;
    xname.len=strlen((char *)servername);
    xname.index=0;

    if (xname.len>0) {

	xname.name=(char *)servername;

    } else {

	/* fallback to address */
	xname.name=address;
	xname.len=strlen(address);

    }

    calculate_nameindex(&xname);

    entry=find_entry_batch(directory, &xname, error);

    if (! entry) {
	union datalink_u link;

	entry=create_network_map_entry(workspace, directory, &xname, error);

	if (! entry) {

	    logoutput("install_sftp_servershare: unable to create server map %s", xname.name);
	    unlock_directory_excl(directory->inode);
	    return -1;

	}

	link.data=(void *) context;
	set_datalink(entry->inode, &link);
	context->inode=entry->inode;
	result=0;

	create_desktopentry_file("/etc/fs-workspace/desktopentry.netserver", entry, context->workspace);

    } else {
	union datalink_u *link=get_datalink(entry->inode);

	if (link->data) {

	    /* inode points already to something
		TODO: check what it's pointing to.... */

	    logoutput("install_ssh_server: server %s already created", xname.name);
	    unlock_directory_excl(directory->inode);
	    return 0;

	}

    }

    unlock_directory_excl(directory->inode);

    /* create home map in server map */

    get_remote_supported_services(context);

    return result;

}

int install_ssh_server_context(struct workspace_mount_s *workspace, struct entry_s *parent, char *address, unsigned int port, unsigned int *error)
{
    struct inode_s *inode=parent->inode;
    struct directory_s *root_directory=NULL;

    root_directory=get_directory(inode);

    if (root_directory) {
	struct entry_s *entry=NULL;
	struct name_s xname;

	/* create sftp network */

	xname.name=_SFTP_NETWORK_NAME;
	xname.len=strlen(xname.name);
	calculate_nameindex(&xname);

	entry=create_network_map_entry(workspace, root_directory, &xname, error);

	if (entry) {

	    inode=entry->inode;

	    if (lock_directory_excl(inode)==0) {
		struct directory_s *net_directory=get_directory(inode);

		unlock_directory_excl(inode);

		return install_ssh_server(workspace, entry, address, port, error);

	    }

	}

    }

    return -1;

}
