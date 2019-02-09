/*
  2010, 2011, 2012, 2013, 2014, 2015, 2016, 2017 Stef Bon <stefbon@gmail.com>

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

#include <inttypes.h>
#include <ctype.h>

#include <sys/stat.h>
#include <sys/param.h>
#include <sys/types.h>
#include <pthread.h>
#include <arpa/inet.h>

#include "logging.h"
#include "pathinfo.h"
#include "utils.h"
#include "main.h"
#include "simple-list.h"
#include "simple-hash.h"
#include "workerthreads.h"
#include "network-utils.h"

#include "workspace-interface.h"
#include "workspaces.h"
#include "workspace-context.h"
#include "options.h"
#include "discover.h"

extern struct fs_options_struct fs_options;

/*
    keep track of services on the network like:
    - ssh-sftp
    - webdav
    - smb
*/

struct host_found_s;

struct service_found_s {
    unsigned long					id;
    struct service_address_s				service;
    unsigned int					code;
    struct host_found_s					*host;
    unsigned int					method;
    unsigned int					depends;
    struct timespec					found;
    unsigned long					refcount;
    struct list_element_s				list;
};

struct host_found_s {
    unsigned long					id;
    unsigned int					method;
    struct host_address_s				host;
    struct timespec					found;
    struct timespec					changed;
    pthread_mutex_t					mutex;
    struct list_element_s				list;
    unsigned int					refcount;
    unsigned int					count;
    struct list_header_s				services;
};

struct hosts_found_s {
    unsigned int					count;
    struct timespec					changed;
    pthread_mutex_t					mutex;
    unsigned long 					hostid;
    unsigned long 					serviceid;
    struct list_header_s				hosts;
};

struct queue_element_s {
    unsigned int					method;
    struct context_address_s				address;
    unsigned int					code;
    unsigned int					depends;
    unsigned int					port;
    struct list_element_s				list;
};

struct queued_services_s {
    struct list_header_s				queue;
    pthread_mutex_t					mutex;
};
struct process_services_s {
    process_new_service					cb;
    pthread_t						threadid;
    struct timespec 					since;
    unsigned char 					changed;
    pthread_mutex_t 					mutex;
};

static struct hosts_found_s hosts_found;
static struct simple_hash_s servicegroup;
static struct queued_services_s discover_queue;
static struct process_services_s process_services;

static unsigned int calculate_id_hash(unsigned long id)
{
    return id % servicegroup.len;
}

static unsigned int id_hashfunction(void *data)
{
    struct service_found_s *service=(struct service_found_s *) data;
    return calculate_id_hash(service->id);
}

static struct service_found_s *lookup_service_id(unsigned long id)
{
    unsigned int hashvalue=calculate_id_hash(id);
    void *index=NULL;
    struct service_found_s *service=NULL;

    service=(struct service_found_s *) get_next_hashed_value(&servicegroup, &index, hashvalue);

    while(service) {

	if (service->id==id) break;
	service=(struct service_found_s *) get_next_hashed_value(&servicegroup, &index, hashvalue);

    }

    return service;

}

void add_service_servicegroup(struct service_found_s *s)
{
    add_data_to_hash(&servicegroup, (void *) s);
}

void remove_service_servicegroup(struct service_found_s *s)
{
    remove_data_from_hash(&servicegroup, (void *) s);
}

void free_data_servicegroup(void *data)
{
    struct service_found_s *service=(struct service_found_s *) data;
    free(service);
}

static void queue_service_found(unsigned int code, unsigned int method, unsigned int depends, struct context_address_s *address)
{
    struct queue_element_s *queue=malloc(sizeof(struct queue_element_s));

    if (queue) {

	queue->code=code;
	queue->method=method;
	queue->depends=depends;
	memcpy(&queue->address, address, sizeof(struct context_address_s));
	init_list_element(&queue->list, NULL);

	pthread_mutex_lock(&discover_queue.mutex);
	add_list_element_last(&discover_queue.queue, &queue->list);
	pthread_mutex_unlock(&discover_queue.mutex);

    }

}

struct queue_element_s *get_next_queued_service_found()
{
    pthread_mutex_lock(&discover_queue.mutex);
    struct list_element_s *list=get_list_head(&discover_queue.queue, SIMPLE_LIST_FLAG_REMOVE);
    pthread_mutex_unlock(&discover_queue.mutex);
    return (list) ? ((struct queue_element_s *) ( ((char *) list) - offsetof(struct queue_element_s, list))) : NULL;
}

static struct host_found_s *get_container_host(struct list_element_s *list)
{
    return (struct host_found_s *) ( ((char *) list) - offsetof(struct host_found_s, list));
}

static struct service_found_s *get_container_service(struct list_element_s *list)
{
    return (struct service_found_s *) ( ((char *) list) - offsetof(struct service_found_s, list));
}

/* NOTE: srcmp is used to compare strings, these strings must be zero terminated! */

static int compare_context_address(struct context_address_s *a, struct context_address_s *b)
{

    if (a->network.type!=b->network.type) return -1;

    if (a->network.type==_INTERFACE_ADDRESS_SMB_SERVER) {

	if (strcmp(a->network.target.smbserver, b->network.target.smbserver)==0) {

	    if (a->service.type==_INTERFACE_SERVICE_NONE && b->service.type==_INTERFACE_SERVICE_NONE) {

		return 0;

	    } else if (a->service.type==_INTERFACE_SERVICE_SMB_SHARE && b->service.type==_INTERFACE_SERVICE_SMB_SHARE) {

		if (strcmp(a->service.target.smbshare.share, b->service.target.smbshare.share)==0) return 0;

	    }

	}

    } else if (a->network.type==_INTERFACE_ADDRESS_NETWORK) {

	if (compare_host_address(&a->network.target.host, &b->network.target.host)==0) {

	    if (a->service.type==_INTERFACE_SERVICE_NONE) {

		return 0;

	    } else if (a->service.type==_INTERFACE_SERVICE_PORT) {

		if (a->service.target.port.port==b->service.target.port.port && a->service.target.port.type==b->service.target.port.type) return 0;

	    } else if (a->service.type==_INTERFACE_SERVICE_SFTP) {

		if (strcmp(a->service.target.sftp.name, b->service.target.sftp.name)==0) return 0;

	    } else if (a->service.type==_INTERFACE_SERVICE_NFS_EXPORT) {

		if (strcmp(a->service.target.nfs.dir, b->service.target.nfs.dir)==0 && a->service.target.nfs.port==b->service.target.nfs.port) {

		    return 0;

		}

	    }

	}

    } else if (a->network.type==_INTERFACE_ADDRESS_NONE) {

	if (a->service.type==_INTERFACE_SERVICE_FUSE) {

	    if (a->service.target.fuse.source && a->service.target.fuse.mountpoint && a->service.target.fuse.name &&
		b->service.target.fuse.source && b->service.target.fuse.mountpoint && b->service.target.fuse.name) {

		if (strcmp(a->service.target.fuse.source, b->service.target.fuse.source)==0 && strcmp(a->service.target.fuse.mountpoint, b->service.target.fuse.mountpoint)==0 &&
		    strcmp(a->service.target.fuse.name, b->service.target.fuse.name)==0) return 0;

	    }

	}

    }

    return -1;
}

static void process_nothing(struct host_address_s *h, struct service_address_s *s, unsigned int code, struct timespec *f, unsigned long hid, unsigned long sid, void *ptr)
{
}



#define _ADD_NET_SERVICE_HOST						1
#define _ADD_NET_SERVICE_SERVICE					2
#define _ADD_NET_SERVICE_HOST_EXIST					4
#define _ADD_NET_SERVICE_SERVICE_EXIST					8

static unsigned int add_net_service_unlocked(unsigned int code, unsigned int method, struct context_address_s *address, unsigned char queued, unsigned int *error)
{
    struct host_found_s *host=NULL;
    struct list_element_s *list=NULL;
    struct service_found_s *service=NULL;
    unsigned int result=0;

    logoutput("add_net_service_unlocked");

    /* add a service
	- lookup the hostname and create host if not found
	- lookup the service and create it not found
    */

    *error=0;

    list=get_list_head(&hosts_found.hosts, 0);

    while(list) {

	host=get_container_host(list);

	if (address->network.type==_INTERFACE_ADDRESS_NETWORK) {

	    if (compare_host_address(&host->host, &address->network.target.host)==0) break;

	}

	list=get_next_element(list);
	host=NULL;

    }

    if (! host) {

	host=malloc(sizeof(struct host_found_s));

	if (host) {
	    char *target=NULL;
	    unsigned int port=0;

	    memset(host, 0, sizeof(struct host_found_s));
	    hosts_found.hostid++;
	    host->id=hosts_found.hostid;
	    host->method=method;

	    memcpy(&host->host, &address->network.target.host, sizeof(struct host_address_s));

	    get_current_time(&host->found);
	    host->changed.tv_sec=0;
	    host->changed.tv_nsec=0;

	    pthread_mutex_init(&host->mutex, NULL);
	    init_list_element(&host->list, NULL);
	    host->refcount=0;
	    host->count=0;
	    init_list_header(&host->services, SIMPLE_LIST_TYPE_EMPTY, NULL);
	    add_list_element_first(&hosts_found.hosts, &host->list);

	    result |= _ADD_NET_SERVICE_HOST;

	    translate_context_address_network(address, &target, &port, NULL);
	    logoutput("add_net_service_unlocked: added host %s:%i", target, port);

	} else {

	    *error=ENOMEM;
	    return result;

	}

    } else {

	result |= _ADD_NET_SERVICE_HOST_EXIST;

    }

    list=get_list_head(&host->services, 0);

    while (list) {
	struct context_address_s tmp;

	service=get_container_service(list);

	/* construct a tmp context_address to use the compare function */

	memset(&tmp, 0, sizeof(struct context_address_s));
	memcpy(&tmp, address, sizeof(struct context_address_s));
	memcpy(&tmp.service, service, sizeof(struct service_address_s));

	if (compare_context_address(&tmp, address)==0) break;

	list=list->n;
	service=NULL;

    }

    if (! service) {

	service=malloc(sizeof(struct service_found_s));

	if (service) {

	    memset(service, 0, sizeof(struct service_found_s));
	    hosts_found.serviceid++;
	    service->id=hosts_found.serviceid;
	    service->code=code;
	    service->method=method;
	    service->host=host;
	    memcpy(&service->service, &address->service, sizeof(struct service_address_s));
	    get_current_time(&service->found);
	    service->refcount=0;
	    memcpy(&hosts_found.changed, &service->found, sizeof(struct timespec));

	    add_list_element_first(&host->services, &service->list);
	    add_service_servicegroup(service);
	    result |= _ADD_NET_SERVICE_SERVICE;

	    logoutput("add_net_service_unlocked: added service port %i", address->service.target.port.port);

	} else {

	    *error=ENOMEM;
	    return result;

	}

    } else {

	result |= _ADD_NET_SERVICE_SERVICE_EXIST;
	*error=EEXIST;

    }

    return result;

}

/* get all the current services
*/

void get_net_services(struct timespec *since, process_new_service cb, void *ptr)
{
    struct list_element_s *hlist=NULL;
    struct list_element_s *slist=NULL;
    struct host_found_s *host=NULL;
    struct service_found_s *service=NULL;
    struct queue_element_s *queue=NULL;
    unsigned int added=0;
    struct timespec maxfound={0, 0};

    logoutput("get_net_services");

    pthread_mutex_lock(&hosts_found.mutex);

    processlist:

    /* walk every host and every service
	and process only that services which have been changed/added after "since"*/

    hlist=get_list_head(&hosts_found.hosts, 0);

    while (hlist) {

	host=get_container_host(hlist);
	slist=get_list_head(&host->services, 0);

	while (slist) {

	    service=get_container_service(slist);

	    /* process only services added lately */

	    if (service->found.tv_sec > since->tv_sec || (service->found.tv_sec == since->tv_sec && service->found.tv_nsec > since->tv_nsec)) {
		char *target=NULL;
		unsigned int port=0;

		translate_context_host_address(&host->host, &target, NULL);
		translate_context_network_port(&service->service, &port);
		logoutput("get_net_services: run cb for %s:%i", target, port);

		(* cb)(&host->host, &service->service, service->code, &service->found, host->id, service->id, ptr);

		if (service->found.tv_sec > maxfound.tv_sec || (service->found.tv_sec == maxfound.tv_sec && service->found.tv_nsec > maxfound.tv_nsec)) {

		    maxfound.tv_sec=service->found.tv_sec;
		    maxfound.tv_nsec=service->found.tv_nsec;

		}

	    }

	    slist=get_next_element(slist);
	    service=NULL;

	}

	hlist=get_next_element(hlist);
	host=NULL;

    }

    /* adjust the since time to get only the new services */
    since->tv_sec=maxfound.tv_sec; 
    since->tv_nsec=maxfound.tv_nsec;

    /* test the queue */

    logoutput("get_net_services: check for queued services");

    added=0;
    queue=get_next_queued_service_found();

    while (queue) {
	unsigned int result=0;
	unsigned int error=0;
	struct context_address_s address;

	memset(&address, 0, sizeof(struct context_address_s));
	memcpy(&address, &queue->address, sizeof(struct context_address_s));

	result=add_net_service_unlocked(queue->code, queue->method, &address, 1, &error);
	if (result & _ADD_NET_SERVICE_SERVICE) added++;
	free(queue);

	logoutput("get_net_services: next");

	queue=get_next_queued_service_found();

    }

    if (added>0) goto processlist;
    logoutput("get_net_services: ready");
    pthread_mutex_unlock(&hosts_found.mutex);


}

/* increase refcount to service
*/

void increase_service_refcount(unsigned long id)
{
    struct service_found_s *service=NULL;

    pthread_mutex_lock(&hosts_found.mutex);
    service=lookup_service_id(id);
    if (service) service->refcount++;
    pthread_mutex_unlock(&hosts_found.mutex);

}

void decrease_service_refcount(unsigned long id)
{
    struct service_found_s *service=NULL;

    pthread_mutex_lock(&hosts_found.mutex);
    service=lookup_service_id(id);
    if (service) service->refcount--;
    pthread_mutex_unlock(&hosts_found.mutex);

}

int init_discover_group(unsigned int *error)
{

    /* list of hosts */

    memset(&hosts_found, 0, sizeof(struct hosts_found_s));
    hosts_found.count=0;
    hosts_found.changed.tv_sec=0;
    hosts_found.changed.tv_nsec=0;
    pthread_mutex_init(&hosts_found.mutex, NULL);
    init_list_header(&hosts_found.hosts, SIMPLE_LIST_TYPE_EMPTY, NULL);

    /* process the changes */

    process_services.cb=process_nothing;
    process_services.threadid=0;
    pthread_mutex_init(&process_services.mutex, NULL);
    process_services.changed=0;
    process_services.since.tv_sec=0;
    process_services.since.tv_nsec=0;

    /* queue */

    init_list_header(&discover_queue.queue, SIMPLE_LIST_TYPE_EMPTY, NULL);
    pthread_mutex_init(&discover_queue.mutex, NULL);

    if (initialize_group(&servicegroup, id_hashfunction, 128, error)==0) {

	logoutput_info("init_discover_group: initialized");

    } else {

	logoutput_warning("init_discover_group: error %i:%s", *error, strerror(*error));
	return -1;

    }

    return 0;

}

void set_discover_net_cb(process_new_service cb)
{
    process_services.cb=cb;
}

static unsigned int convert_avahi_service_type(const char *name, unsigned int *depends)
{

    if (strcmp(name, "_sftp-ssh._tcp")==0) {

	if (depends) *depends=WORKSPACE_SERVICE_SSH;
	return WORKSPACE_SERVICE_SFTP;

    } else if (strcmp(name, "_ssh._tcp")==0) {

	return WORKSPACE_SERVICE_SSH;

    } else if (strcmp(name, "_smb._tcp")==0) {

	return WORKSPACE_SERVICE_SMB;

    } else if (strcmp(name, "_nfs._tcp")==0) {

	return WORKSPACE_SERVICE_NFS;

    }

    return 0;

}

static void process_services_thread(void *ptr)
{
    struct timespec since={0, 0};

    pthread_mutex_lock(&process_services.mutex);
    process_services.threadid=pthread_self();
    process_services.changed=0;
    memcpy(&since, &process_services.since, sizeof(struct timespec));
    pthread_mutex_unlock(&process_services.mutex);

    process:

    /* get all the services found since */

    get_net_services(&since, process_services.cb, NULL);

    pthread_mutex_lock(&process_services.mutex);

    if (process_services.changed==1) {

	process_services.changed=0;
	pthread_mutex_unlock(&process_services.mutex);
	goto process;

    }

    process_services.threadid=0;
    memcpy(&process_services.since, &since, sizeof(struct timespec));
    pthread_mutex_unlock(&process_services.mutex);

}

static void start_get_service_thread(struct timespec *since)
{

    pthread_mutex_lock(&process_services.mutex);

    if (process_services.threadid>0) {

	/* there is already a thread */

	process_services.changed=1;

    } else {
	unsigned int error=0;

	memcpy(&process_services.since, since, sizeof(struct timespec));
	work_workerthread(NULL, 0, process_services_thread, NULL, &error);

	if (error>0) {

	    logoutput_info("start_get_service_thread: error %i:%s starting thread", error, strerror(error));

	}

    }

    pthread_mutex_unlock(&process_services.mutex);

}

static unsigned int add_net_service_common(unsigned int code, char *hostname, char *ip, unsigned int port, unsigned int method, unsigned int depends)
{
    int lock=0;
    unsigned int result=0;

    if (check_family_ip_address(ip, "ipv4") != 1) {

	logoutput("add_net_service_common: address %s not supported", ip);
	return 0;

    }

    /* try to get the lock to add services
	it is possible the list may be in use for a **long** time
	and waiting for the lock to release takes too long
	so if the lock is busy: queue the values to be picked up later */

    lock=pthread_mutex_trylock(&hosts_found.mutex);

    if (lock==0) {
	struct context_address_s address;
	unsigned int error=0;
	unsigned int added=0;
	struct timespec since;

	get_current_time(&since);

	/* got the lock to the normal list */

	memset(&address, 0, sizeof(struct context_address_s));
	address.network.type=_INTERFACE_ADDRESS_NETWORK;

	if (method==DISCOVER_METHOD_AVAHI) {

	    /* do not trust the hostname reported by AVAHI */

	    set_host_address(&address.network.target.host, NULL, ip, NULL);

	} else {

	    set_host_address(&address.network.target.host, hostname, ip, NULL);

	}

	address.service.type=_INTERFACE_SERVICE_PORT;
	address.service.target.port.port=port;
	address.service.target.port.type=_INTERFACE_PORT_TCP; /* for sure? TODO add flag for TCP and/or UDP */

	added=add_net_service_unlocked(code, method, &address, 0, &error);
	if (error>0) logoutput_info("add_net_service_avahi: error %i:%s", error, strerror(error));

	/* if service is a new or added but found earlier process futher */

        if (added & (_ADD_NET_SERVICE_SERVICE | _ADD_NET_SERVICE_SERVICE_EXIST)) start_get_service_thread(&since);
	if (added & _ADD_NET_SERVICE_SERVICE) result++;

	pthread_mutex_unlock(&hosts_found.mutex);

    } else if (lock==EBUSY) {
	struct context_address_s address;

	/* list is locked: queue it to be processed later */

	memset(&address, 0, sizeof(struct context_address_s));
	address.network.type=_INTERFACE_ADDRESS_NETWORK;

	if (method==DISCOVER_METHOD_AVAHI) {

	    /* do not trust the hostname reported by AVAHI */

	    set_host_address(&address.network.target.host, NULL, ip, NULL);

	} else {

	    set_host_address(&address.network.target.host, hostname, ip, NULL);

	}

	address.service.type=_INTERFACE_SERVICE_PORT;
	address.service.target.port.port=port;
	address.service.target.port.type=_INTERFACE_PORT_TCP; /* for sure? TODO add flag for TCP and/or UDP */

	queue_service_found(code, method, depends, &address);
	result++; /* dont know it has been processes earlier */

    } else {

	logoutput_warning("add_net_service_avahi: error %i:%s", lock, strerror(lock));

    }

    return result;

}

unsigned int add_net_service_generic(const char *type, char *hostname, char *ip, unsigned int port, unsigned char method)
{

    if (method==DISCOVER_METHOD_AVAHI) {
	unsigned int depends=0;
	unsigned int service=convert_avahi_service_type(type, &depends);

	if (service>0) {
	    unsigned int len=(hostname) ? strlen(hostname) : 0;
	    char realhostname[len + 1];

	    memset(realhostname, '\0', len + 1);
	    memcpy(realhostname, hostname, len);

	    if (len>0) {
		char *sep=memrchr(realhostname, '.', len);

		if (sep && strncmp(sep, ".local", 6)==0) *sep='\0';

	    }

	    logoutput("add_net_service_generic: type %s host %s ip %s port %i", type, realhostname, ip, port);

	    /* TODO: get the **real** hostname, the hostname with avvahi has this .local appended, irritating */

	    return add_net_service_common(service, realhostname, ip, port, DISCOVER_METHOD_AVAHI, depends);

	}

    } else {
	unsigned int code=0;
	unsigned int depends=0;

	if (strcmp(type, "tcp:sftp")==0 || strcmp(type, "tcp:ssh/sftp")==0) {

	    code=WORKSPACE_SERVICE_SFTP;
	    depends=WORKSPACE_SERVICE_SSH;

	} else if (strcmp(type, "tcp:smb")==0) {

	    code=WORKSPACE_SERVICE_SMB;

	} else if (strcmp(type, "tcp:nfs")==0) {

	    code=WORKSPACE_SERVICE_NFS;

	} else {

	    logoutput_warning("add_net_service_generic: type %s not reckognized", type);

	}

	if (code>0) return add_net_service_common(code, hostname, ip, port, method, depends);

    }

    return 0;

}

void free_discover_records()
{
    struct list_element_s *hlist=NULL;
    struct list_element_s *slist=NULL;
    struct host_found_s *host=NULL;
    struct service_found_s *service=NULL;

    hlist=get_list_head(&hosts_found.hosts, SIMPLE_LIST_FLAG_REMOVE);

    while (hlist) {

	host=get_container_host(hlist);
	slist=get_list_head(&host->services,  SIMPLE_LIST_FLAG_REMOVE);

	while (slist) {

	    service=get_container_service(slist);
	    free(service);
	    service=NULL;

	    slist=get_list_head(&host->services,  SIMPLE_LIST_FLAG_REMOVE);

	}

	pthread_mutex_destroy(&host->mutex);
	free(host);

	hlist=get_list_head(&hosts_found.hosts,  SIMPLE_LIST_FLAG_REMOVE);

    }

    pthread_mutex_destroy(&hosts_found.mutex);
    pthread_mutex_destroy(&process_services.mutex);
    pthread_mutex_destroy(&discover_queue.mutex);

    free_group(&servicegroup, NULL);

}
