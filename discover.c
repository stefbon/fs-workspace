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
#include "main.h"
#include "simple-list.h"
#include "simple-hash.h"
#include "workerthreads.h"

#include "workspace-interface.h"
#include "options.h"
#include "utils.h"
#include "discover.h"

extern struct fs_options_struct fs_options;

/*
    keep track of services on the network like:
    - ssh-sftp
    - webdav
    - smb
*/

struct head_common_s {
    struct list_element_s				*head;
    struct list_element_s				*tail;
};

struct host_found_s;

struct service_found_s {
    unsigned long					id;
    unsigned int 					service;
    struct host_found_s					*host;
    unsigned int					method;
    struct context_address_s 				address;
    struct timespec					found;
    unsigned long					refcount;
    struct list_element_s				list;
};

struct host_found_s {
    unsigned long					id;
    unsigned int					method;
    char						*hostname;
    char						ipv4[INET_ADDRSTRLEN];
    char						ipv6[INET6_ADDRSTRLEN];
    struct timespec					found;
    struct timespec					changed;
    pthread_mutex_t					mutex;
    struct list_element_s				list;
    unsigned int					refcount;
    unsigned int					count;
    struct head_common_s				services;
};

struct hosts_found_s {
    unsigned int					count;
    struct timespec					changed;
    pthread_mutex_t					mutex;
    unsigned long 					hostid;
    unsigned long 					serviceid;
    struct head_common_s				hosts;
};

struct queue_element_s {
    unsigned int					method;
    char 						*hostname;
    unsigned int					service;
    char 						ipv4[INET_ADDRSTRLEN];
    unsigned int					port;
    struct queue_element_s				*next;
};

struct queue_head_s {
    struct queue_element_s				*head;
    struct queue_element_s				*tail;
    unsigned int					count;
    pthread_mutex_t 					mutex;
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
static struct queue_head_s discover_queue;
static struct process_services_s process_services;

static void free_service_found(struct service_found_s *service);

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
    free_service_found(service);
}

static void queue_service_found(unsigned int method, char *hostname, unsigned int service, char *ipv4, unsigned int port)
{
    struct queue_element_s *queue=malloc(sizeof(struct queue_element_s));

    if (queue) {

	queue->method=method;
	queue->hostname=strdup(hostname);
	queue->service=service;
	strcpy(queue->ipv4, ipv4);
	queue->port=port;
	queue->next=NULL;

	pthread_mutex_lock(&discover_queue.mutex);

	if (discover_queue.head==NULL) {

	    discover_queue.head=queue;
	    discover_queue.tail=queue;

	} else {

	    discover_queue.tail->next=queue;
	    discover_queue.tail=queue;

	}

	discover_queue.count++;
	pthread_mutex_unlock(&discover_queue.mutex);

    }

}

struct queue_element_s *get_next_queued_service_found()
{
    struct queue_element_s *queue=NULL;

    pthread_mutex_lock(&discover_queue.mutex);

    if (discover_queue.head) {

	queue=discover_queue.head;

	if (queue->next==NULL) {

	    discover_queue.head=NULL;
	    discover_queue.tail=NULL;

	} else {

	    discover_queue.head=queue->next;

	}

	discover_queue.count--;
	queue->next=NULL;

    }

    pthread_mutex_unlock(&discover_queue.mutex);
    return queue;

}

static struct host_found_s *get_container_host(struct list_element_s *list)
{
    return (struct host_found_s *) ( ((char *) list) - offsetof(struct host_found_s, list));
}

static struct service_found_s *get_container_service(struct list_element_s *list)
{
    return (struct service_found_s *) ( ((char *) list) - offsetof(struct service_found_s, list));
}

static int compare_context_address(struct context_address_s *a, struct context_address_s *b)
{
    /*	compare addresses they are the same
	- what if a is ipv4, b is ipv6 (or vice versa), but the target service is the same (just the route to it is different?)
	- what is the addresses are the same, but the service is different? (for example ssh and sftp)
    */

    if (a->type==b->type) {

	if (a->type==_INTERFACE_SMB_SERVERSHARE) {

	    if (strcmp(a->target.smbshare.server, b->target.smbshare.server)==0 && strcmp(a->target.smbshare.share, b->target.smbshare.share)==0) return 0;

	} else if (a->type==_INTERFACE_NETWORK_IPV4 || a->type==_INTERFACE_NETWORK_IPV6) {

	    if (strcmp(a->target.network.address, b->target.network.address)==0 && a->target.network.port==b->target.network.port) return 0;

	}

    }

    return -1;
}

static int set_service_context_address(struct host_found_s *host, struct context_address_s *a, struct context_address_s *b)
{

    a->type=b->type;
    a->target.network.port=b->target.network.port;

    if (b->type==_INTERFACE_NETWORK_IPV4) {

	/* compare the ipv4 of the host */

	if (strcmp(b->target.network.address, host->ipv4)==0) {

	    a->target.network.address=host->ipv4; /* no need to be allocated ; note to not te be freed later */

	} else {

	    a->target.network.address=strdup(b->target.network.address);

	    if (! a->target.network.address) {

		logoutput_warning("set_service_context_address: error allocating memory for networkaddress %s", b->target.network.address);
		return -1;

	    }

	}

    } else if (b->type==_INTERFACE_NETWORK_IPV6) {

	/* compare the ipv6 of the host */

	if (strcmp(b->target.network.address, host->ipv6)==0) {

	    a->target.network.address=host->ipv6; /* no need to be allocated ; note to not te be freed later */

	} else {

	    a->target.network.address=strdup(b->target.network.address);

	    if (! a->target.network.address) {

		logoutput_warning("set_service_context_address: error allocating memory for networkaddress %s", b->target.network.address);
		return -1;

	    }

	}

    } else if (b->type==_INTERFACE_SMB_SERVERSHARE) {

	/* compare server name with hostname */

	if (strcmp(b->target.smbshare.server, host->hostname)==0) {

	    a->target.smbshare.server=host->hostname;

	} else {

	    a->target.smbshare.server=strdup(b->target.smbshare.server);

	}

	a->target.smbshare.share=strdup(b->target.smbshare.share);

	if (! a->target.smbshare.share || ! a->target.smbshare.server) {

	    logoutput_warning("set_service_context_address: error allocating memory for smb servershare");
	    return -1;

	}

    }

    return 0;

}

static void free_service_context_address(struct host_found_s *host, struct context_address_s *a)
{

    if (a->type==_INTERFACE_NETWORK_IPV4) {

	if (a->target.network.address!=host->ipv4) free(a->target.network.address);
	a->target.network.address=NULL;

    } else if (a->type==_INTERFACE_NETWORK_IPV6) {

	if (a->target.network.address!=host->ipv6) free(a->target.network.address);
	a->target.network.address=NULL;

    } else if (a->type==_INTERFACE_SMB_SERVERSHARE) {

	if (a->target.smbshare.server!=host->hostname) free(a->target.smbshare.server);
	a->target.smbshare.server=NULL;

    }

}

static void free_service_found(struct service_found_s *service)
{
    free_service_context_address(service->host, &service->address);
    free(service);
}

static void process_nothing(unsigned int service, struct context_address_s *address, struct timespec *found, unsigned long hostid, unsigned long serviceid, void *ptr)
{
}

#define _ADD_NET_SERVICE_HOST						1
#define _ADD_NET_SERVICE_SERVICE					2
#define _ADD_NET_SERVICE_HOST_EXIST					4
#define _ADD_NET_SERVICE_SERVICE_EXIST					8

static unsigned int add_net_service_unlocked(unsigned int method, char *hostname, unsigned int code, struct context_address_s *address, unsigned char queued, unsigned int *error)
{
    struct host_found_s *host=NULL;
    struct list_element_s *list=NULL;
    struct service_found_s *service=NULL;
    unsigned int result=0;

    logoutput("add_net_service_unlocked: add %s/service %i", hostname, code);

    /* add a service
	- lookup the hostname and create host if not found
	- lookup the service and create it of not found
    */

    *error=0;

    list=hosts_found.hosts.head;

    while(list) {

	host=get_container_host(list);
	if (strcmp(hostname, host->hostname)==0) break;
	list=list->next;
	host=NULL;

    }

    if (! host) {

	host=malloc(sizeof(struct host_found_s));

	if (host) {

	    memset(host, 0, sizeof(struct host_found_s));
	    hosts_found.hostid++;
	    host->id=hosts_found.hostid;
	    host->method=method;

	    if (queued==0) {

		host->hostname=strdup(hostname);

	    } else {

		host->hostname=hostname;

	    }

	    if (address->type==_INTERFACE_NETWORK_IPV4) {

		strcpy(host->ipv4, address->target.network.address);

	    } else if (address->type==_INTERFACE_NETWORK_IPV6) {

		strcpy(host->ipv6, address->target.network.address);

	    }

	    get_current_time(&host->found);
	    host->changed.tv_sec=0;
	    host->changed.tv_nsec=0;

	    pthread_mutex_init(&host->mutex, NULL);
	    host->list.next=NULL;
	    host->list.prev=NULL;
	    host->refcount=0;
	    host->count=0;
	    host->services.tail=NULL;
	    host->services.head=NULL;

	    add_list_element_first(&hosts_found.hosts.head, &hosts_found.hosts.tail, &host->list);

	    result |= _ADD_NET_SERVICE_HOST;

	} else {

	    *error=ENOMEM;
	    return result;

	}

    } else {

	result |= _ADD_NET_SERVICE_HOST_EXIST;

    }

    list=host->services.head;

    while (list) {

	service=get_container_service(list);

	if (compare_context_address(&service->address, address)==0) break;
	list=list->next;
	service=NULL;

    }

    if (! service) {

	service=malloc(sizeof(struct service_found_s));

	if (service) {

	    memset(service, 0, sizeof(struct service_found_s));
	    hosts_found.serviceid++;
	    service->id=hosts_found.serviceid;
	    service->service=code;
	    service->method=method;
	    service->host=host;

	    if (set_service_context_address(host, &service->address, address)==-1) {

		free_service_found(service);
		*error=ENOMEM;
		return result;

	    }

	    get_current_time(&service->found);
	    service->refcount=0;
	    memcpy(&hosts_found.changed, &service->found, sizeof(struct timespec));

	    add_list_element_first(&host->services.head, &host->services.tail, &service->list);
	    add_service_servicegroup(service);
	    result |= _ADD_NET_SERVICE_SERVICE;

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

    hlist=hosts_found.hosts.head;

    while (hlist) {

	host=get_container_host(hlist);
	slist=host->services.head;

	while (slist) {

	    service=get_container_service(slist);

	    if (service->found.tv_sec > since->tv_sec || (service->found.tv_sec == since->tv_sec && service->found.tv_nsec > since->tv_nsec)) {

		(* cb)(service->service, &service->address, &service->found, host->id, service->id, ptr);

		if (service->found.tv_sec > maxfound.tv_sec || (service->found.tv_sec == maxfound.tv_sec && service->found.tv_nsec > maxfound.tv_nsec)) {

		    maxfound.tv_sec=service->found.tv_sec;
		    maxfound.tv_nsec=service->found.tv_nsec;

		}

	    }

	    slist=slist->next;

	}

	hlist=hlist->next;

    }

    /* adjust the since time to get only the new services */
    since->tv_sec=maxfound.tv_sec; 
    since->tv_nsec=maxfound.tv_nsec;

    /* test the queue */

    logoutput("get_net_services: test queue");

    added=0;
    queue=get_next_queued_service_found();

    while (queue) {
	unsigned int result=0;
	unsigned int error=0;
	struct context_address_s address;

	memset(&address, 0, sizeof(struct context_address_s));
	address.type=_INTERFACE_NETWORK_IPV4;
        address.target.network.address=queue->ipv4;
	address.target.network.port=queue->port;

	result=add_net_service_unlocked(queue->method, queue->hostname, queue->service, &address, 1, &error);

	if (!(result & _ADD_NET_SERVICE_HOST)) free(queue->hostname);
	queue->hostname=NULL;
	if (result & _ADD_NET_SERVICE_SERVICE) added++;
	free(queue);

	queue=get_next_queued_service_found();

    }

    if (added>0) goto processlist;

    pthread_mutex_unlock(&hosts_found.mutex);

    logoutput("get_net_services: ready");

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
    hosts_found.hosts.head=NULL;
    hosts_found.hosts.tail=NULL;

    /* process the changes */

    process_services.cb=process_nothing;
    process_services.threadid=0;
    pthread_mutex_init(&process_services.mutex, NULL);
    process_services.changed=0;
    process_services.since.tv_sec=0;
    process_services.since.tv_nsec=0;

    /* queue */

    discover_queue.head=NULL;
    discover_queue.tail=NULL;
    discover_queue.count=0;
    pthread_mutex_init(&discover_queue.mutex, NULL);

    if (initialize_group(&servicegroup, id_hashfunction, 128, error)==0) {

	logoutput("init_discover_group: initialized");

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

static unsigned int convert_avahi_service_type(const char *name)
{

    if (strcmp(name, "_sftp-ssh._tcp")==0) {

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

	    logoutput("start_get_service_thread: error %i:%s starting thread", error, strerror(error));

	}

    }

    pthread_mutex_unlock(&process_services.mutex);

}

static void add_net_service_common(unsigned int service, char *hostname, char *ipv4, unsigned int port, unsigned int method)
{
    int lock=0;

    /* try to get the lock to add services
	it is possible the list may be in use for a **long** time
	and waiting for the lock to release takes too long
	so if the lock is busy: queue the values to be picked up later */

    lock=pthread_mutex_trylock(&hosts_found.mutex);

    if (lock==0) {
	struct context_address_s address;
	unsigned int error=0;
	unsigned int result=0;
	struct timespec since;

	get_current_time(&since);

	/* got the lock to the normal list */

	memset(&address, 0, sizeof(struct context_address_s));
	address.type=_INTERFACE_NETWORK_IPV4;
	address.target.network.address=ipv4;
	address.target.network.port=port;

	result=add_net_service_unlocked(method, hostname, service, &address, 0, &error);
	if (error>0) logoutput_info("add_net_service_avahi: error %i:%s", error, strerror(error));

	/* if service is a new or added but found earlier process futher */

        if (result & (_ADD_NET_SERVICE_SERVICE | _ADD_NET_SERVICE_SERVICE_EXIST)) {

	    /* activate a thread */

	    start_get_service_thread(&since);

	}

	pthread_mutex_unlock(&hosts_found.mutex);

    } else if (lock==EBUSY) {

	/* list is locked: queue it to be processed later */

	queue_service_found(method, hostname, service, ipv4, port);

    } else {

	logoutput_warning("add_net_service_avahi: error %i:%s", lock, strerror(lock));

    }

}

void add_net_service_avahi(const char *type, char *hostname, char *ipv4, unsigned int port)
{
    unsigned int service=convert_avahi_service_type(type);

    if (service>0) {

	logoutput("add_net_service_avahi: type %s host %s ip %s port %i", type, hostname, ipv4, port);
	add_net_service_common(service, hostname, ipv4, port, DISCOVER_METHOD_AVAHI);

    } else {

	logoutput("add_net_service_avahi: type %s not reckognized", type);

    }

}

void add_net_service_staticfile(const char *type, char *hostname, char *ipv4, unsigned int port)
{
    unsigned int service=0;

    if (strcmp(type, "tcp:sftp")==0) {

	service=WORKSPACE_SERVICE_SFTP;

    } else if (strcmp(type, "tcp:smb")==0) {

	service=WORKSPACE_SERVICE_SMB;

    } else if (strcmp(type, "tcp:nfs")==0) {

	service=WORKSPACE_SERVICE_NFS;

    } else {

	logoutput("add_net_service_staticfile: type %s not reckognized", type);

    }

    if (service>0) {

	logoutput("add_net_service_staticfile: type %s host %s ip %s port %i", type, hostname, ipv4, port);    
	add_net_service_common(service, hostname, ipv4, port, DISCOVER_METHOD_STATICFILE);

    }

}

void free_discover_records()
{
    struct list_element_s *hlist=NULL;
    struct list_element_s *slist=NULL;
    struct host_found_s *host=NULL;
    struct service_found_s *service=NULL;

    hlist=get_list_head(&hosts_found.hosts.head, &hosts_found.hosts.tail);

    while (hlist) {

	host=get_container_host(hlist);
	slist=get_list_head(&host->services.head, &host->services.tail);

	while (slist) {

	    service=get_container_service(slist);
	    free_service_found(service);

	    slist=get_list_head(&host->services.head, &host->services.tail);

	}

	pthread_mutex_destroy(&host->mutex);
	free(host);

	hlist=get_list_head(&hosts_found.hosts.head, &hosts_found.hosts.tail);

    }

    pthread_mutex_destroy(&hosts_found.mutex);
    pthread_mutex_destroy(&process_services.mutex);
    pthread_mutex_destroy(&discover_queue.mutex);

    free_group(&servicegroup, NULL);

}
