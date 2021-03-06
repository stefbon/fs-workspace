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

#ifndef FS_WORKSPACE_DISCOVER_H
#define FS_WORKSPACE_DISCOVER_H

#define WORKSPACE_SERVICE_SMB				1
#define WORKSPACE_SERVICE_SFTP				2
#define WORKSPACE_SERVICE_SSH				0 /* is not an fs */
#define WORKSPACE_SERVICE_WEBDAV			4
#define WORKSPACE_SERVICE_NFS				5

#define DISCOVER_METHOD_AVAHI				1
#define DISCOVER_METHOD_STATICFILE			2
#define DISCOVER_METHOD_FSTREE				3

/*
    TODO:
    - add discovery of ssh servers by scanning sshd_config (system and personal)
    - add discovery of servers by scanning the network (nmap..)
*/

// Prototypes

typedef void (*process_new_service)(struct host_address_s *host, struct service_address_s *s, unsigned int code, struct timespec *found, unsigned long hostid, unsigned long serviceid, void *ptr);
void get_net_services(struct timespec *since, process_new_service cb, void *ptr);

unsigned int add_net_service_generic(const char *type, char *hostname, char *ip, unsigned int port, unsigned char method);

void increase_service_refcount(unsigned long id);
void decrease_service_refcount(unsigned long id);

int init_discover_group(unsigned int *error);
void set_discover_net_cb(process_new_service cb);

#endif
