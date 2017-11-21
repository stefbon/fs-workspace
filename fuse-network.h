/*
  2010, 2011, 2012 Stef Bon <stefbon@gmail.com>

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

#ifndef FS_WORKSPACE_FUSE_NETWORK_H
#define FS_WORKSPACE_FUSE_NETWORK_H

struct entry_s *create_network_map_entry(struct workspace_mount_s *workspace, struct directory_s *directory, struct name_s *xname, unsigned int *error);
void install_net_services_cb(unsigned int service, struct context_address_s *address, struct timespec *found, unsigned long hostid, unsigned long serviceid, void *ptr);

#endif
