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

#ifndef FS_WORKSPACE_MONITORMOUNTS_H
#define FS_WORKSPACE_MONITORMOUNTS_H

#define UMOUNT_WORKSPACE_FLAG_MOUNT				1
#define UMOUNT_WORKSPACE_FLAG_EXTRA				2

int add_mountinfo_watch(struct beventloop_s *loop, unsigned int *error);
void umount_mounts_found(struct fuse_user_s *user, unsigned int flags);

#endif
