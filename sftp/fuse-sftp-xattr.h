/*
  2010, 2011, 2012, 2013, 2014, 2015, 2016 Stef Bon <stefbon@gmail.com>

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

#ifndef FS_WORKSPACE_SFTP_XATTR_H
#define FS_WORKSPACE_SFTP_XATTR_H

void _fs_sftp_setxattr(struct service_context_s *context, struct fuse_request_s *request, struct pathinfo_s *pathinfo, struct inode_s *inode, const char *name, const char *value, size_t size, int flags);
void _fs_sftp_getxattr(struct service_context_s *context, struct fuse_request_s *request, struct pathinfo_s *pathinfo, struct inode_s *inode, const char *name, size_t size);
void _fs_sftp_listxattr(struct service_context_s *context, struct fuse_request_s *request, struct pathinfo_s *pathinfo, struct inode_s *inode, size_t size);
void _fs_sftp_removexattr(struct service_context_s *context, struct fuse_request_s *request, struct pathinfo_s *pathinfo, struct inode_s *inode, const char *name);

#endif
