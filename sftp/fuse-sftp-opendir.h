/*
  2010, 2011, 2012, 2013, 2014, 2015 Stef Bon <stefbon@gmail.com>

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

#ifndef _FS_WORKSPACE_SFTP_OPENDIR_H
#define _FS_WORKSPACE_SFTP_OPENDIR_H

void _fs_sftp_opendir(struct fuse_opendir_s *opendir, struct fuse_request_s *r, struct pathinfo_s *pathinfo, unsigned int flags);
void _fs_sftp_readdir(struct fuse_opendir_s *opendir, struct fuse_request_s *r, size_t size, off_t offset);
void _fs_sftp_readdirplus(struct fuse_opendir_s *opendir, struct fuse_request_s *r, size_t size, off_t offset);
void _fs_sftp_fsyncdir(struct fuse_opendir_s *opendir, struct fuse_request_s *r, unsigned char datasync);
void _fs_sftp_releasedir(struct fuse_opendir_s *opendir, struct fuse_request_s *r);

#endif
