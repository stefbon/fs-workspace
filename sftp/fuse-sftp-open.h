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

#ifndef FS_WORKSPACE_SFTP_OPEN_H
#define FS_WORKSPACE_SFTP_OPEN_H

void _fs_sftp_open(struct fuse_openfile_s *openfile, struct fuse_request_s *f, struct pathinfo_s *pathinfo, unsigned int flags);
void _fs_sftp_create(struct fuse_openfile_s *openfile,struct fuse_request_s *f, struct pathinfo_s *pathinfo, struct stat *st, unsigned int flags);
void _fs_sftp_read(struct fuse_openfile_s *openfile, struct fuse_request_s *f, size_t size, off_t off, unsigned int flags, uint64_t lock_owner);
void _fs_sftp_write(struct fuse_openfile_s *openfile, struct fuse_request_s *f, const char *buff, size_t size, off_t off, unsigned int flags, uint64_t lock_owner);
void _fs_sftp_flush(struct fuse_openfile_s *openfile, struct fuse_request_s *f, uint64_t lockowner);
void _fs_sftp_fsync(struct fuse_openfile_s *openfile, struct fuse_request_s *f, unsigned char datasync);
void _fs_sftp_release(struct fuse_openfile_s *openfile, struct fuse_request_s *f, unsigned int flags, uint64_t lock_owner);

void _fs_sftp_open_disconnected(struct fuse_openfile_s *openfile, struct fuse_request_s *f_request, struct pathinfo_s *pathinfo, unsigned int flags);
void _fs_sftp_create_disconnected(struct fuse_openfile_s *openfile, struct fuse_request_s *f_request, struct pathinfo_s *pathinfo, struct stat *st, unsigned int flags);
void _fs_sftp_read_disconnected(struct fuse_openfile_s *openfile, struct fuse_request_s *f_request, size_t size, off_t off, unsigned int flags, uint64_t lock_owner);
void _fs_sftp_write_disconnected(struct fuse_openfile_s *openfile, struct fuse_request_s *f_request, const char *buff, size_t size, off_t off, unsigned int flags, uint64_t lock_owner);
void _fs_sftp_fsync_disconnected(struct fuse_openfile_s *openfile, struct fuse_request_s *f_request, unsigned char datasync);
void _fs_sftp_flush_disconnected(struct fuse_openfile_s *openfile, struct fuse_request_s *f_request, uint64_t lockowner);
void _fs_sftp_release_disconnected(struct fuse_openfile_s *openfile, struct fuse_request_s *f_request, unsigned int flags, uint64_t lock_owner);

#endif
