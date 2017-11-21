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

#ifndef FS_WORKSPACE_SFTP_LOCK_H
#define FS_WORKSPACE_SFTP_LOCK_H

void _fs_sftp_flock(struct fuse_openfile_s *openfile, struct fuse_request_s *r, unsigned char type);
void _fs_sftp_getlock(struct fuse_openfile_s *openfile, struct fuse_request_s *f_request, struct flock *flock);
void _fs_sftp_setlock(struct fuse_openfile_s *openfile, struct fuse_request_s *f_request, struct flock *flock);
void _fs_sftp_setlockw(struct fuse_openfile_s *openfile, struct fuse_request_s *f_request, struct flock *flock);

#endif
