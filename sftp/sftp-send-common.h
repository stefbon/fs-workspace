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

#ifndef FS_WORKSPACE_SFTP_SEND_COMMON_H
#define FS_WORKSPACE_SFTP_SEND_COMMON_H

/* prototypes */

int send_sftp_open_ctx(void *ptr, struct sftp_request_s *sftp_r);
int send_sftp_create_ctx(void *ptr, struct sftp_request_s *sftp_r);
int send_sftp_opendir_ctx(void *ptr, struct sftp_request_s *sftp_r);
int send_sftp_read_ctx(void *ptr, struct sftp_request_s *sftp_r);
int send_sftp_write_ctx(void *ptr, struct sftp_request_s *sftp_r);
int send_sftp_readdir_ctx(void *ptr, struct sftp_request_s *sftp_r);
int send_sftp_close_ctx(void *ptr, struct sftp_request_s *sftp_r);
int send_sftp_remove_ctx(void *ptr, struct sftp_request_s *sftp_r);
int send_sftp_rename_ctx(void *ptr, struct sftp_request_s *sftp_r);
int send_sftp_mkdir_ctx(void *ptr, struct sftp_request_s *sftp_r);
int send_sftp_rmdir_ctx(void *ptr, struct sftp_request_s *sftp_r);
int send_sftp_stat_ctx(void *ptr, struct sftp_request_s *sftp_r);
int send_sftp_lstat_ctx(void *ptr, struct sftp_request_s *sftp_r);
int send_sftp_fstat_ctx(void *ptr, struct sftp_request_s *sftp_r);
int send_sftp_setstat_ctx(void *ptr, struct sftp_request_s *sftp_r);
int send_sftp_fsetstat_ctx(void *ptr, struct sftp_request_s *sftp_r);
int send_sftp_readlink_ctx(void *ptr, struct sftp_request_s *sftp_r);
int send_sftp_symlink_ctx(void *ptr, struct sftp_request_s *sftp_r);
int send_sftp_block_ctx(void *ptr, struct sftp_request_s *sftp_r);
int send_sftp_unblock_ctx(void *ptr, struct sftp_request_s *sftp_r);
int send_sftp_realpath_ctx(void *ptr, struct sftp_request_s *sftp_r);

int send_sftp_fsync_ctx(void *ptr, struct sftp_request_s *sftp_r);
int send_sftp_statvfs_ctx(void *ptr, struct sftp_request_s *sftp_r);
int send_sftp_fstatvfs_ctx(void *ptr, struct sftp_request_s *sftp_r);
int send_sftp_fsnotify_ctx(void *ptr, struct sftp_request_s *sftp_r);

int get_support_sftp_ctx(void *ptr, const char *name);
void set_support_sftp_ctx(void *ptr, const char *name, int flag);

#endif
