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

#ifndef FS_WORKSPACE_SFTP_SEND_V03_H
#define FS_WORKSPACE_SFTP_SEND_V03_H

/* prototypes */

int send_sftp_init_v03(struct sftp_subsystem_s *sftp_subsystem, unsigned int *seq);
int send_sftp_open_v03(struct sftp_subsystem_s *sftp_subsystem, struct sftp_request_s *sftp_r);
int send_sftp_create_v03(struct sftp_subsystem_s *sftp_subsystem, struct sftp_request_s *sftp_r);
int send_sftp_opendir_v03(struct sftp_subsystem_s *sftp_subsystem, struct sftp_request_s *sftp_r);
int send_sftp_read_v03(struct sftp_subsystem_s *sftp_subsystem, struct sftp_request_s *sftp_r);
int send_sftp_write_v03(struct sftp_subsystem_s *sftp_subsystem, struct sftp_request_s *sftp_r);
int send_sftp_readdir_v03(struct sftp_subsystem_s *sftp_subsystem, struct sftp_request_s *sftp_r);
int send_sftp_close_v03(struct sftp_subsystem_s *sftp_subsystem, struct sftp_request_s *sftp_r);
int send_sftp_remove_v03(struct sftp_subsystem_s *sftp_subsystem, struct sftp_request_s *sftp_r);
int send_sftp_rename_v03(struct sftp_subsystem_s *sftp_subsystem, struct sftp_request_s *sftp_r);
int send_sftp_mkdir_v03(struct sftp_subsystem_s *sftp_subsystem, struct sftp_request_s *sftp_r);
int send_sftp_rmdir_v03(struct sftp_subsystem_s *sftp_subsystem, struct sftp_request_s *sftp_r);
int send_sftp_stat_v03(struct sftp_subsystem_s *sftp_subsystem, struct sftp_request_s *sftp_r);
int send_sftp_lstat_v03(struct sftp_subsystem_s *sftp_subsystem, struct sftp_request_s *sftp_r);
int send_sftp_fstat_v03(struct sftp_subsystem_s *sftp_subsystem, struct sftp_request_s *sftp_r);
int send_sftp_setstat_v03(struct sftp_subsystem_s *sftp_subsystem, struct sftp_request_s *sftp_r);
int send_sftp_fsetstat_v03(struct sftp_subsystem_s *sftp_subsystem, struct sftp_request_s *sftp_r);
int send_sftp_readlink_v03(struct sftp_subsystem_s *sftp_subsystem, struct sftp_request_s *sftp_r);
int send_sftp_symlink_v03(struct sftp_subsystem_s *sftp_subsystem, struct sftp_request_s *sftp_r);
int send_sftp_block_v03(struct sftp_subsystem_s *sftp_subsystem, struct sftp_request_s *sftp_r);
int send_sftp_unblock_v03(struct sftp_subsystem_s *sftp_subsystem, struct sftp_request_s *sftp_r);
int send_sftp_realpath_v03(struct sftp_subsystem_s *sftp_subsystem, struct sftp_request_s *sftp_r);
int send_sftp_extension_v03(struct sftp_subsystem_s *sftp_subsystem, struct sftp_request_s *sftp_r);

int send_sftp_statvfs(struct sftp_subsystem_s *sftp_subsystem, struct sftp_request_s *sftp_r);
int send_sftp_fstatvfs(struct sftp_subsystem_s *sftp_subsystem, struct sftp_request_s *sftp_r);
int send_sftp_fsync(struct sftp_subsystem_s *sftp_subsystem, struct sftp_request_s *sftp_r);

void use_sftp_send_v03(struct sftp_subsystem_s *sftp_subsystem);

#endif

