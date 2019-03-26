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

#ifndef FS_WORKSPACE_SFTP_COMMON_UTILS_H
#define FS_WORKSPACE_SFTP_COMMON_UTILS_H

/* prototypes */

int get_session_status_ctx(struct context_interface_s *interface);

int complete_path_sftp_home(struct context_interface_s *interface, char *buffer, struct pathinfo_s *pathinfo);
int complete_path_sftp_root(struct context_interface_s *interface, char *buffer, struct pathinfo_s *pathinfo);
int complete_path_sftp_custom(struct context_interface_s *interface, char *buffer, struct pathinfo_s *pathinfo);

unsigned int get_complete_pathlen_home(struct context_interface_s *interface, unsigned int len);
unsigned int get_complete_pathlen_root(struct context_interface_s *interface, unsigned int len);
unsigned int get_complete_pathlen_custom(struct context_interface_s *interface, unsigned int len);

int check_realpath_sftp(struct context_interface_s *interface, char *path, char **remote_target);

void sftp_fsnotify_event(struct sftp_subsystem_s *sftp, uint64_t unique, uint32_t mask, struct ssh_string_s *who, struct ssh_string_s *host, struct ssh_string_s *file);
unsigned int get_sftp_remote_home(void *ptr, struct ssh_string_s *home);

#endif
