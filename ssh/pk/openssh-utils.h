/*
  2017, 2018 Stef Bon <stefbon@gmail.com>

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

#ifndef FS_WORKSPACE_SSH_PK_OPENSSH_UTILS_H
#define FS_WORKSPACE_SSH_PK_OPENSSH_UTILS_H

#include <pwd.h>

/* prototypes */

int _match_pattern_host(char *host, char *hostpattern, unsigned int level);

unsigned int get_path_openssh_user(struct passwd *pwd, char *path, char *buffer, unsigned int len);
unsigned int get_path_openssh_system(char *path, char *buffer, unsigned int len);

unsigned int get_directory_openssh_common(struct passwd *pwd, const char *what, char *buffer, unsigned int len);

unsigned int open_file_ssh_user(struct passwd *pwd, char *path, struct stat *st, unsigned int *error);
unsigned int open_file_ssh_system(struct passwd *pwd, char *path, struct stat *st, unsigned int *error);

int stat_file_ssh_user(struct passwd *pwd, char *path, struct stat *st, unsigned int *error);
int stat_file_ssh_system(struct passwd *pwd, char *path, struct stat *st, unsigned int *error);

#endif
