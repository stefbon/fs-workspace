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

#ifndef CTX_KEYSTORE_OPENSSH_UTILS_H
#define CTX_KEYSTORE_OPENSSH_UTILS_H

#include <pwd.h>

/* prototypes */

unsigned int get_path_openssh_user(struct passwd *pwd, char *path, char *buffer, unsigned int len);
unsigned int get_path_openssh_system(char *path, char *buffer, unsigned int len);

unsigned int open_file_ssh_user(struct passwd *pwd, char *path, struct stat *st, unsigned int *error);
unsigned int open_file_ssh_system(struct passwd *pwd, char *path, struct stat *st, unsigned int *error);
unsigned int openat_file_ssh(struct passwd *pwd, unsigned int dfd, char *name, unsigned char user, struct stat *st, unsigned int *error);

int stat_file_ssh_user(struct passwd *pwd, char *path, struct stat *st, unsigned int *error);
int stat_file_ssh_system(struct passwd *pwd, char *path, struct stat *st, unsigned int *error);

#endif
