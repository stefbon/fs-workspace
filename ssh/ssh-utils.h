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

#ifndef FS_WORKSPACE_SSH_UTILS_H
#define FS_WORKSPACE_SSH_UTILS_H

/* prototypes */

unsigned int create_hash(const char *name, char *in, unsigned int size, struct ssh_string_s *out, unsigned int *error);
unsigned int fill_random(char *pos, unsigned int len);
int init_ssh_backend_library(unsigned int *error);
void init_ssh_utils();
uint64_t ntohll(uint64_t value);
void replace_cntrl_char(char *buffer, unsigned int size);
void replace_newline_char(char *ptr, unsigned int *size);

#endif
