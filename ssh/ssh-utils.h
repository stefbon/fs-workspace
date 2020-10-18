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

#define SKIPSPACE_FLAG_REPLACEBYZERO		1

#define REPLACE_CNTRL_FLAG_TEXT			1
#define REPLACE_CNTRL_FLAG_BINARY		2

#include "datatypes/ssh-string.h"

#define SSH_HASH_TYPE_MD5			1
#define SSH_HASH_TYPE_SHA1			2
#define SSH_HASH_TYPE_SHA256			3
#define SSH_HASH_TYPE_SHA512			4
#define SSH_HASH_TYPE_SHA3_256			5
#define SSH_HASH_TYPE_SHA3_512			6

struct ssh_hash_s {
    char					name[32];
    unsigned int				size;
    unsigned int				len;
    unsigned char				digest[];
};

/* prototypes */

unsigned int get_hash_size(const char *name);
void init_ssh_hash(struct ssh_hash_s *hash, char *name, unsigned int size);
unsigned int create_hash(char *in, unsigned int size, struct ssh_hash_s *hash, unsigned int *error);
unsigned int fill_random(char *pos, unsigned int len);
int init_ssh_backend_library(unsigned int *error);
void init_ssh_utils();
uint64_t ntohll(uint64_t value);

void replace_cntrl_char(char *buffer, unsigned int size, unsigned char flag);
void replace_newline_char(char *ptr, unsigned int size);
unsigned int skip_trailing_spaces(char *ptr, unsigned int size, unsigned int flags);
unsigned int skip_heading_spaces(char *ptr, unsigned int size);

void logoutput_base64encoded(char *prefix, char *buffer, unsigned int size);

#endif
