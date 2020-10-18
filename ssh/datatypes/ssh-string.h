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

#ifndef FS_WORKSPACE_SSH_DATATYPES_STRING_H
#define FS_WORKSPACE_SSH_DATATYPES_STRING_H

#define SSH_STRING_FLAG_HEADER				1
#define SSH_STRING_FLAG_DATA				2

struct ssh_string_s {
    unsigned int			len;
    char				*ptr;
};

/* prototypes */

void init_ssh_string(struct ssh_string_s *s);
void free_ssh_string(struct ssh_string_s *s);
unsigned int create_ssh_string(struct ssh_string_s *s, unsigned int len, char *data);
int compare_ssh_string(struct ssh_string_s *t, const unsigned char type, void *ptr);
int create_copy_ssh_string(struct ssh_string_s *t, struct ssh_string_s *s);
unsigned int get_ssh_string_length(struct ssh_string_s *s, unsigned int flags);

unsigned int read_ssh_string_header(char *buffer, unsigned int size, unsigned int *len);
unsigned int write_ssh_string_header(char *buffer, unsigned int size, unsigned int len);

unsigned int read_ssh_string(char *buffer, unsigned int size, struct ssh_string_s *s);
int get_ssh_string_from_buffer(char **b, unsigned int size, struct ssh_string_s *s);
unsigned int write_ssh_string(char *buffer, unsigned int size, const unsigned char type, void *ptr);
void move_ssh_string(struct ssh_string_s *a, struct ssh_string_s *b);
int ssh_string_compare(struct ssh_string_s *s, const unsigned char type, void *ptr);
unsigned int buffer_count_strings(char *buffer, unsigned int size, unsigned int max);

#endif
