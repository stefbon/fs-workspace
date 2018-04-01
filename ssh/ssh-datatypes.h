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

#ifndef FS_WORKSPACE_SSH_DATATYPES_H
#define FS_WORKSPACE_SSH_DATATYPES_H

#if HAVE_LIBGCRYPT
#include <gcrypt.h>
#endif

struct ssh_string_s {
    unsigned int			len;
    char				*ptr;
};

struct commalist_s {
    char 				*list;
    unsigned int 			len;
    unsigned int 			size;
};

struct ssh_pkalgo_s {
    unsigned int			id;
    const char				*name;
    unsigned int			len;
};

struct ssh_mpint_s {
    union {
#if HAVE_LIBGCRYPT
	gcry_mpi_t			mpi;
#endif
	void				*ptr;
    } lib;
};

/* prototypes */

void init_ssh_string(struct ssh_string_s *s);
void free_ssh_string(struct ssh_string_s *s);
unsigned int create_ssh_string(struct ssh_string_s *s, unsigned int len);
int get_ssh_string_from_buffer(char **b, unsigned int size, struct ssh_string_s *s);
unsigned int write_ssh_string(char *buffer, unsigned int size, const unsigned char type, void *ptr);

int read_pk_mpint(struct ssh_mpint_s *mp, char *buffer, unsigned int size, unsigned int *error);
int write_pk_mpint(struct ssh_mpint_s *mp, char *buffer, unsigned int size, unsigned int *error);

void free_pk_mpint(struct ssh_mpint_s *mp);
void init_pk_mpint(struct ssh_mpint_s *mp);

#endif
