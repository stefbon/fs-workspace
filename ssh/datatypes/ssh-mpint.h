/*
  2018 Stef Bon <stefbon@gmail.com>

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

#ifndef FS_WORKSPACE_SSH_DATATYPES_MPINT_H
#define FS_WORKSPACE_SSH_DATATYPES_MPINT_H

#if HAVE_LIBGCRYPT
#include <gcrypt.h>
#endif

#define SSH_MPINT_FORMAT_SSH		1
#define SSH_MPINT_FORMAT_USC		2

struct ssh_mpint_s {
    union {
#if HAVE_LIBGCRYPT
	gcry_mpi_t			mpi;
#endif
	void				*ptr;
    } lib;
};

struct ssh_mpoint_s {
    union {
#if HAVE_LIBGCRYPT
	gcry_mpi_t			mpi;
#endif
	void				*ptr;
    } lib;
};

/* prototypes */

int create_ssh_mpint(struct ssh_mpint_s *mp);
unsigned int get_nbits_ssh_mpint(struct ssh_mpint_s *mp);
unsigned int get_nbytes_ssh_mpint(struct ssh_mpint_s *mp);
void power_modulo_ssh_mpint(struct ssh_mpint_s *result, struct ssh_mpint_s *b, struct ssh_mpint_s *e, struct ssh_mpint_s *m);
int compare_ssh_mpint(struct ssh_mpint_s *a, struct ssh_mpint_s *b);
void swap_ssh_mpint(struct ssh_mpint_s *a, struct ssh_mpint_s *b);
int invm_ssh_mpint(struct ssh_mpint_s *x, struct ssh_mpint_s *a, struct ssh_mpint_s *m);
int randomize_ssh_mpint(struct ssh_mpint_s *mp, unsigned int bits);

void free_ssh_mpint(struct ssh_mpint_s *mp);
void init_ssh_mpint(struct ssh_mpint_s *mp);

int read_ssh_mpint(struct ssh_mpint_s *mp, char *buffer, unsigned int size, unsigned int format, unsigned int *error);
int write_ssh_mpint(struct ssh_mpint_s *mp, char *buffer, unsigned int size, unsigned int format, unsigned int *error);

void msg_read_ssh_mpint(struct msg_buffer_s *mb, struct ssh_mpint_s *mp, unsigned int *plen);
void msg_write_ssh_mpint(struct msg_buffer_s *mb, struct ssh_mpint_s *mp);

void init_ssh_mpoint(struct ssh_mpoint_s *mp);
void free_ssh_mpoint(struct ssh_mpoint_s *mp);

int compare_ssh_mpoint(struct ssh_mpoint_s *a, struct ssh_mpoint_s *b);

int read_ssh_mpoint(struct ssh_mpoint_s *mp, char *buffer, unsigned int size, unsigned int format, unsigned int *error);
int write_ssh_mpoint(struct ssh_mpoint_s *mp, char *buffer, unsigned int size, unsigned int format, unsigned int *error);

void msg_read_ssh_mpoint(struct msg_buffer_s *mb, struct ssh_mpoint_s *mp, unsigned int *plen);
void msg_write_ssh_mpoint(struct msg_buffer_s *mb, struct ssh_mpoint_s *mp);


#endif
