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

#include "global-defines.h"

#include <stdio.h>
#include <stdlib.h>
#include <stddef.h>
#include <stdbool.h>
#include <string.h>
#include <unistd.h>
#include <ctype.h>
#include <inttypes.h>

#include <sys/param.h>
#include <sys/types.h>
#include <errno.h>

#ifdef HAVE_GLIB2
#include <glib.h>
#endif

#if HAVE_LIBGCRYPT
#include <gcrypt.h>
#endif

#include <utils.h>

#include "ssh-datatypes.h"
#include "pk-types.h"

#if HAVE_LIBGCRYPT

unsigned int pk_mpint_get_nbits(struct ssh_mpint_s *mp)
{
    if (mp->lib.mpi==NULL) return 0;
    return gcry_mpi_get_nbits(mp->lib.mpi);
}

int pk_mpint_cmp(struct ssh_mpint_s *a, struct ssh_mpint_s *b)
{
    return gcry_mpi_cmp(a->lib.mpi, b->lib.mpi);
}

void pk_mpint_swap(struct ssh_mpint_s *a, struct ssh_mpint_s *b)
{
    gcry_mpi_swap(a->lib.mpi, b->lib.mpi);
}

int pk_mpint_invm(struct ssh_mpint_s *x, struct ssh_mpint_s *a, struct ssh_mpint_s *m)
{
    return gcry_mpi_invm(x->lib.mpi, a->lib.mpi, m->lib.mpi);
}

#else

unsigned int pk_mpint_get_nbits(struct ssh_mpint_s *mp)
{
    return 0;
}

int pk_mpint_cmp(struct ssh_mpint_s *a, struct ssh_mpint_s *b)
{
    return 0;
}

void pk_mpint_swap(struct ssh_mpint_s *a, struct ssh_mpint_s *b)
{
}

int pk_mpint_invm(struct ssh_mpint_s *x, struct ssh_mpint_s *a, struct ssh_mpint_s *m)
{
    return 0;
}

#endif

#ifdef HAVE_GLIB2

int decode_buffer_base64(char *buffer, unsigned int size, struct ssh_string_s *decoded)
{
    gsize len=(gsize) size;
    char tmp[size + 1];

    memcpy(tmp, buffer, size);
    tmp[size] = '\0';

    decoded->ptr = (char *) g_base64_decode((const gchar *) tmp, &len);

    if (decoded->ptr) {

	decoded->len=len;
	return (int) len;

    }

    return -1;
}

#else

int decode_buffer_base64(char *buffer, unsigned int size, struct ssh_string_s *decoded)
{
    return -1;
}

#endif
