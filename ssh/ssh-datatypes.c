/*
  2010, 2011, 2012, 2103, 2014, 2015, 2016, 2017, 2018 Stef Bon <stefbon@gmail.com>

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
#include <errno.h>
#include <err.h>
#include <sys/time.h>
#include <time.h>
#include <pthread.h>
#include <ctype.h>
#include <inttypes.h>

#include <sys/param.h>
#include <sys/types.h>
#include <sys/stat.h>

#include "main.h"
#include "utils.h"
#include "logging.h"

#include "ssh-datatypes.h"
#include "ssh-utils.h"

void init_ssh_string(struct ssh_string_s *s)
{
    s->ptr=NULL;
    s->len=0;
}

void free_ssh_string(struct ssh_string_s *s)
{
    if (s->ptr) {

	free(s->ptr);
	s->ptr=NULL;

    }

    init_ssh_string(s);
}

unsigned int create_ssh_string(struct ssh_string_s *s, unsigned int len)
{
    s->ptr=malloc(len);
    if (s->ptr) return len;

    return 0;
}

int get_ssh_string_from_buffer(char **b, unsigned int size, struct ssh_string_s *s)
{
    char *pos = *b;

    if (size > 4) {

	s->len=get_uint32(pos);
	pos+=4;
	size-=4;

    } else {

	/* buffer is not large enough */
	return -1;

    }

    if (s->len <= size) {

	if (create_ssh_string(s, s->len)>0) {

	    memcpy(s->ptr, pos, s->len);
	    pos+=s->len;

	} else {

	    /* allocation problem */
	    return -1;

	}

    } else {

	/* not enough data in buffer */
	return -1;

    }

    *b=pos;

    return (4 + s->len);

}

unsigned int write_ssh_string(char *buffer, unsigned int size, const unsigned char type, void *ptr)
{
    char *pos=NULL;

    switch (type) {

    case 's' : {
	struct ssh_string_s *s=(struct ssh_string_s *) ptr;

	if (buffer) {
	    char *pos=buffer;

	    store_uint32(pos, s->len);
	    pos+=4;
	    memcpy(pos, s->ptr, s->len);

	}

	return (4 + s->len);
	break;
    }
    case 'c' : {
	char *data=(char *) ptr;
	unsigned int len=strlen(data);

	if (buffer) {
	    char *pos=buffer;

	    store_uint32(pos, len);
	    pos+=4;
	    memcpy(pos, data, len);

	}

	return (4 + len);
	break;
    }
    default :

	break;

    }

    return 0;

}


#if HAVE_LIBGCRYPT

#include <gcrypt.h>

static unsigned int get_nbytes_pk_mpint(struct ssh_mpint_s *mp)
{
    unsigned int bits = gcry_mpi_get_nbits(mp->lib.mpi);
    unsigned int bytes = (bits / 8) + (((bits % 8) == 0) ? 0 : 1);
    return bytes;
}

int read_pk_mpint(struct ssh_mpint_s *mp, char *buffer, unsigned int size, unsigned int *error)
{
    size_t nscanned=0;
    gcry_error_t err=0;

    err=gcry_mpi_scan(&mp->lib.mpi, GCRYMPI_FMT_SSH, (const unsigned char *) buffer, (size_t) size, &nscanned);

    if (err) {

	logoutput("read_pk_mpint: error %s/%s", gcry_strsource(err), gcry_strerror(err));

	*error=EIO;
	return -1;

    }

    return (int) nscanned;
}

int write_pk_mpint(struct ssh_mpint_s *mp, char *buffer, unsigned int size, unsigned int *error)
{
    size_t nwritten=0;
    gcry_error_t err=0;

    if (buffer==NULL) return (4 + get_nbytes_pk_mpint(mp));

    err=gcry_mpi_print(GCRYMPI_FMT_SSH, (unsigned char *) buffer, (size_t) size, &nwritten, mp->lib.mpi);

    if (err) {

	logoutput("write_pk_mpint: error %s/%s", gcry_strsource(err), gcry_strerror(err));

	*error=EIO;
	return -1;

    }

    return (int) nwritten;

}

void free_pk_mpint(struct ssh_mpint_s *mp)
{
    if (mp->lib.mpi) {

	gcry_mpi_release(mp->lib.mpi);
	mp->lib.mpi=NULL;

    }
}

void init_pk_mpint(struct ssh_mpint_s *mp)
{
    mp->lib.mpi=NULL;
}

#else

int read_pk_mpint(struct ssh_mpint_s *mp, char *buffer, unsigned int size, unsigned int *error)
{
    *error=EOPNOTSUPP;
    return -1;
}

int write_pk_mpint(struct ssh_mpint_s *mp, char *buffer, unsigned int size, unsigned int *error)
{
    *error=EOPNOTSUPP;
    return -1;
}

void free_pk_mpint(struct ssh_mpint_s *mp)
{
}

void init_pk_mpint(struct ssh_mpint_s *mp)
{
}

#endif
