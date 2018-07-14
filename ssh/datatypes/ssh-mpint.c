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
#include <ctype.h>
#include <inttypes.h>

#include <sys/param.h>
#include <sys/types.h>
#include <sys/stat.h>

#include "logging.h"

#include "ssh-datatypes.h"
#include "ssh-utils.h"

#if HAVE_LIBGCRYPT

#include <gcrypt.h>

int create_ssh_mpint(struct ssh_mpint_s *mp)
{
    if (mp->lib.mpi==NULL) mp->lib.mpi=gcry_mpi_new(0);
    return (mp->lib.mpi) ? 0 : -1;
}

unsigned int get_nbits_ssh_mpint(struct ssh_mpint_s *mp)
{
    if (mp->lib.mpi) return gcry_mpi_get_nbits(mp->lib.mpi);
    return 0;
}

unsigned int get_nbytes_ssh_mpint(struct ssh_mpint_s *mp)
{
    unsigned int bytes = 0;

    if (mp->lib.mpi) {
	unsigned int bits = gcry_mpi_get_nbits(mp->lib.mpi);

	bytes = (bits / 8);

	if ((bits % 8) == 0) {

	    /* test highest bit is set add an extry byte to prevent it's read as negative */
	    if (gcry_mpi_test_bit(mp->lib.mpi, bits)) bytes++;

	} else {

	    /* bits does not fit in bytes */
	    bytes++;

	}

    }

    return bytes;
}

void power_modulo_ssh_mpint(struct ssh_mpint_s *result, struct ssh_mpint_s *b, struct ssh_mpint_s *e, struct ssh_mpint_s *m)
{
    gcry_mpi_powm(result->lib.mpi, b->lib.mpi, e->lib.mpi, m->lib.mpi);
}

int compare_ssh_mpint(struct ssh_mpint_s *a, struct ssh_mpint_s *b)
{

    if (a->lib.mpi==NULL || b->lib.mpi==NULL) {

	logoutput("compare_ssh_mpint: one or both arguments not defined (first %s second %s)", (a->lib.mpi) ? "defined" : "notdefined", (b->lib.mpi) ? "defined" : "notdefined");
	return -1;

    }

    return gcry_mpi_cmp(a->lib.mpi, b->lib.mpi);
}

void swap_ssh_mpint(struct ssh_mpint_s *a, struct ssh_mpint_s *b)
{
    gcry_mpi_swap(a->lib.mpi, b->lib.mpi);
}

int invm_ssh_mpint(struct ssh_mpint_s *x, struct ssh_mpint_s *a, struct ssh_mpint_s *m)
{
    return gcry_mpi_invm(x->lib.mpi, a->lib.mpi, m->lib.mpi);
}

int randomize_ssh_mpint(struct ssh_mpint_s *mp, unsigned int bits)
{

    if (create_ssh_mpint(mp)==0) {

	gcry_mpi_randomize(mp->lib.mpi, bits, GCRY_WEAK_RANDOM);
	return 0;

    }

    return -1;

}

int read_ssh_mpint(struct ssh_mpint_s *mp, char *buffer, unsigned int size, unsigned int format, unsigned int *error)
{
    size_t nscanned=0;
    gcry_error_t err=0;
    enum gcry_mpi_format mpi_format;

    switch (format) {
    case SSH_MPINT_FORMAT_SSH :

	mpi_format=GCRYMPI_FMT_SSH;
	break;

    case SSH_MPINT_FORMAT_USC :

	mpi_format=GCRYMPI_FMT_USG;
	break;

    default :

	mpi_format=GCRYMPI_FMT_STD;

    }

    err=gcry_mpi_scan(&mp->lib.mpi, mpi_format, (const unsigned char *) buffer, (size_t) size, &nscanned);

    if (err) {

	logoutput("read_ssh_mpint: error %s/%s", gcry_strsource(err), gcry_strerror(err));

	*error=EIO;
	return -1;

    }

    return (int) nscanned;
}

int write_ssh_mpint(struct ssh_mpint_s *mp, char *buffer, unsigned int size, unsigned int format, unsigned int *error)
{
    size_t nwritten=0;
    gcry_error_t err=0;
    enum gcry_mpi_format mpi_format;

    switch (format) {
    case SSH_MPINT_FORMAT_SSH :

	mpi_format=GCRYMPI_FMT_SSH;
	break;

    case SSH_MPINT_FORMAT_USC :

	mpi_format=GCRYMPI_FMT_USG;
	break;

    default :

	mpi_format=GCRYMPI_FMT_STD;

    }

    if (buffer==NULL) return (4 + get_nbytes_ssh_mpint(mp));

    err=gcry_mpi_print(format, (unsigned char *) buffer, (size_t) size, &nwritten, mp->lib.mpi);

    if (err) {

	logoutput("write_ssh_mpint: error %s/%s", gcry_strsource(err), gcry_strerror(err));

	*error=EIO;
	return -1;

    }

    return (int) nwritten;

}

void msg_read_ssh_mpint(struct msg_buffer_s *mb, struct ssh_mpint_s *mp, unsigned int *plen)
{
    size_t nscanned=0;
    gcry_error_t err=0;
    unsigned int len=(mb->len - mb->pos);

    if (plen) len=*plen;

    err=gcry_mpi_scan(&mp->lib.mpi, GCRYMPI_FMT_SSH, (const unsigned char *) &mb->data[mb->pos], (size_t) len, &nscanned);

    if (err) {

	logoutput("msg_read_ssh_mpint: error %s/%s", gcry_strsource(err), gcry_strerror(err));
	set_msg_buffer_fatal_error(mb, EIO);

    }

    mb->pos += nscanned;
    if (plen) ((*plen) -= nscanned);
}

void msg_write_ssh_mpint(struct msg_buffer_s *mb, struct ssh_mpint_s *mp)
{
    unsigned int len = 4 + get_nbytes_ssh_mpint(mp);

    if (mb->data) {

	if (mb->pos + len <= mb->len) {
	    size_t nwritten=0;
	    gcry_error_t err=gcry_mpi_print(GCRYMPI_FMT_SSH, (unsigned char *) &mb->data[mb->pos], (size_t)(mb->len - mb->pos), &nwritten, mp->lib.mpi);

	    if (err) {

		logoutput("msg_write_ssh_mpint: error %s/%s", gcry_strsource(err), gcry_strerror(err));
		set_msg_buffer_fatal_error(mb, EIO);
		mb->pos += (nwritten==0) ? len : nwritten;

	    } else {

		mb->pos += nwritten;

	    }

	} else {

	    set_msg_buffer_fatal_error(mb, ENOBUFS);
	    mb->pos += len;

	}

    } else {

	mb->pos += len;

    }

}

void free_ssh_mpint(struct ssh_mpint_s *mp)
{
    if (mp->lib.mpi) {

	gcry_mpi_release(mp->lib.mpi);
	mp->lib.mpi=NULL;

    }
}

void init_ssh_mpint(struct ssh_mpint_s *mp)
{
    mp->lib.mpi=NULL;
}

int compare_ssh_mpoint(struct ssh_mpoint_s *a, struct ssh_mpoint_s *b)
{
    unsigned int alen=0;
    void *aptr=NULL;
    unsigned int blen=0;
    void *bptr=NULL;

    if (a->lib.mpi==NULL || b->lib.mpi==NULL) {

	logoutput("compare_ssh_mpoint: a and/or b not defined");
	return -1;

    }

    aptr=gcry_mpi_get_opaque(a->lib.mpi, &alen);
    bptr=gcry_mpi_get_opaque(b->lib.mpi, &blen);

    if (aptr && bptr && (alen==blen)) {

#ifdef FS_WORKSPACE_DEBUG
	logoutput("compare_ssh_mpoint: memcmp (len=%i)", alen/8);
#endif

	if (memcmp(aptr, bptr, (alen/8))==0) return 0;

    }

    return -1;
}


int read_ssh_mpoint(struct ssh_mpoint_s *mp, char *buffer, unsigned int size, unsigned int format, unsigned int *error)
{
    unsigned int len=0;
    char *pos=buffer;

    if (format != SSH_MPINT_FORMAT_SSH) {

	logoutput("read_ssh_mpoint: format %i not supported", format);
	*error=EINVAL;
	return -1;

    }

    if (size > 4) {

	len=get_uint32(pos);
	pos+=4;

	// logoutput("read_ssh_mpoint: size: %i len %i", size, len);

	if (4 + len <= size) {
	    char *data=(char *) gcry_malloc(len);

	    if (data) {

		memcpy(data, pos, len);

		mp->lib.mpi=gcry_mpi_set_opaque(NULL, (void *) data, (8 * len));

		if (mp->lib.mpi==NULL) {

		    if (mp->lib.mpi) {

			gcry_mpi_release(mp->lib.mpi);
			mp->lib.mpi=NULL;

		    } else {

			free(data);

		    }

		    return -1;

		} else {

		    pos+=len;

		}

	    } else {

		*error=ENOMEM;
		return -1;

	    }

	} else {

	    *error=ENOBUFS;
	    return -1;

	}

    } else {

	*error=ENOBUFS;
	return -1;

    }

    return (int)(pos - buffer);

}

void msg_read_ssh_mpoint(struct msg_buffer_s *mb, struct ssh_mpoint_s *mp, unsigned int *plen)
{

    // logoutput("msg_read_ssh_mpoint: pos %i size %i", mb->pos, mb->len);

    if (mb->len - mb->pos > 4) {
	unsigned int len=0;

	len=get_uint32(&mb->data[mb->pos]);

	if (plen) {

	    if (*plen < len + 4) {

		set_msg_buffer_fatal_error(mb, ENOBUFS);
		return;

	    }

	    (*plen) -= (len + 4);

	}

	mb->pos+=4;

	// logoutput("msg_read_ssh_mpoint: len %i", len);

	if (mb->pos + len <= mb->len) {
	    char *buffer=(char *) gcry_malloc(len);

	    if (buffer) {

		// logoutput("msg_read_ssh_mpoint: malloc");

		memcpy(buffer, &mb->data[mb->pos], len);

		mp->lib.mpi=gcry_mpi_set_opaque(NULL, (void *) buffer, (8 * len));

		//set_msg_buffer_fatal_error(mb, EIO);

		//    if (mp->lib.mpi) {

		//	gcry_mpi_release(mp->lib.mpi);
		//	mp->lib.mpi=NULL;

		//    } else {

		//	free(buffer);

		//    }

		// }

	    } else {

		set_msg_buffer_fatal_error(mb, ENOMEM);

	    }

	} else {

	    set_msg_buffer_fatal_error(mb, ENOBUFS);

	}

	mb->pos+=len;

    }

}

int write_ssh_mpoint(struct ssh_mpoint_s *mp, char *buffer, unsigned int size, unsigned int format, unsigned int *error)
{
    unsigned int len=0;
    void *ptr=NULL;

    if (format != SSH_MPINT_FORMAT_SSH) {

	logoutput("read_ssh_mpoint: format %i not supported", format);
	*error=EINVAL;
	return -1;

    }

    *error=EIO;
    ptr=gcry_mpi_get_opaque(mp->lib.mpi, &len);

    if (ptr) {
	struct ssh_string_s tmp;

	init_ssh_string(&tmp);
	tmp.ptr=(char *) ptr;
	tmp.len = len/8;

	if (size >= tmp.len + 4) {

	    *error=0;
	    return write_ssh_string(buffer, size, 's', (void *) &tmp);

	}

    }

    return -1;

}

void msg_write_ssh_mpoint(struct msg_buffer_s *mb, struct ssh_mpoint_s *mp)
{
    unsigned int len=0;
    void *ptr=NULL;

    // logoutput("msg_write_ssh_mpoint (%s)", ((mp->lib.mpi) ? "defined" : "notdefined"));

    ptr=gcry_mpi_get_opaque(mp->lib.mpi, &len);

    // logoutput("msg_write_ssh_mpoint A");

    if (ptr) {
	struct ssh_string_s tmp;

	init_ssh_string(&tmp);
	tmp.ptr=(char *) ptr;
	tmp.len = len/8;

#ifdef FS_WORKSPACE_DEBUG

	if (mb->data) {

	    logoutput("msg_write_ssh_mpoint: len %i pos %i size %i", tmp.len, mb->pos, mb->len - mb->pos);

	} else {

	    logoutput("msg_write_ssh_mpoint: len %i pos %i", tmp.len, mb->pos);

	}

#endif

	if ((mb->len - mb->pos) >= tmp.len + 4) {

	    msg_write_ssh_string(mb, 's', (void *) &tmp);
	    return;

	}

    }

    mb->error=EIO;

}

void free_ssh_mpoint(struct ssh_mpoint_s *mp)
{

#ifdef FS_WORKSPACE_DEBUG

    logoutput("free_ssh_mpoint");

#endif

    if (mp->lib.mpi) {

	// gcry_mpi_set_opaque(mp->lib.mpi, NULL, 0); /* will release the pointer */
	logoutput("free_ssh_mpoint: gcry_mpi_release");
	gcry_mpi_release(mp->lib.mpi);
	mp->lib.mpi=NULL;

    }
}

void init_ssh_mpoint(struct ssh_mpoint_s *mp)
{
#ifdef FS_WORKSPACE_DEBUG

    logoutput("init_ssh_mpoint");

#endif
    mp->lib.mpi=NULL;
}

#else

int create_ssh_mpint(struct ssh_mpint_s *mp)
{
    return -1;
}

unsigned int get_nbits_ssh_mpint(struct ssh_mpint_s *mp)
{
    return 0;
}

unsigned int get_nbytes_ssh_mpint(struct ssh_mpint_s *mp)
{
    return 0;
}

void power_modulo_ssh_mpint(struct ssh_mpint_s *result, struct ssh_mpint_s *b, struct ssh_mpint_s *e, struct ssh_mpint_s *m)
{
}

int compare_ssh_mpint(struct ssh_mpint_s *a, struct ssh_mpint_s *b)
{
    return -1;
}

void swap_ssh_mpint(struct ssh_mpint_s *a, struct ssh_mpint_s *b)
{
}

int invm_ssh_mpint(struct ssh_mpint_s *x, struct ssh_mpint_s *a, struct ssh_mpint_s *m)
{
    return -1;
}

int randomize_ssh_mpint(struct ssh_mpint_s *mp, unsigned int bits)
{
    return -1;
}

int read_ssh_mpint(struct ssh_mpint_s *mp, char *buffer, unsigned int size, unsigned int format, unsigned int *error)
{
    *error=EOPNOTSUPP;
    return -1;
}

int write_ssh_mpint(struct ssh_mpint_s *mp, char *buffer, unsigned int size, unsigned int format, unsigned int *error)
{
    *error=EOPNOTSUPP;
    return -1;
}

void msg_write_ssh_mpint(struct msg_buffer_s *mb, struct ssh_mpint_s *mp)
{
}

void free_ssh_mpint(struct ssh_mpint_s *mp)
{
}

void init_ssh_mpint(struct ssh_mpint_s *mp)
{
}

void msg_read_ssh_mpoint(struct msg_buffer_s *mb, struct ssh_mpoint_s *mp)
{
}

void free_ssh_mpoint(struct ssh_mpoint_s *mp)
{
}

void init_ssh_mpoint(struct ssh_mpoint_s *mp)
{
}

#endif
