/*
  2010, 2011, 2012, 2103, 2014, 2015, 2016 Stef Bon <stefbon@gmail.com>

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
#include <fcntl.h>
#include <dirent.h>
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

#include <gcrypt.h>

#include "logging.h"
#include "main.h"

#include "utils.h"

#include "ssh-common.h"
#include "ssh-utils.h"
#include "ssh-keyx.h"
#include "ssh-keyx-dh.h"


struct libgcrypt_dh_s {
    unsigned int 	bits;
    gcry_mpi_t 		p;
    gcry_mpi_t 		g;
    gcry_mpi_t		x;
    gcry_mpi_t		e;
    gcry_mpi_t		f;
    gcry_mpi_t		K;
};

static unsigned int get_size_modgroup_libgcrypt(struct ssh_dh_s *dh)
{
    struct libgcrypt_dh_s *lg=(struct libgcrypt_dh_s *) dh->library.ptr;

    return gcry_mpi_get_nbits(lg->p);

}

static void calc_e_libgcrypt(struct ssh_dh_s *dh)
{
    struct libgcrypt_dh_s *lg=(struct libgcrypt_dh_s *) dh->library.ptr;
    unsigned int bits=gcry_mpi_get_nbits(lg->p) - 1;

    lg->x=gcry_mpi_new(0);
    lg->e=gcry_mpi_new(0);

    /* create a random with size bits */

    gcry_mpi_randomize(lg->x, bits, GCRY_WEAK_RANDOM);

    /* calculate e with e = g^x mod p */

    gcry_mpi_powm(lg->e, lg->g, lg->x, lg->p);

    logoutput("calc_e_libgcrypt: (bits p: %i bits g: %i bits e: %i)", gcry_mpi_get_nbits(lg->p), gcry_mpi_get_nbits(lg->g), gcry_mpi_get_nbits(lg->e));

}

static unsigned int write_e_libgcrypt(struct ssh_dh_s *dh, char *pos, unsigned int len)
{
    struct libgcrypt_dh_s *lg=(struct libgcrypt_dh_s *) dh->library.ptr;
    size_t nwritten=0;

    logoutput("write_e_libgcrypt: size %i", len);

    if (lg->e) {

	/* write e in mpint format */

	gcry_mpi_print(GCRYMPI_FMT_SSH, (unsigned char *)pos, len, &nwritten, lg->e);

	logoutput("write_e_libgcrypt: written %i", nwritten);

    } else {

	logoutput("write_e_libgcrypt: error e not set");

    }

    return (unsigned int) nwritten;

}

static unsigned int write_f_libgcrypt(struct ssh_dh_s *dh, char *pos, unsigned int len)
{
    struct libgcrypt_dh_s *lg=(struct libgcrypt_dh_s *) dh->library.ptr;
    size_t nwritten=0;

    if (lg->f) {

	/* write f in mpint format */

	gcry_mpi_print(GCRYMPI_FMT_SSH, (unsigned char *)pos, len, &nwritten, lg->f);

    }

    return (unsigned int) nwritten;

}

static unsigned int read_f_libgcrypt(struct ssh_dh_s *dh, char *pos, unsigned int len)
{
    struct libgcrypt_dh_s *lg=(struct libgcrypt_dh_s *) dh->library.ptr;
    gcry_error_t ecode;
    size_t nwritten=0;

    if (gcry_mpi_scan(&lg->f, GCRYMPI_FMT_SSH, (unsigned char *)pos, len, &nwritten)!=GPG_ERR_NO_ERROR) nwritten=0;

    return (unsigned int) nwritten;

}

static void calc_K_libgcrypt(struct ssh_dh_s *dh)
{
    struct libgcrypt_dh_s *lg=(struct libgcrypt_dh_s *) dh->library.ptr;

    lg->K=gcry_mpi_new(0);

    gcry_mpi_powm(lg->K, lg->f, lg->x, lg->p);

}

static unsigned int write_K_libgcrypt(struct ssh_dh_s *dh, char *pos, unsigned int len)
{
    struct libgcrypt_dh_s *lg=(struct libgcrypt_dh_s *) dh->library.ptr;
    size_t nwritten=0;

    if (lg->K) {

	/* write K in mpint format */

	gcry_mpi_print(GCRYMPI_FMT_SSH, (unsigned char *)pos, len, &nwritten, lg->K);

    }

    return (unsigned int) nwritten;

}

static void free_libgcrypt(struct ssh_dh_s *dh)
{
    struct libgcrypt_dh_s *lg=(struct libgcrypt_dh_s *) dh->library.ptr;

    if (lg) {

	if (lg->p) gcry_mpi_release(lg->p);
	if (lg->g) gcry_mpi_release(lg->g);
	if (lg->x) gcry_mpi_release(lg->x);
	if (lg->e) gcry_mpi_release(lg->e);
	if (lg->f) gcry_mpi_release(lg->f);
	if (lg->K) gcry_mpi_release(lg->K);

	free(lg);

	dh->library.ptr=NULL;

    }

}

int init_dh_libgcrypt(struct ssh_dh_s *dh, unsigned char *p, unsigned int p_len, unsigned char *g, unsigned int g_len)
{
    struct libgcrypt_dh_s *lg=NULL;

    lg=malloc(sizeof(struct libgcrypt_dh_s));

    if (lg) {

	logoutput("init_dh_libgcrypt");

	memset(lg, 0, sizeof(struct libgcrypt_dh_s));

	dh->library.type=_LIBRARY_LIBGCRYPT;
	dh->library.ptr=(void *) lg;

	dh->status=_DH_STATUS_GOTP; /* static: has already p */

	dh->get_size_modgroup=get_size_modgroup_libgcrypt;
	dh->free=free_libgcrypt;
	dh->calc_e=calc_e_libgcrypt;
	dh->write_e=write_e_libgcrypt;
	dh->write_f=write_f_libgcrypt;
	dh->read_f=read_f_libgcrypt;
	dh->calc_K=calc_K_libgcrypt;
	dh->write_K=write_K_libgcrypt;

	gcry_mpi_scan(&lg->p, GCRYMPI_FMT_USG, p, p_len, NULL);
	gcry_mpi_scan(&lg->g, GCRYMPI_FMT_USG, g, g_len, NULL);

	return 0;

    }

    return -1;

}
