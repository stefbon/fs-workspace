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

#include "logging.h"
#include "main.h"
#include "utils.h"
#include "workspace-interface.h"

#include "ssh-common.h"
#include "ssh-utils.h"

#if HAVE_LIBGCRYPT

#include <gcrypt.h>

#endif

static struct ssh_utils_s utils;

#ifdef HAVE_LIBGCRYPT

unsigned int create_hash(const char *name, char *in, unsigned int size, struct ssh_string_s *out, unsigned int *error)
{
    int algo=gcry_md_map_name(name);
    unsigned int len=0;
    gcry_md_hd_t handle;

    if (algo==0) {

	if (error) *error=EINVAL;
	return 0;

    }

    len=gcry_md_get_algo_dlen(algo);
    if (out==NULL || in==NULL) return len;

    if (gcry_md_open(&handle, algo, 0)==0) {
	unsigned char *digest=NULL;

	gcry_md_write(handle, in, size);
	digest=gcry_md_read(handle, algo);
	if (out->len < len) len=out->len;
	memcpy(out->ptr, digest, len);
	gcry_md_close(handle);

    } else {

	if (error) *error=EIO;
	len=0;

    }

    return len;

}

#else

unsigned int create_hash(const char *name, char *in, unsigned int size, struct ssh_string_s *out, unsigned int *error)
{
    *error=EOPNOTSUPP;
    return 0;

}

#endif

#ifdef HAVE_LIBGCRYPT

unsigned int fill_random(char *buffer, unsigned int size)
{
    gcry_create_nonce((unsigned char *)buffer, (size_t) size);
    return size;
}

#else

unsigned int fill_random(char *buffer, unsigned int size)
{
    return 0;
}

#endif

int init_ssh_backend_library(unsigned int *error)
{
#ifdef HAVE_LIBGCRYPT

    logoutput("init_ssh_backend_library: libgcrypt %s", GCRYPT_VERSION);

    GCRY_THREAD_OPTION_PTHREAD_IMPL;
    gcry_control(GCRYCTL_SET_THREAD_CBS, &gcry_threads_pthread);

    /* disable secure memory (for now) */

    gcry_control(GCRYCTL_DISABLE_SECMEM, 0);
    gcry_control(GCRYCTL_ENABLE_M_GUARD);
    gcry_control(GCRYCTL_SET_VERBOSITY, 3);

    if ( ! gcry_check_version(GCRYPT_VERSION)) {


	*error=ELIBBAD;
	logoutput_warning("init_ssh_backend_library");
	return -1;

    }

    gcry_control(GCRYCTL_INITIALIZATION_FINISHED, 0);
    return 0;

#else

    return -1;

#endif

}

/* host specific n to h */

/* little endian */

uint64_t ntohll_le(uint64_t nvalue)
{
    return ( (((uint64_t)ntohl(nvalue))<<32) + ntohl(nvalue >> 32) );
}

/* big endian */

uint64_t ntohll_be(uint64_t nvalue)
{
    return nvalue;
}

void init_ssh_utils()
{
    unsigned int endian_test=1;
    unsigned int error=0;

    /* determine the ntohll function to use for this host (big or litlle endian) */

    if (*((char *) &endian_test) == 1) {

	/* little endian */

	utils.ntohll=ntohll_le;

    } else {

	/* big endian */

	utils.ntohll=ntohll_be;

    }

}

uint64_t ntohll(uint64_t value)
{
    return (* utils.ntohll)(value);
}

void replace_cntrl_char(char *buffer, unsigned int size)
{
    for (unsigned int i=0; i<size; i++) {

	if (iscntrl(buffer[i])) {

	    buffer[i]=' ';

	}

    }
}

void replace_newline_char(char *ptr, unsigned int *size)
{
    char *sep=NULL;
    unsigned int tmp=*size;

    // logoutput("replace_newline_char: prev %i", tmp);

    sep=memchr(ptr, 13, tmp);

    if (sep) {

	*sep='\0';
	tmp=(unsigned int) (sep - ptr);

	// logoutput("replace_newline_char: new %i", tmp);
	*size=tmp;

    }

}
