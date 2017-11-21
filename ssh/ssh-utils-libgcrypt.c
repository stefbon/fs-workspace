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

#include <gcrypt.h>

#include "logging.h"
#include "main.h"

#include "utils.h"

#include "ssh-common.h"
#include "ssh-utils.h"

static unsigned char done=0;

/* create a hash */

static unsigned int hash_libgcrypt(const char *name, struct common_buffer_s *in, struct common_buffer_s *out, unsigned int *error)
{
    int algo=gcry_md_map_name(name);
    unsigned int len=0;

    if (algo>0) {

	len=gcry_md_get_algo_dlen(algo);

	if (len<=out->len) {
	    gcry_md_hd_t handle;

	    if (gcry_md_open(&handle, algo, 0)==0) {
		unsigned char *digest=NULL;

		gcry_md_write(handle, in->ptr, in->len);
		digest=gcry_md_read(handle, algo);

		memcpy(out->ptr, digest, len);

		gcry_md_close(handle);

	    } else {

		len=0;
		*error=EINVAL;

	    }

	} else {

	    *error=ENOBUFS;
	    len=0;

	}

    } else {

	*error=EINVAL;

    }

    return len;

}

struct hash_libgcrypt_s {
    gcry_md_hd_t		md;
    unsigned int		algo;
};

void *hash_init_libgcrypt(const char *name, unsigned int *error)
{
    int algo=gcry_md_map_name(name);

    if (algo>0) {
	struct hash_libgcrypt_s *handle=NULL;

	handle=malloc(sizeof(struct hash_libgcrypt_s));

	if (handle) {
	    gcry_error_t result=0;

	    handle->md=NULL;
	    handle->algo=algo;

	    result=gcry_md_open(&handle->md, algo, 0);

	    if (result==0) {

		return (void *) handle;

	    } else {

		logoutput("hash_init_libgcrypt: error %s/%s", gcry_strsource(result), gcry_strerror(result));
		free(handle);

	    }

	}

    }

    return NULL;

}

void update_hash_libgcrypt(void *ptr, unsigned char *buffer, size_t size)
{
    struct hash_libgcrypt_s *handle=(struct hash_libgcrypt_s *) ptr;

    gcry_md_write(handle->md, buffer, size);

}

void final_hash_libgcrypt(void *ptr, unsigned char *hash, size_t size)
{
    struct hash_libgcrypt_s *handle=(struct hash_libgcrypt_s *) ptr;
    gcry_error_t result=0;
    unsigned char *read=NULL;
    unsigned int len=gcry_md_get_algo_dlen(handle->algo);

    read=gcry_md_read(handle->md, 0);

    if (size<=len) {

	memcpy(hash, read, size);

    } else {

	memcpy(hash, read, len);

    }

    gcry_md_close(handle->md);
    free(handle);

}

static unsigned int fill_random_libgcrypt(unsigned char *pos, unsigned int len)
{
    gcry_create_nonce(pos, (size_t) len);

    return len;
}

static unsigned int get_digest_len_libgcrypt(const char *name)
{
    unsigned int len=0;
    int algo=gcry_md_map_name(name);

    if (algo>0) len=gcry_md_get_algo_dlen(algo);

    return len;

}

static int init_library_libgcrypt(unsigned int *error)
{

    if (done==0) {

	logoutput("init_library_libgcrypt");

	GCRY_THREAD_OPTION_PTHREAD_IMPL;

	gcry_control(GCRYCTL_SET_THREAD_CBS, &gcry_threads_pthread);

	/* disable secure memory (for now) */

	gcry_control(GCRYCTL_DISABLE_SECMEM, 0);
	gcry_control(GCRYCTL_ENABLE_M_GUARD);
	gcry_control(GCRYCTL_SET_VERBOSITY, 3);

	if ( ! gcry_check_version(GCRYPT_VERSION)) {


	    *error=ELIBBAD;
	    logoutput_warning("init_library_libgcrypt: libgcrypt version mismatch");
	    return -1;

	}

	gcry_control(GCRYCTL_INITIALIZATION_FINISHED, 0);

	done=1; /* prevent called more than once */

    }

    return 0;

}

void init_sshutils_libgcrypt(struct ssh_utils_s *utils)
{

    utils->init_library=init_library_libgcrypt;

    utils->hash=hash_libgcrypt;
    utils->get_digest_len=get_digest_len_libgcrypt;

    utils->fill_random=fill_random_libgcrypt;

}
