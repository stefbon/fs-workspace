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

#include "ssh-pubkey.h"
#include "ssh-pubkey-utils-libgcrypt.h"
#include "ssh-pubkey-format-libgcrypt.h"
#include "ssh-pubkey-libgcrypt.h"
#include "ssh-pubkey-utils.h"

/*
    check the hash (of H) created by the client with the signature of H created by the server
    the server has created the signature using the private servers key
    the client can verify it using the servers public key.

    TODO:
    function which gives the name for the hash; it is default sha1, but modern ssh servers can have a different hash
*/

static int verify_sigH_rsa_libgcrypt(struct ssh_key_s *key, struct common_buffer_s *data, struct common_buffer_s *sigH, const char *hashname)
{
    struct _rsa_public_key_s *rsa=(struct _rsa_public_key_s *) key->ptr;
    gcry_sexp_t s_hash=NULL;
    unsigned char sha1_hash[20];
    int algo=gcry_md_map_name(hashname);
    unsigned int hash_len=gcry_md_get_algo_dlen(algo);
    unsigned char hash_array[hash_len];
    char hashname_lower[strlen(hashname)+1];
    int verified=-1;

    if (hash_len==0) {

	logoutput("verify_sigH_rsa_libgcrypt: hash %s not supported", hashname);
	return -1;

    }

    /* build s-expression for the data */

    gcry_md_hash_buffer(algo, hash_array, data->ptr, data->size);

    strcpy(hashname_lower, hashname);
    for (unsigned int i=0; i<strlen(hashname); i++) hashname_lower[i]=tolower((unsigned char) hashname[i]);

    logoutput("verify_sigH_rsa_libgcrypt: hash %s - %s", hashname_lower, hashname);

    if (gcry_sexp_build(&s_hash, NULL, "(data (flags pkcs1) (hash %s %b))", hashname, hash_len, hash_array)==GPG_ERR_NO_ERROR) {
	gcry_sexp_t s_pkey=NULL;

	if (gcry_sexp_build(&s_pkey, NULL, "(public-key(rsa(e%m)(n%m)))", rsa->e, rsa->n)==GPG_ERR_NO_ERROR) {
	    gcry_sexp_t s_sig=NULL;

	    /*	build s-expr for signature of H for rsa 
		(sig-val (rsa(s))) */

	    if (gcry_sexp_build(&s_sig, NULL, "(sig-val (rsa(s %b)))", sigH->len, sigH->ptr)==GPG_ERR_NO_ERROR) {
		gcry_error_t result=0;

		result=gcry_pk_verify(s_sig, s_hash, s_pkey);

		if (result==GPG_ERR_NO_ERROR) {

		    verified=0;

		} else {

		    logoutput("verify_sigH_rsa_libgcrypt: error %s/%s", gcry_strsource(result), gcry_strerror(result));

		}

	    }

	    if (s_sig) gcry_sexp_release(s_sig);

	}

	if (s_pkey) gcry_sexp_release(s_pkey);

    }

    if (s_hash) gcry_sexp_release(s_hash);

    return verified;
}

static int verify_sigH_dss_libgcrypt(struct ssh_key_s *key, struct common_buffer_s *data, struct common_buffer_s *sigH, const char *hashname)
{
    struct _dss_public_key_s *dss=(struct _dss_public_key_s *) key->ptr;
    gcry_sexp_t s_hash=NULL;
    gcry_mpi_t m_hash=NULL;
    int algo=gcry_md_map_name(hashname);
    unsigned int hash_len=gcry_md_get_algo_dlen(algo);
    unsigned char hash[hash_len];
    char hashname_lower[strlen(hashname)+1];
    int verified=-1;

    if (hash_len==0) {

	logoutput("verify_sigH_dss_libgcrypt: hash %s not supported", hashname);
	return -1;

    }

    /* build s-expression for the hash */

    gcry_md_hash_buffer(algo, hash, data->ptr, data->size);

    if (gcry_mpi_scan(&m_hash, GCRYMPI_FMT_USG, hash, hash_len, NULL)==GPG_ERR_NO_ERROR && gcry_sexp_build(&s_hash, NULL, "%m", m_hash)==GPG_ERR_NO_ERROR) {
	gcry_sexp_t s_pkey=NULL;

	/* build s-expression for public key */

	if (gcry_sexp_build(&s_pkey, NULL, "(public-key(dsa(p%m)(q%m)(g%m)(y%m)))", dss->p, dss->q, dss->g, dss->y)==GPG_ERR_NO_ERROR) {
	    gcry_mpi_t m_sig_r=NULL;
	    gcry_mpi_t m_sig_s=NULL;
	    size_t len=0;

	    /*
		build s-expression for signature of H for dss

		(sig-val (dsa(r)(s)))

		see: RFC4253 6.6. Public Key Algorithms
	    */

	    if (gcry_mpi_scan(&m_sig_r, GCRYMPI_FMT_SSH, sigH->ptr, sigH->len, &len)==GPG_ERR_NO_ERROR && 
		gcry_mpi_scan(&m_sig_s, GCRYMPI_FMT_SSH, sigH->ptr + len, sigH->len - len, &len)==GPG_ERR_NO_ERROR) {
		gcry_sexp_t s_sig=NULL;

		if (gcry_sexp_build(&s_sig, NULL, "(sig-val(dsa(r%m)(s%m)))", m_sig_r, m_sig_s)==GPG_ERR_NO_ERROR) {

		    if (gcry_pk_verify(s_sig, s_hash, s_pkey)==GPG_ERR_NO_ERROR) verified=0;

		}

		if (s_sig) gcry_sexp_release(s_sig);

	    }

	    if (m_sig_r) gcry_mpi_release(m_sig_r);
	    if (m_sig_s) gcry_mpi_release(m_sig_s);

	}

	if (s_pkey) gcry_sexp_release(s_pkey);

    }

    if (s_hash) gcry_sexp_release(s_hash);
    if (m_hash) gcry_mpi_release(m_hash);

    return verified;
}

static int verify_sigH_ed25519_libgcrypt(struct ssh_key_s *key, struct common_buffer_s *data, struct common_buffer_s *sigH, const char *hashname)
{
    struct _ecc_public_key_s *ecc=(struct _ecc_public_key_s *) key->ptr;
    gcry_sexp_t s_hash=NULL;
    int verified=-1;

    /* build s-expression for data (here the sign algo does the hashing self)*/

    if (gcry_sexp_build(&s_hash, NULL, "(data (flags eddsa) (hash-algo %s) (value %b))", hashname, data->size, data->ptr)==GPG_ERR_NO_ERROR) {
	gcry_sexp_t s_pkey=NULL;

	/* build s-expression for public key */

	if (gcry_sexp_build(&s_pkey, NULL, "(public-key (ecc (curve Ed25519) (flags eddsa) (q%m)))", ecc->q)==GPG_ERR_NO_ERROR) {
	    gcry_mpi_t m_sig_r=NULL;
	    gcry_mpi_t m_sig_s=NULL;
	    size_t len=0;

	    /*
		build s-expression for signature of H for ed25519

		(sig-val (eddsa(r)(s)))
	    */

	    if (gcry_mpi_scan(&m_sig_r, GCRYMPI_FMT_SSH, sigH->ptr, sigH->len, &len)==GPG_ERR_NO_ERROR && 
		gcry_mpi_scan(&m_sig_s, GCRYMPI_FMT_SSH, sigH->ptr + len, sigH->len - len, &len)==GPG_ERR_NO_ERROR) {
		gcry_sexp_t s_sig=NULL;

		if (gcry_sexp_build(&s_sig, NULL, "(sig-val(eddsa(r%m)(s%m)))", m_sig_r, m_sig_s)==GPG_ERR_NO_ERROR) {

		    if (gcry_pk_verify(s_sig, s_hash, s_pkey)==GPG_ERR_NO_ERROR) verified=0;

		}

		if (s_sig) gcry_sexp_release(s_sig);

	    }

	    if (m_sig_r) gcry_mpi_release(m_sig_r);
	    if (m_sig_s) gcry_mpi_release(m_sig_s);

	}

	if (s_pkey) gcry_sexp_release(s_pkey);

    }

    if (s_hash) gcry_sexp_release(s_hash);

    return verified;
}

static int create_signature_rsa_libgcrypt(struct ssh_key_s *key, struct common_buffer_s *data, struct ssh_string_s *signature, const char *hashname, unsigned int *error)
{
    int success=-1;
    int algo=gcry_md_map_name(hashname);
    unsigned int hash_len=gcry_md_get_algo_dlen(algo);
    unsigned char hash[hash_len];
    char hashname_lower[strlen(hashname)+1];
    gcry_sexp_t s_data=NULL;

    logoutput("create_signature_rsa_libgcrypt");

    if (hash_len==0) {

	logoutput("create_signature_rsa_libgcrypt: hash %s not supported", hashname);
	return -1;

    }

    if (read_parameters_private_key(key, error)==-1) {

	logoutput("create_signature_rsa_libgcrypt: failed to read the rsa parameters");
	return -1;

    }

    *error=0;
    gcry_md_hash_buffer(algo, hash, data->ptr, data->size);

    /*
	digest is hardcoded: sha1 is **always** used for creating signatures
	recently (20161030) I've read on crypto.stackexchange.com that there are plans
	to allow other digests as well:

	- https://tools.ietf.org/html/draft-rsa-dsa-sha2-256-03
	- https://tools.ietf.org/html/draft-ssh-ext-info-05
    */

    memset(hashname_lower, '\0', sizeof(hashname_lower));
    for (unsigned int i=0; i<strlen(hashname); i++) hashname_lower[i]=tolower(hashname[i]);

    if (gcry_sexp_build(&s_data, NULL, "(data (flags pkcs1) (hash %s %b))", hashname, hash_len, hash)==GPG_ERR_NO_ERROR) {
	struct _rsa_private_key_s *rsa=(struct _rsa_private_key_s *) key->ptr;
	gcry_sexp_t s_private=NULL;

	if (gcry_sexp_build(&s_private, NULL, "(private-key(rsa(n%m)(e%m)(d%m)(p%m)(q%m)(u%m)))", rsa->n, rsa->e, rsa->d, rsa->p, rsa->q, rsa->u)==GPG_ERR_NO_ERROR) {
	    gcry_sexp_t s_sig=NULL;
	    gcry_error_t result=0;

	    result=gcry_pk_sign(&s_sig, s_data, s_private);

	    if (result==GPG_ERR_NO_ERROR) {

		/*	find the 's' in the s-expr for the signature
			convert that to a mpi, and write that as buffer used in ssh*/

		gcry_sexp_t list;
		list=gcry_sexp_find_token(s_sig, "s", 0);

		if (list) {
		    gcry_mpi_t tmp=gcry_sexp_nth_mpi(list, 1, 0);
		    size_t size=0;

		    /* write mpi as buffer */

		    size=gcry_mpi_get_nbits(tmp);

		    if (size % 8 == 0) {

			size=size/8;

		    } else {

			size=size/8 + 1;

		    }

		    signature->ptr=malloc(size);

		    if (signature->ptr) {
			size_t written=0;

			result=gcry_mpi_print(GCRYMPI_FMT_STD, (unsigned char *)signature->ptr, size, &written, tmp);

			if (result==GPG_ERR_NO_ERROR) {

			    success=0;
			    signature->len=(unsigned int) written;
			    signature->flags|=SSH_STRING_FLAG_ALLOCATE;

			} else {

			    logoutput("create_signature_rsa_libgcrypt: error %s/%s writing signature", gcry_strsource(result), gcry_strerror(result));
			    free(signature->ptr);
			    signature->ptr=NULL;

			}

		    } else {

			logoutput("create_signature_rsa_libgcrypt: error %i allocating signature (%s)", ENOMEM, strerror(ENOMEM));

		    }

		    gcry_mpi_release(tmp);
		    gcry_sexp_release(list);

		} else {

		    logoutput("create_signature_rsa_libgcrypt: signature not found in sexp");

		}

	    } else {

		logoutput("create_signature_rsa_libgcrypt: error %s/%s", gcry_strsource(result), gcry_strerror(result));
		*error=EIO;

	    }

	    if (s_private) gcry_sexp_release(s_private);

	}

	if (s_data) gcry_sexp_release(s_data);

    }

    free_rsa_private_key(key);

    return success;

}

static int create_signature_dss_libgcrypt(struct ssh_key_s *key, struct common_buffer_s *data, struct ssh_string_s *signature, const char *hashname, unsigned int *error)
{
    gcry_mpi_t m_data=NULL;
    int success=-1;
    int algo=gcry_md_map_name(hashname);
    unsigned int hash_len=gcry_md_get_algo_dlen(algo);
    unsigned char hash[hash_len];
    gcry_sexp_t s_data=NULL;

    if (hash_len==0) {

	logoutput("create_signature_dss_libgcrypt: hash %s not supported", hashname);
	return -1;

    }

    if (read_parameters_private_key(key, error)==-1) {

	logoutput("create_signature_dss_libgcrypt: failed to read the dss parameters");
	return -1;

    }

    *error=0;
    gcry_md_hash_buffer(algo, hash, data->ptr, data->size);

    //if (gcry_mpi_scan(&m_data, GCRYMPI_FMT_USG, sha1_hash, 20, NULL)==GPG_ERR_NO_ERROR && gcry_sexp_build(&s_data, NULL, "(data (flags raw)(value %m))", m_data)==GPG_ERR_NO_ERROR) {
    if (gcry_mpi_scan(&m_data, GCRYMPI_FMT_USG, hash, 20, NULL)==GPG_ERR_NO_ERROR && gcry_sexp_build(&s_data, NULL, "%m", m_data)==GPG_ERR_NO_ERROR) {
	struct _dss_private_key_s *dss=(struct _dss_private_key_s *) key->ptr;
	gcry_sexp_t s_private=NULL;

	if (gcry_sexp_build(&s_private, NULL, "(private-key(dsa(p%m)(q%m)(g%m)(y%m)(x%m)))", dss->p, dss->q, dss->g, dss->y, dss->x)==GPG_ERR_NO_ERROR) {
	    gcry_sexp_t s_sig;
	    gcry_error_t result=0;
	    unsigned int len_s=0;
	    unsigned int len_r=0;

	    result=gcry_pk_sign(&s_sig, s_data, s_private);

	    if (result==GPG_ERR_NO_ERROR) {
		size_t size=0;
		gcry_mpi_t m_sig_r=NULL;
		gcry_mpi_t m_sig_s=NULL;

		/* find the 'r' and the's' in the s-expr for the signature
		    convert both to a mpi, and write them as buffer used in ssh*/

		gcry_sexp_t list;
		list=gcry_sexp_find_token(s_sig, "r", 0);

		if (list) {

		    m_sig_r=gcry_sexp_nth_mpi(list, 1, 0);

		    /* write mpi as buffer */

		    len_r=gcry_mpi_get_nbits(m_sig_r);

		    if (len_r % 8 == 0) {

			len_r=len_r/8;

		    } else {

			len_r=len_r/8 + 1;

		    }

		    size+=len_r;
		    gcry_sexp_release(list);

		}

		list=gcry_sexp_find_token(s_sig, "s", 0);

		if (list) {

		    m_sig_s=gcry_sexp_nth_mpi(list, 1, 0);
		    len_s=gcry_mpi_get_nbits(m_sig_s);

		    if (len_s % 8 == 0) {

			len_s=len_s/8;

		    } else {

			len_s=len_s/8 + 1;

		    }

		    size+=len_s;
		    gcry_sexp_release(list);

		}

		signature->ptr=malloc(size);

		if (signature->ptr) {
		    size_t written=0;
		    char *pos=signature->ptr;

		    result=gcry_mpi_print(GCRYMPI_FMT_STD, (unsigned char *)pos, size, &written, m_sig_r);

		    if (result!=GPG_ERR_NO_ERROR) {

			logoutput("create_signature_dss_libgcrypt: error %s/%s writing signature", gcry_strsource(result), gcry_strerror(result));
			free(signature->ptr);
			signature->ptr=NULL;

		    } else {

			pos+=written;
			result=gcry_mpi_print(GCRYMPI_FMT_STD, (unsigned char *)pos, size - written, &written, m_sig_s);

			if (result!=GPG_ERR_NO_ERROR) {

			    logoutput("create_signature_dss_libgcrypt: error %s/%s writing signature", gcry_strsource(result), gcry_strerror(result));
			    free(signature->ptr);
			    signature->ptr=NULL;

			}

			pos+=written;
			success=0;
			signature->len=(unsigned int) (pos - signature->ptr);
			signature->flags|=SSH_STRING_FLAG_ALLOCATE;
			logoutput("create_signature_dss_libgcrypt: signature len %i", signature->len);

		    }

		} else {

		    logoutput("create_signature_dss_libgcrypt: error %i allocating signature (%s)", ENOMEM, strerror(ENOMEM));

		}

		gcry_mpi_release(m_sig_r);
		gcry_mpi_release(m_sig_s);

	    } else {

		logoutput("create_signature_dss_libgcrypt: error %s/%s", gcry_strsource(result), gcry_strerror(result));
		*error=EIO;

	    }

	    if (s_private) gcry_sexp_release(s_private);

	} else {

	    logoutput("create_signature_dss_libgcrypt: error building sexp");
	    *error=EIO;

	}

	gcry_mpi_release(m_data);
	if (s_data) gcry_sexp_release(s_data);

    } else {

	logoutput("create_signature_dss_libgcrypt: error reading data");
	*error=EIO;

    }

    free_dss_private_key(key);

    return success;

}

static int create_signature_ed25519_libgcrypt(struct ssh_key_s *key, struct common_buffer_s *data, struct ssh_string_s *signature, const char *hashname, unsigned int *error)
{
    int success=-1;
    gcry_sexp_t s_data=NULL;

    if (read_parameters_private_key(key, error)==-1) {

	logoutput("create_signature_ed25519_libgcrypt: failed to read the dss parameters");
	return -1;

    }

    *error=0;

    if (gcry_sexp_build(&s_data, NULL, "(data (flags eddsa) (hash-algo sha512) (value %b))", hashname, data->size, data->ptr)==GPG_ERR_NO_ERROR) {
	struct _ecc_private_key_s *ecc=(struct _ecc_private_key_s *) key->ptr;
	gcry_sexp_t s_private=NULL;

	if (gcry_sexp_build(&s_private, NULL, "(private-key(ecc (curve \"Ed25519\")(flags eddsa)(d%m)))", ecc->d)==GPG_ERR_NO_ERROR) {
	    gcry_sexp_t s_sig;
	    gcry_error_t result=0;
	    unsigned int len_s=0;
	    unsigned int len_r=0;

	    result=gcry_pk_sign(&s_sig, s_data, s_private);

	    if (result==GPG_ERR_NO_ERROR) {
		size_t size=0;
		gcry_mpi_t m_sig_r=NULL;
		gcry_mpi_t m_sig_s=NULL;

		/* find the 'r' and the's' in the s-expr for the signature
		    convert both to a mpi, and write them as buffer used in ssh*/

		gcry_sexp_t list;
		list=gcry_sexp_find_token(s_sig, "r", 0);

		if (list) {

		    m_sig_r=gcry_sexp_nth_mpi(list, 1, 0);

		    /* write mpi as buffer */

		    len_r=gcry_mpi_get_nbits(m_sig_r);

		    if (len_r % 8 == 0) {

			len_r=len_r/8;

		    } else {

			len_r=len_r/8 + 1;

		    }

		    size+=len_r;
		    gcry_sexp_release(list);

		}

		list=gcry_sexp_find_token(s_sig, "s", 0);

		if (list) {

		    m_sig_s=gcry_sexp_nth_mpi(list, 1, 0);
		    len_s=gcry_mpi_get_nbits(m_sig_s);

		    if (len_s % 8 == 0) {

			len_s=len_s/8;

		    } else {

			len_s=len_s/8 + 1;

		    }

		    size+=len_s;
		    gcry_sexp_release(list);

		}

		signature->ptr=malloc(size);

		if (signature->ptr) {
		    size_t written=0;
		    char *pos=signature->ptr;

		    result=gcry_mpi_print(GCRYMPI_FMT_STD, (unsigned char *)pos, size, &written, m_sig_r);

		    if (result!=GPG_ERR_NO_ERROR) {

			logoutput("create_signature_ed25519_libgcrypt: error %s/%s writing signature", gcry_strsource(result), gcry_strerror(result));
			free(signature->ptr);
			signature->ptr=NULL;

		    } else {

			pos+=written;
			result=gcry_mpi_print(GCRYMPI_FMT_STD, (unsigned char *)pos, size - written, &written, m_sig_s);

			if (result!=GPG_ERR_NO_ERROR) {

			    logoutput("create_signature_ed25519_libgcrypt: error %s/%s writing signature", gcry_strsource(result), gcry_strerror(result));
			    free(signature->ptr);
			    signature->ptr=NULL;

			}

			pos+=written;
			success=0;
			signature->len=(unsigned int) (pos - signature->ptr);
			signature->flags|=SSH_STRING_FLAG_ALLOCATE;
			logoutput("create_signature_ed25519_libgcrypt: signature len %i", signature->len);

		    }

		} else {

		    logoutput("create_signature_ed25519_libgcrypt: error %i allocating signature (%s)", ENOMEM, strerror(ENOMEM));

		}

		gcry_mpi_release(m_sig_r);
		gcry_mpi_release(m_sig_s);

	    } else {

		logoutput("create_signature_ed25519_libgcrypt: error %s/%s", gcry_strsource(result), gcry_strerror(result));
		*error=EIO;

	    }

	    if (s_private) gcry_sexp_release(s_private);

	} else {

	    logoutput("create_signature_ed25519_libgcrypt: error building sexp");
	    *error=EIO;

	}

	if (s_data) gcry_sexp_release(s_data);

    } else {

	logoutput("create_signature_ed25519_libgcrypt: error reading data");
	*error=EIO;

    }

    free_dss_private_key(key);

    return success;

}

static int create_signature_libgcrypt(struct ssh_key_s *key, struct common_buffer_s *data, struct ssh_string_s *signature, const char *hashname, unsigned int *error)
{

    if (key->type & _PUBKEY_METHOD_SSH_RSA) {

	return create_signature_rsa_libgcrypt(key, data, signature, hashname, error);

    } else if (key->type & _PUBKEY_METHOD_SSH_DSS) {

	return create_signature_dss_libgcrypt(key, data, signature, hashname, error);

    } else if (key->type & _PUBKEY_METHOD_SSH_ED25519) {

	return create_signature_ed25519_libgcrypt(key, data, signature, hashname, error);

    }

    *error=EINVAL;
    return -1;

}

static int verify_sigH_libgcrypt(struct ssh_key_s *key, struct common_buffer_s *data, struct common_buffer_s *sigH, const char *hashname)
{

    if (key->type & _PUBKEY_METHOD_SSH_RSA) {

	return verify_sigH_rsa_libgcrypt(key, data, sigH, hashname);

    } else if (key->type & _PUBKEY_METHOD_SSH_DSS) {

	return verify_sigH_dss_libgcrypt(key, data, sigH, hashname);

    } else if (key->type & _PUBKEY_METHOD_SSH_ED25519) {

	return verify_sigH_ed25519_libgcrypt(key, data, sigH, hashname);

    }

    return -1;

}

static int read_parameters_libgcrypt(struct ssh_key_s *key, unsigned int *error)
{

    if (key->type & _PUBKEY_METHOD_PRIVATE) {

	if (key->format==_PUBKEY_FORMAT_OPENSSH_KEY) {

	    return read_private_openssh_key(key, error);

	} else if (key->format==_PUBKEY_FORMAT_DER) {

	    if (key->type & _PUBKEY_METHOD_SSH_DSS) {

		return read_private_dss_ASN1_libgcrypt(key, error);

	    } else if (key->type & _PUBKEY_METHOD_SSH_RSA) {

		return read_private_rsa_ASN1_libgcrypt(key, error);

	    }

	}

    } else {

	if (key->type & _PUBKEY_METHOD_SSH_DSS) {

	    return read_parameters_public_dss_ssh_libgcrypt(key, error);

	} else if (key->type & _PUBKEY_METHOD_SSH_RSA) {

	    return read_parameters_public_rsa_ssh_libgcrypt(key, error);

	}

    }

    logoutput("read_parameters_libgcrypt: type not reckognized");
    *error=EINVAL;
    return -1;

}

void init_pubkey_libgcrypt(struct ssh_pubkey_s *pubkey)
{
    pubkey->verify_sigH=verify_sigH_libgcrypt;
    pubkey->read_parameters=read_parameters_libgcrypt;
    pubkey->create_signature=create_signature_libgcrypt;
}

unsigned int ssh_get_pubkey_list_libgcrypt(struct commalist_s *clist)
{
    unsigned int len=0;

    len+=check_add_pubkeyname("ssh-rsa", clist);
    len+=check_add_pubkeyname("ssh-dss", clist);
    return len;

}
