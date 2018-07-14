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
#include <sys/time.h>
#include <time.h>
#include <ctype.h>
#include <inttypes.h>

#include <sys/param.h>
#include <sys/types.h>

#include <logging.h>
#include <utils.h>

#include "ssh-datatypes.h"
#include "pk-types.h"
#include "pk-keys.h"

#ifdef HAVE_LIBGCRYPT

#include <gcrypt.h>

/* generic function to convert a s-expression for a signature to a buffer
    - gcry_sexp_t s_sig				s-expression used by gcrypt for the signature
    - const char *param				tokens to extract from signature s-expression
    - unsigned int len				number of tokens
    - unsigned int *error			error code
*/

static int write_sig_param_buffer(gcry_sexp_t s_sig, struct ssh_string_s *sig, const char *param, unsigned int len, unsigned int *error)
{
    gcry_mpi_t tmp[len];
    size_t size=0;
    int result=0;
    char *pos=NULL;

    memset(tmp, 0, len * sizeof(gcry_mpi_t));

    for (unsigned int i=0; i<len; i++) {

	gcry_sexp_t list = gcry_sexp_find_token(s_sig, &param[i], 1);

	if (list) {
	    unsigned int bits=0;

	    tmp[i]=gcry_sexp_nth_mpi(list, 1, 0);

	    /* get the size in bytes
		normally the number of bits is a multiple of 8 */

	    bits = gcry_mpi_get_nbits(tmp[i]);
	    size += (bits / 8) + (((bits % 8) == 0) ? 0 : 1);

	    gcry_sexp_release(list);

	} else {

	    goto error;

	}

    }

    sig->ptr=malloc(size);

    if (sig->ptr==NULL) {

	*error=ENOMEM;
	goto error;

    }

    sig->len=size;

    /* write mpi to buffer using "STD" format (no length header)
	test this ... for pubkey and hostbased auth */

    pos=sig->ptr;

    for (unsigned int i=0; i<len; i++) {
	size_t written=0;
	gcry_error_t err;

	err=gcry_mpi_print(GCRYMPI_FMT_STD, (unsigned char *)pos, (size_t)(sig->len - result), &written, tmp[i]);

	if (err) {

	    result=0;
	    goto error;

	}

	pos += written;
	result += written;

	gcry_mpi_release(tmp[i]);
	tmp[i]=NULL;

    }

    return result;

    error:

    for (unsigned int i=0; i<len; i++) {

	if (tmp[i]) {

	    gcry_mpi_release(tmp[i]);
	    tmp[i]=NULL;
	}

    }

    if (sig->ptr) {

	free(sig->ptr);
	sig->ptr=NULL;

    }

    return -1;

}

int create_sig_rsa(struct ssh_key_s *key, char *buffer, unsigned int size, struct ssh_string_s *sig, const char *hashname, unsigned int *error)
{
    int success=-1;
    int algo=gcry_md_map_name((hashname) ? hashname : "sha1");
    unsigned int dlen=(algo>0) ? gcry_md_get_algo_dlen(algo) : 0;
    unsigned char digest[dlen];
    gcry_sexp_t s_data = NULL, s_private = NULL, s_sig = NULL;
    gcry_error_t err = 0;
    int len=0;

    logoutput("create_sig_rsa: hash %s", hashname);

    if (dlen==0) {

	logoutput("create_sig_rsa: hash %s not supported", hashname);
	*error=EINVAL;
	return -1;

    }

    gcry_md_hash_buffer(algo, digest, buffer, size);

    err=gcry_sexp_build(&s_data, NULL, "(data (flags pkcs1) (hash %s %b))", gcry_md_algo_name(algo), dlen, digest);

    if (err) {

	logoutput("create_sig_rsa: error %s/%s", gcry_strsource(err), gcry_strerror(err));
	*error=EIO;
	goto out;

    }

    err=gcry_sexp_build(&s_private, NULL, "(private-key (rsa (n %m)(e %m)(d %m)(p %m)(q %m)(u %m)))",
					    key->param.rsa.n.lib.mpi,
					    key->param.rsa.e.lib.mpi,
					    key->param.rsa.d.lib.mpi,
					    key->param.rsa.p.lib.mpi,
					    key->param.rsa.q.lib.mpi,
					    key->param.rsa.u.lib.mpi);

    if (err) {

	logoutput("create_sig_rsa: error %s/%s", gcry_strsource(err), gcry_strerror(err));
	*error=EIO;
	goto out;

    }

    err=gcry_pk_sign(&s_sig, s_data, s_private);

    if (err) {

	logoutput("create_sig_rsa: error %s/%s", gcry_strsource(err), gcry_strerror(err));
	*error=EINVAL;
	goto out;

    }

    /*	find the 's' in the s-expr for the signature
	convert that to a mpi, and write that as buffer used in ssh*/

    len = write_sig_param_buffer(s_sig, sig, "s", 1, error);

    if (len>0) {

	success=0;

	if (len<sig->len) {

	    logoutput_warning("create_sig_rsa: %i bytes allocated, but %i used", sig->len, len);
	    sig->len=len;

	}

    }

    out:

    if (s_data) gcry_sexp_release(s_data);
    if (s_private) gcry_sexp_release(s_private);
    if (s_sig) gcry_sexp_release(s_sig);

    return success;

}

int create_sig_dss(struct ssh_key_s *key, char *buffer, unsigned int size, struct ssh_string_s *sig, const char *hashname, unsigned int *error)
{
    int success=-1;
    int algo=gcry_md_map_name((hashname) ? hashname : "sha1");
    unsigned int dlen=gcry_md_get_algo_dlen(algo);
    unsigned char digest[dlen];
    gcry_sexp_t s_data = NULL, s_private = NULL, s_sig = NULL;
    gcry_error_t err = 0;
    int len = 0;

    if (dlen==0) {

	logoutput("create_sig_dss: hash %s not supported", hashname);
	*error=EINVAL;
	return -1;

    }

    gcry_md_hash_buffer(algo, digest, buffer, size);

    err=gcry_sexp_build(&s_data, NULL, "(data (flags rfc6979) (hash %s %b))", gcry_md_algo_name(algo), dlen, digest);

    if (err) {

	logoutput("create_sig_dss: error %s/%s", gcry_strsource(err), gcry_strerror(err));
	*error=EIO;
	goto out;

    }

    err=gcry_sexp_build(&s_private, NULL, "(private-key (dsa (p %m)(q %m)(g %m)(y %m)(x %m)))",
					    key->param.dss.p.lib.mpi,
					    key->param.dss.q.lib.mpi,
					    key->param.dss.g.lib.mpi,
					    key->param.dss.y.lib.mpi,
					    key->param.dss.x.lib.mpi);

    if (err) {

	logoutput("create_sig_dss: error %s/%s", gcry_strsource(err), gcry_strerror(err));
	*error=EIO;
	goto out;

    }

    err=gcry_pk_sign(&s_sig, s_data, s_private);

    if (err) {

	logoutput("create_sig_dss: error %s/%s", gcry_strsource(err), gcry_strerror(err));
	*error=EIO;
	goto out;

    }

    /* the signature is build, but in s-expression format, convert it a string */

    len = write_sig_param_buffer(s_sig, sig, "rs", 2, error);

    if (len>0) {

	success=0;

	if (len<sig->len) {

	    logoutput_warning("create_sig_dss: %i bytes allocated, but %i used", sig->len, len);
	    sig->len=len;

	}

    }

    out:

    if (s_data) gcry_sexp_release(s_data);
    if (s_private) gcry_sexp_release(s_private);
    if (s_sig) gcry_sexp_release(s_sig);

    return success;

}

int create_sig_ecc(struct ssh_key_s *key, char *buffer, unsigned int size, struct ssh_string_s *sig, const char *hashname, unsigned int *error)
{
    int success=-1;
    int algo=gcry_md_map_name((hashname) ? hashname : "sha1");
    gcry_sexp_t s_data = NULL, s_private = NULL, s_sig = NULL;
    gcry_error_t err = 0;
    int len=0;
    char *curve=NULL;

    if (key->algo->id == SSH_PKALGO_ID_ED25519) {

	curve="Ed25519";

    } else if (key->algo->id & SSH_PKALGO_ID_CURVE25519) {

	curve="Curve25519";

    } else {

	logoutput("create_sig_ecc: error algo %s not supported", key->algo->name);
	goto out;

    }

    err=gcry_sexp_build(&s_data, NULL, "(data (flags eddsa) (hash-algo %s) (value %b))", gcry_md_algo_name(algo), size, buffer);

    if (err) {

	logoutput("create_sig_ecc: error creating data s-exp %s/%s", gcry_strsource(err), gcry_strerror(err));
	*error=EIO;
	goto out;

    }

    /* q is opaque mpint, libgcrypt will handle these */

    if (key->param.ecc.q.lib.mpi) {

	err=gcry_sexp_build(&s_private, NULL, "(private-key(ecc (curve %s)(flags eddsa)(q %m)(d %m)))", curve, key->param.ecc.q.lib.mpi, key->param.ecc.d.lib.mpi);

    } else {

	err=gcry_sexp_build(&s_private, NULL, "(private-key(ecc (curve %s)(flags eddsa)(d %m)))", curve, key->param.ecc.d.lib.mpi);

    }

    if (err) {

	logoutput("create_sig_ecc: error createing private key s-exp %s/%s", gcry_strsource(err), gcry_strerror(err));
	*error=EIO;
	goto out;

    }

    err=gcry_pk_sign(&s_sig, s_data, s_private);

    if (err) {

	logoutput("create_sig_ecc: error signing %s/%s", gcry_strsource(err), gcry_strerror(err));
	*error=EIO;
	goto out;

    }

    len = write_sig_param_buffer(s_sig, sig, "rs", 2, error);

    if (len>0) {

	success=0;

	if (len<sig->len) {

	    logoutput("create_sig_ecc: %i bytes allocated, but %i used", sig->len, len);
	    sig->len=len;

	}

    }

    out:

    if (s_data) gcry_sexp_release(s_data);
    if (s_private) gcry_sexp_release(s_private);
    if (s_sig) gcry_sexp_release(s_sig);

    return success;

}

#else

int create_sig_rsa(struct ssh_key_s *key, char *buffer, unsigned int size, struct ssh_string_s *sig, const char *hashname, unsigned int *error)
{
    *error=EOPNOTSUPP;
    return -1;
}

int create_sig_dss(struct ssh_key_s *key, char *buffer, unsigned int size, struct ssh_string_s *sig, const char *hashname, unsigned int *error)
{
    *error=EOPNOTSUPP;
    return -1;
}

int create_sig_ecc(struct ssh_key_s *key, char *buffer, unsigned int size, struct ssh_string_s *sig, const char *hashname, unsigned int *error)
{
    *error=EOPNOTSUPP;
    return -1;
}

#endif

int create_sig(struct ssh_key_s *key, char *buffer, unsigned int size, struct ssh_string_s *sig, const char *hashname, unsigned int *error)
{
    struct ssh_pkalgo_s *algo=key->algo;

    if (algo==NULL) {

	*error=EINVAL;
	return -1;

    }

    switch (algo->scheme) {

    case SSH_PKALGO_SCHEME_RSA:

	return create_sig_rsa(key, buffer, size, sig, hashname, error);

    case SSH_PKALGO_SCHEME_DSS:

	return create_sig_dss(key, buffer, size, sig, hashname, error);

    case SSH_PKALGO_SCHEME_ECC:

	return create_sig_ecc(key, buffer, size, sig, hashname, error);

    }

    *error=EOPNOTSUPP;
    return -1;

}
