/*
  2017 Stef Bon <stefbon@gmail.com>

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

#if HAVE_LIBGCRYPT

#include <gcrypt.h>

/* create s-exp s_sig build from the param and name like:
    "(sig-val (dsa (r %m)(s %m)))"*/

static int read_pk_signature_params(gcry_mpi_t *tmp, unsigned int len, struct ssh_string_s *sig, unsigned int *error)
{
    gcry_error_t err = 0;
    char *pos=sig->ptr;
    unsigned int left=sig->len;
    size_t size=0;

    for (unsigned int i=0; i<len; i++) {

	tmp[i]=NULL;
	size=0;

	/* param are unsigned integers without header and padding: STD*/

	err=gcry_mpi_scan(&tmp[i], GCRYMPI_FMT_STD, (const unsigned char *)pos, (size_t)left, &size);

	if (err) {

	    logoutput("read_pk_signature_params: error reading signature (%s/%s)", gcry_strsource(err), gcry_strerror(err));
	    *error=EIO;
	    return -1;

	}

	pos += size;
	left -= size;

    }

    return 0;

}

int verify_sig_rsa(struct ssh_key_s *key, char *buffer, unsigned int size, struct ssh_string_s *sig, const char *hashname, unsigned int *error)
{
    int algo = (hashname) ? gcry_md_map_name(hashname) : gcry_md_map_name("sha1");
    unsigned int dlen = (algo>0) ? gcry_md_get_algo_dlen(algo) : 0;
    unsigned char digest[dlen];
    int verified = -1;
    gcry_error_t err = 0;
    gcry_sexp_t s_pkey = NULL, s_hash = NULL, s_sig = NULL;

    if (dlen==0) {

	logoutput("verify_sig_rsa: hash %s not supported", hashname);
	*error=EINVAL;
	return -1;

    }

    gcry_md_hash_buffer(algo, digest, buffer, size);

    err=gcry_sexp_build(&s_hash, NULL, "(data (flags pkcs1) (hash %s %b))", gcry_md_algo_name(algo), dlen, digest);

    if (err) {

	logoutput("verify_sig_rsa: error creating data s-exp (%s/%s)", gcry_strsource(err), gcry_strerror(err));
	*error=EIO;
	goto out;

    }

    err=gcry_sexp_build(&s_pkey, NULL, "(public-key (rsa(e %m)(n %m)))", key->param.rsa.e.lib.mpi, key->param.rsa.n.lib.mpi);

    if (err) {

	logoutput("verify_sig_rsa: error creating pk s-exp (%s/%s)", gcry_strsource(err), gcry_strerror(err));
	*error=EIO;
	goto out;

    }

    /* build s-expression for signature rsa
	(sig-val (rsa(s)))
	see: RFC4253 6.6. Public Key Algorithms
	no reading of paramaters is required as with dss and ecc */

    err=gcry_sexp_build(&s_sig, NULL, "(sig-val (rsa(s %b)))", sig->len, sig->ptr);

    if (err) {

	logoutput("verify_sig_rsa: error creating sig-val s-exp (%s/%s)", gcry_strsource(err), gcry_strerror(err));
	*error=EIO;
	goto out;

    }

    err=gcry_pk_verify(s_sig, s_hash, s_pkey);

    if (err) {

	if (err==GPG_ERR_BAD_SIGNATURE) {

	    /* not an error */

	    logoutput("verify_sig_rsa: bad signature");

	} else {

	    logoutput("verify_sig_rsa: error verify signature (%s/%s)", gcry_strsource(err), gcry_strerror(err));
	    *error=EIO;

	}

    } else {

	verified=0;

    }

    out:

    if (s_sig) gcry_sexp_release(s_sig);
    if (s_pkey) gcry_sexp_release(s_pkey);
    if (s_hash) gcry_sexp_release(s_hash);

    return verified;
}

/* signature for dss is the "r" followed by the "s" */

int verify_sig_dss(struct ssh_key_s *key, char *buffer, unsigned int size, struct ssh_string_s *sig, const char *hashname, unsigned int *error)
{
    int algo = gcry_md_map_name((hashname) ? hashname : "sha1");
    unsigned int dlen = (algo>0) ? gcry_md_get_algo_dlen(algo) : 0;
    unsigned char digest[dlen];
    int verified=-1;
    gcry_error_t err = 0;
    gcry_sexp_t s_pkey = NULL, s_hash = NULL, s_sig = NULL;
    gcry_mpi_t m_sig[2];
    size_t len = 0;

    if (dlen==0) {

	logoutput("verify_sig_dss: hash %s not supported", hashname);
	*error=EINVAL;
	return -1;

    }

    gcry_md_hash_buffer(algo, digest, buffer, size);

    err=gcry_sexp_build(&s_hash, NULL, "(data (flags rfc6979) (hash %s %b))", gcry_md_algo_name(algo), dlen, digest);

    if (err) {

	logoutput("verify_sig_dss: error creating data s-exp (%s/%s)", gcry_strsource(err), gcry_strerror(err));
	*error=EIO;
	goto out;

    }

    err=gcry_sexp_build(&s_pkey, NULL, "(public-key(dsa(p%m)(q%m)(g%m)(y%m)))", key->param.dss.p.lib.mpi, key->param.dss.q.lib.mpi, key->param.dss.g.lib.mpi, key->param.dss.y.lib.mpi);

    if (err) {

	logoutput("verify_sig_dss: error creating pk s-exp (%s/%s)", gcry_strsource(err), gcry_strerror(err));
	*error=EIO;
	goto out;

    }

    /* get the r and s from signature and store in mpi array */

    if (read_pk_signature_params(&m_sig[0], 2, sig, error)==-1) {

	logoutput("verify_sig_dss: error reading signature");
	goto out;

    }

    /* build s-expression for signature for dss
	(sig-val (dsa(r)(s)))
	see: RFC4253 6.6. Public Key Algorithms */

    err=gcry_sexp_build(&s_sig, NULL, "(sig-val (dsa (r %m)(s %m)))", m_sig[0], m_sig[1]);

    if (err) {

	logoutput("verify_sig_dss: error creating sig-val s-exp (%s/%s)", gcry_strsource(err), gcry_strerror(err));
	*error=EIO;
	goto out;

    }

    err=gcry_pk_verify(s_sig, s_hash, s_pkey);

    if (err) {

	if (err==GPG_ERR_BAD_SIGNATURE) {

	    /* not an error */

	    logoutput("verify_sig_dss: bad signature");

	} else {

	    logoutput("verify_sig_dss: error verify signature (%s/%s)", gcry_strsource(err), gcry_strerror(err));
	    *error=EIO;

	}

    } else {

	verified=0;

    }

    out:

    if (s_sig) gcry_sexp_release(s_sig);
    if (m_sig[0]) gcry_mpi_release(m_sig[0]);
    if (m_sig[1]) gcry_mpi_release(m_sig[1]);
    if (s_pkey) gcry_sexp_release(s_pkey);
    if (s_hash) gcry_sexp_release(s_hash);

    return verified;
}

int verify_sig_ecc(struct ssh_key_s *key, char *buffer, unsigned int size, struct ssh_string_s *sig, const char *hashname, unsigned int *error)
{
    int algo = gcry_md_map_name((hashname) ? hashname : "sha1");
    gcry_error_t err = 0;
    gcry_sexp_t s_hash = NULL, s_pkey = NULL, s_sig = NULL;
    gcry_mpi_t m_sig[2];
    size_t len=0;
    int verified=-1;
    void *ptr=NULL;
    unsigned int nbits=0;
    char *curve=NULL;

    if (key->algo->id == SSH_PKALGO_ID_ED25519) {

	curve="Ed25519";

    } else if (key->algo->id == SSH_PKALGO_ID_CURVE25519) {

	curve="Curve25519";

    } else {

	logoutput("create_sig_ecc: error algo %s not supported", key->algo->name);
	goto out;

    }

    if (algo==GCRY_MAC_NONE) {

	logoutput("verify_sig_ecc: hash %s not supported", hashname);
	*error=EINVAL;
	return -1;

    }

    if (sig->len<64) {

	logoutput("verify_sig_ecc: error signature is too short (%i)", sig->len);
	goto out;

    }

    ptr=gcry_mpi_get_opaque(key->param.ecc.q.lib.mpi, &nbits);

    if (ptr==NULL || nbits==0) {

	logoutput("verify_sig_ecc: error reading q as opaque value");
	goto out;

    }

    /* building the s-expr for the publickey
	more flavors are possible: add an if  */

    err=gcry_sexp_build(&s_pkey, NULL, "(public-key (ecc (curve %s) (flags eddsa) (q %b)))", curve, (nbits/8), ptr);

    if (err) {

	logoutput("verify_sig_ecc: error creating pk s-exp (%s/%s)", gcry_strsource(err), gcry_strerror(err));
	goto out;

    }

    /* no hashing of data required, here the sign algo does the hashing self, only provide the name */

    err=gcry_sexp_build(&s_hash, NULL, "(data (flags eddsa) (hash-algo %s) (value %b))", gcry_md_algo_name(algo), size, buffer);

    if (err) {

	logoutput("verify_sig_ecc: error creating data s-exp (%s/%s)", gcry_strsource(err), gcry_strerror(err));
	goto out;

    }

    /* get the r and s from signature and store in mpi array */

    // if (read_pk_signature_params(&m_sig[0], 2, sig, error)==-1) {

	// logoutput("verify_sig_dss: error reading signature");
	// goto out;

    // }

    err=gcry_sexp_build(&s_sig, NULL, "(sig-val (eddsa (r %b) (s %b)))", 32, &sig[0], 32, &sig[32]);

    if (err) {

	logoutput("verify_sig_ecc: error creating sig-val s-exp (%s/%s)", gcry_strsource(err), gcry_strerror(err));
	goto out;

    }

    err=gcry_pk_verify(s_sig, s_hash, s_pkey);

    if (err) {

	if (err==GPG_ERR_BAD_SIGNATURE) {

	    /* not an error */

	    logoutput("verify_sig_ecc: bad signature");

	} else {

	    logoutput("verify_sig_ecc: error verify signature (%s/%s)", gcry_strsource(err), gcry_strerror(err));

	}

    } else {

	verified=0;

    }

    out:

    if (s_sig) gcry_sexp_release(s_sig);
    if (m_sig[0]) gcry_mpi_release(m_sig[0]);
    if (m_sig[1]) gcry_mpi_release(m_sig[1]);
    if (s_pkey) gcry_sexp_release(s_pkey);
    if (s_hash) gcry_sexp_release(s_hash);

    return verified;
}

#else

int verify_sig_rsa(struct ssh_key_s *key, char *buffer, unsigned int size, struct ssh_string_s *sig, const char *hashname, unsigned int *error)
{
    *error=EOPNOTSUPP;
    return -1;
}

int verify_sig_dss(struct ssh_key_s *key, char *buffer, unsigned int size, struct ssh_string_s *sig, const char *hashname, unsigned int *error)
{
    *error=EOPNOTSUPP;
    return -1;
}

int verify_sig_ecc(struct ssh_key_s *key, char *buffer, unsigned int size, struct ssh_string_s *sig, const char *hashname, unsigned int *error)
{
    *error=EOPNOTSUPP;
    return -1;
}

#endif

int verify_sig(struct ssh_key_s *key, char *buffer, unsigned int size, struct ssh_string_s *sig, const char *hashname, unsigned int *error)
{
    struct ssh_pkalgo_s *algo=key->algo;

    switch (algo->scheme) {

    case SSH_PKALGO_SCHEME_RSA:

	return verify_sig_rsa(key, buffer, size, sig, hashname, error);

    case SSH_PKALGO_SCHEME_DSS:

	return verify_sig_dss(key, buffer, size, sig, hashname, error);

    case SSH_PKALGO_SCHEME_ECC:

	return verify_sig_ecc(key, buffer, size, sig, hashname, error);


    }

    *error=EOPNOTSUPP;
    return -1;

}
