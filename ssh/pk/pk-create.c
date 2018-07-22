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

#include <utils.h>
#include "logging.h"
#include "ssh-datatypes.h"
#include "pk-types.h"
#include "pk-keys.h"

static int compare_sexp_type(gcry_sexp_t s_key, const char *name)
{
    gcry_sexp_t s_data = NULL;
    int result=-1;

    s_data=gcry_sexp_car(s_key);

    if (s_data) {
	size_t len=0;
	const char *data=gcry_sexp_nth_data(s_data, 0, &len);

	if (data) {

	    if (len==strlen(name) && memcmp(data, name, len)==0) result=0;

	}

    }

    if (result==-1) logoutput("compare_sexp_type: s-exp invalid (missing type %s)", name);
    return result;
}

static const char *get_sexp_key_param(gcry_sexp_t s_list, const char *name, size_t *len)
{
    const char *pos=NULL;
    gcry_sexp_t s_param = gcry_sexp_find_token(s_list, name, 0);

    if (s_param) {

	pos=gcry_sexp_nth_data(s_param, 1, len);

    }

    return pos;

}

static int check_presence_sexp_param(gcry_sexp_t s_list, const char *name, const char *value)
{
    int result=-1;
    size_t len=0;
    const char *pos=get_sexp_key_param(s_list, name, &len);

    if (pos && len>0) {

	if (len==strlen(value) && memcmp(pos, value, len)==0) result=0;

    }

    return result;

}

static int read_key_sexp_param_rsa(gcry_sexp_t s_keydata, struct ssh_key_s *key)
{
    gcry_sexp_t s_key=NULL;
    gcry_sexp_t s_param=NULL;
    int result=-1;

    if (key->secret==0) {

	s_key=gcry_sexp_find_token(s_keydata, "public-key", 0);

    } else {

	s_key=gcry_sexp_find_token(s_keydata, "private-key", 0);

    }

    if (s_key) {

	s_param=gcry_sexp_cdr(s_key);

	if (s_param && compare_sexp_type(s_param, "rsa")==0) {
	    gcry_sexp_t s_tmp = NULL;

	    /* d is a regular mpi */

	    s_tmp=gcry_sexp_find_token(s_param, "n", 0);
	    if (s_tmp) key->param.rsa.n.lib.mpi=gcry_sexp_nth_mpi(s_tmp, 1, GCRYMPI_FMT_USG);
	    s_tmp=gcry_sexp_find_token(s_param, "e", 0);
	    if (s_tmp) key->param.rsa.e.lib.mpi=gcry_sexp_nth_mpi(s_tmp, 1, GCRYMPI_FMT_USG);

	    if (key->secret==1) {

		s_tmp=gcry_sexp_find_token(s_param, "d", 0);
		if (s_tmp) key->param.rsa.d.lib.mpi=gcry_sexp_nth_mpi(s_tmp, 1, GCRYMPI_FMT_USG);
		s_tmp=gcry_sexp_find_token(s_param, "p", 0);
		if (s_tmp) key->param.rsa.p.lib.mpi=gcry_sexp_nth_mpi(s_tmp, 1, GCRYMPI_FMT_USG);
		s_tmp=gcry_sexp_find_token(s_param, "q", 0);
		if (s_tmp) key->param.rsa.q.lib.mpi=gcry_sexp_nth_mpi(s_tmp, 1, GCRYMPI_FMT_USG);
		s_tmp=gcry_sexp_find_token(s_param, "u", 0);
		if (s_tmp) key->param.rsa.u.lib.mpi=gcry_sexp_nth_mpi(s_tmp, 1, GCRYMPI_FMT_USG);

	    }


	    if (key->param.rsa.n.lib.mpi==NULL || key->param.rsa.e.lib.mpi==NULL ||
		(key->secret==1 && (key->param.rsa.d.lib.mpi==NULL || key->param.rsa.p.lib.mpi==NULL || key->param.rsa.q.lib.mpi==NULL || key->param.rsa.u.lib.mpi==NULL))) {

		(* key->free_param)(key);

	    } else {

		result=0;

	    }

	}

    }

    out:

    if (s_key) {

	gcry_sexp_release(s_key);
	s_key=NULL;

    }

    if (s_param) {

	gcry_sexp_release(s_param);
	s_param=NULL;

    }

    return result;

}

static int create_ssh_key_rsa(struct ssh_pkalgo_s *algo, struct ssh_key_s *pkey, struct ssh_key_s *skey)
{
    int result=-1;
    gcry_error_t err = 0;
    gcry_sexp_t s_keydata = NULL;
    gcry_sexp_t s_genkey = NULL;
    struct ssh_pkoptions_s *pkoptions=(pkey) ? &pkey->options : &skey->options;

    /* number of bist configurable: get from options */

    if ( pkoptions->options==0 || (pkoptions->options & SSH_PKALGO_OPTION_RSA_BITS_1024)) {

	err=gcry_sexp_build(&s_genkey, NULL, "(genkey (rsa (nbits 4:2048)))");

    } else if ( pkoptions->options & SSH_PKALGO_OPTION_RSA_BITS_2048) {

	err=gcry_sexp_build(&s_genkey, NULL, "(genkey (rsa (nbits 4:2048)))");

    } else {

	logoutput("create_ssh_key_rsa: rsa bit flags not reckognized");
	goto out;

    }

    if (err) {

	logoutput("create_ssh_key_rsa: error creating s-exp (%s/%s)", gcry_strsource(err), gcry_strerror(err));
	goto out;

    }

    err=gcry_pk_genkey(&s_keydata, s_genkey);

    if (err) {

	logoutput("create_ssh_key_rsa: error creating s-exp (%s/%s)", gcry_strsource(err), gcry_strerror(err));
	goto out;

    }

    /* check the first element: it should be "key-data" */

    if (compare_sexp_type(s_keydata, "key-data")==-1) {

	logoutput("create_ssh_key_rsa: s-exp invalid (missing name key-data)");
	goto out;

    }

    /* howto get the values from the public and the private key */

    if (pkey) {

	if (read_key_sexp_param_rsa(s_keydata, pkey)==-1) {

	    logoutput("create_ssh_key_rsa: failed to read public key from s-expr key data");
	    goto out;

	}

    }

    if (skey) {

	if (read_key_sexp_param_rsa(s_keydata, skey)==-1) {

	    logoutput("create_ssh_key_rsa: failed to read private key from s-expr key data");
	    goto out;

	}

    }

    result=0;

    out:

    if (s_genkey) {

	gcry_sexp_release(s_genkey);
	s_genkey=NULL;

    }

    if (s_keydata) {

	gcry_sexp_release(s_keydata);
	s_keydata=NULL;

    }

    return result;

}

static int read_key_sexp_param_dss(gcry_sexp_t s_keydata, struct ssh_key_s *key)
{
    gcry_sexp_t s_key=NULL;
    gcry_sexp_t s_param=NULL;
    int result=-1;

    if (key->secret==0) {

	s_key=gcry_sexp_find_token(s_keydata, "public-key", 0);

    } else {

	s_key=gcry_sexp_find_token(s_keydata, "private-key", 0);

    }

    if (s_key) {

	s_param=gcry_sexp_cdr(s_key);

	if (s_param && compare_sexp_type(s_param, "dsa")==0) {
	    gcry_sexp_t s_tmp = NULL;

	    /* d is a regular mpi */

	    s_tmp=gcry_sexp_find_token(s_param, "p", 0);
	    if (s_tmp) key->param.dss.p.lib.mpi=gcry_sexp_nth_mpi(s_tmp, 1, GCRYMPI_FMT_USG);
	    s_tmp=gcry_sexp_find_token(s_param, "q", 0);
	    if (s_tmp) key->param.dss.q.lib.mpi=gcry_sexp_nth_mpi(s_tmp, 1, GCRYMPI_FMT_USG);
	    s_tmp=gcry_sexp_find_token(s_param, "g", 0);
	    if (s_tmp) key->param.dss.g.lib.mpi=gcry_sexp_nth_mpi(s_tmp, 1, GCRYMPI_FMT_USG);
	    s_tmp=gcry_sexp_find_token(s_param, "y", 0);
	    if (s_tmp) key->param.dss.y.lib.mpi=gcry_sexp_nth_mpi(s_tmp, 1, GCRYMPI_FMT_USG);

	    if (key->secret==1) {

		s_tmp=gcry_sexp_find_token(s_param, "x", 0);
		if (s_tmp) key->param.dss.x.lib.mpi=gcry_sexp_nth_mpi(s_tmp, 1, GCRYMPI_FMT_USG);

	    }


	    if (key->param.dss.p.lib.mpi==NULL || key->param.dss.q.lib.mpi==NULL || key->param.dss.g.lib.mpi==NULL || key->param.dss.y.lib.mpi==NULL ||
		(key->secret==1 && key->param.dss.x.lib.mpi==NULL)) {

		(* key->free_param)(key);

	    } else {

		result=0;

	    }

	}

    }

    out:

    if (s_key) {

	gcry_sexp_release(s_key);
	s_key=NULL;

    }

    if (s_param) {

	gcry_sexp_release(s_param);
	s_param=NULL;

    }

    return result;

}

static int create_ssh_key_dss(struct ssh_pkalgo_s *algo, struct ssh_key_s *pkey, struct ssh_key_s *skey)
{
    int result=-1;
    gcry_error_t err = 0;
    gcry_sexp_t s_keydata = NULL;
    gcry_sexp_t s_genkey = NULL;
    struct ssh_pkoptions_s *pkoptions=(pkey) ? &pkey->options : &skey->options;

    /* number of bist configurable: get from options */

    if ( pkoptions->options==0 || (pkoptions->options & SSH_PKALGO_OPTION_DSS_BITS_1024)) {

	err=gcry_sexp_build(&s_genkey, NULL, "(genkey (dsa (nbits 4:1024)))");

    } else if ( pkoptions->options & SSH_PKALGO_OPTION_DSS_BITS_2048) {

	err=gcry_sexp_build(&s_genkey, NULL, "(genkey (dsa (nbits 4:2048)))");

    } else {

	logoutput("create_ssh_key_dss: rsa bit options not reckognized");
	goto out;

    }

    if (err) {

	logoutput("create_ssh_key_dss: error creating s-exp (%s/%s)", gcry_strsource(err), gcry_strerror(err));
	goto out;

    }

    err=gcry_pk_genkey(&s_keydata, s_genkey);

    if (err) {

	logoutput("create_ssh_key_dss: error creating keydata s-exp (%s/%s)", gcry_strsource(err), gcry_strerror(err));
	goto out;

    }

    /* check the first element: it should be "key-data" */

    if (compare_sexp_type(s_keydata, "key-data")==-1) {

	logoutput("create_ssh_key_dss: s-exp invalid (missing name key-data)");
	goto out;

    }

    /* howto get the values from the public and the private key */

    if (pkey) {

	if (read_key_sexp_param_dss(s_keydata, pkey)==-1) {

	    logoutput("create_ssh_key_dss: failed to read public key from s-expr key data");
	    goto out;

	}

    }

    if (skey) {

	if (read_key_sexp_param_dss(s_keydata, skey)==-1) {

	    logoutput("create_ssh_key_dss: failed to read private key from s-expr key data");
	    goto out;

	}

    }

    result=0;

    out:

    if (s_genkey) {

	gcry_sexp_release(s_genkey);
	s_genkey=NULL;

    }

    if (s_keydata) {

	gcry_sexp_release(s_keydata);
	s_keydata=NULL;

    }

    return result;

}

static int read_key_sexp_param_ecc(gcry_sexp_t s_keydata, struct ssh_key_s *key)
{
    gcry_sexp_t s_key=NULL;
    gcry_sexp_t s_param=NULL;
    int result=-1;

    if (key->secret==0) {

	s_key=gcry_sexp_find_token(s_keydata, "public-key", 0);

    } else {

	s_key=gcry_sexp_find_token(s_keydata, "private-key", 0);

    }

    if (s_key) {

	s_param=gcry_sexp_cdr(s_key);

	if (s_param && compare_sexp_type(s_param, "ecc")==0) {
	    const char *value=NULL;
	    size_t len=0;

	    if (key->algo->id == SSH_PKALGO_ID_ED25519) {

		if (check_presence_sexp_param(s_param, "curve", "Ed25519")==-1) {

		    logoutput("read_key_sexp_param_ecc: s-exp invalid (missing param curve value Ed25519)");
		    goto out;

		}

	    } else if (key->algo->id == SSH_PKALGO_ID_CURVE25519) {

		if (check_presence_sexp_param(s_param, "curve", "Curve25519")==-1) {

		    logoutput("read_key_sexp_param_ecc: s-exp invalid (missing param curve value Curve25519)");
		    goto out;

		}

	    }

	    /* q is the public key and optional for the private key (so if it's not found with the private key it's not fatal) */

	    value=get_sexp_key_param(s_param, "q", &len);

	    if (value && len>0) {
		char *data=malloc(len);

		if (! data) {

		    logoutput("read_key_sexp_param_ecc: error allocating %i bytes", (unsigned int) len);
		    if (key->secret==1) goto privatekey;
		    goto out;

		}

		memcpy(data, value, len);

		if (key->algo->id == SSH_PKALGO_ID_ED25519) {

		    /* q is stored as opaque mpi */

		    key->param.ecc.q.lib.mpi=gcry_mpi_set_opaque(NULL, (void *) data, (8 * len));

		} else if (key->algo->id == SSH_PKALGO_ID_CURVE25519) {
		    // gcry_mpi_t mpi_q_compr=NULL;
		    // gcry_mpi_point_t mpoint_q=gcry_mpi_point_new(0);
		    // gcry_ctx_t ctx;

		    /* decompress the data
			store the q-value first in a tmp opaque mpi */

		    // mpi_q_compr=gcry_mpi_set_opaque(NULL, (void *) data, (8 * len));
		    // gcry_mpi_ec_new(&ctx, NULL, "Curve25519");
		    // gcry_mpi_ec_decode_point(mpoint_q, mpi_q_compr, ctx);

		    /* get the x coordinate
			the result is in little-endian format */

		    // key->param.ecc.q.lib.mpi=gcry_mpi_new(0);
		    // gcry_mpi_point_snatch_get(key->param.ecc.q.lib.mpi, NULL, NULL, mpoint_q);

		    // if (mpi_q_compr) gcry_mpi_release(mpi_q_compr);

		    key->param.ecc.q.lib.mpi=gcry_mpi_set_opaque(NULL, (void *) data, (8 * len));

		}

		if (key->param.ecc.q.lib.mpi) {

		    if (key->secret==0) result=0;

		} else {

		    logoutput("read_key_sexp_param_ecc: failed to store q");
		    free(data);
		    if (key->secret==1) goto privatekey;
		    goto out;

		}

	    } else {

		if (key->secret==0) {

		    /* q is required for the public key */

		    logoutput("read_key_sexp_param_ecc: error q not found");
		    goto out;

		}

	    }

	    privatekey:

	    if (key->secret==1) {
		gcry_sexp_t s_d = gcry_sexp_find_token(s_param, "d", 0);

		/* d is a regular mpi */

		if (s_d) {

		    /* is this right?? in documentation this value is not an mpi */

		    key->param.ecc.d.lib.mpi=gcry_sexp_nth_mpi(s_d, 1, GCRYMPI_FMT_USG);

		    if (key->param.ecc.d.lib.mpi) {

			result=0;

		    } else {

			logoutput("read_key_sexp_param_ecc: failed to store d");

		    }

		    gcry_sexp_release(s_d);

		} else {

		    logoutput("read_key_sexp_param_ecc: error d not found");

		}

	    }

	}

    }

    out:

    if (s_key) {

	gcry_sexp_release(s_key);
	s_key=NULL;

    }

    if (s_param) {

	gcry_sexp_release(s_param);
	s_param=NULL;

    }

    return result;

}

/*
(key-data
  (public-key
    (ecc
      (curve Ed25519)
      (flags eddsa)
      (q q-value)))
  (private-key
    (ecc
      (curve Ed25519)
      (flags eddsa)
      (q q-value)
      (d d-value))))
*/

static int create_ssh_key_ecc(struct ssh_pkalgo_s *algo, struct ssh_key_s *pkey, struct ssh_key_s *skey)
{
    int result=-1;
    gcry_error_t err = 0;
    gcry_sexp_t s_keydata = NULL;
    gcry_sexp_t s_genkey = NULL;

    if (algo->id==SSH_PKALGO_ID_ED25519) {

	err=gcry_sexp_build(&s_genkey, NULL, "(genkey (ecc (curve Ed25519)))");

    } else if (algo->id == SSH_PKALGO_ID_CURVE25519) {

	// err=gcry_sexp_build(&s_genkey, NULL, "(genkey (ecc (curve Curve25519) (flags djb-tweak comp))");
	err=gcry_sexp_build(&s_genkey, NULL, "(genkey (ecc (curve Curve25519) (flags djb-tweak))");

    } else {

	/* others not yet supported */

	logoutput("create_ssh_key_ecc: algo %s not supported", algo->name);
	goto out;

    }

    if (err) {

	logoutput("create_ssh_key_ecc: error creating s-exp (%s/%s)", gcry_strsource(err), gcry_strerror(err));
	goto out;

    }

    err=gcry_pk_genkey(&s_keydata, s_genkey);

    if (err) {

	logoutput("create_ssh_key_ecc: error creating s-exp (%s/%s)", gcry_strsource(err), gcry_strerror(err));
	goto out;

    }

    /* check the first element: it should be "key-data" */

    if (compare_sexp_type(s_keydata, "key-data")==-1) {

	logoutput("create_ssh_key_ecc: s-exp invalid (missing name key-data)");
	goto out;

    }

    /* howto get the values from the public and the private key */

    if (pkey) {

	if (read_key_sexp_param_ecc(s_keydata, pkey)==-1) {

	    logoutput("create_ssh_key_ecc: failed to read public key from s-expr key data");
	    goto out;

	}

    }

    if (skey) {

	if (read_key_sexp_param_ecc(s_keydata, skey)==-1) {

	    logoutput("create_ssh_key_ecc: failed to read private key from s-expr key data");
	    goto out;

	}

    }

    result=0;

    out:

    if (s_genkey) {

	gcry_sexp_release(s_genkey);
	s_genkey=NULL;

    }

    if (s_keydata) {

	gcry_sexp_release(s_keydata);
	s_keydata=NULL;

    }

    return result;

}

int create_ssh_key(struct ssh_pkalgo_s *algo, struct ssh_key_s *pkey, struct ssh_key_s *skey)
{

    if (pkey==NULL && skey==NULL) goto out;
    if (pkey->secret==1 || skey->secret==0) goto out;

    if (pkey) init_ssh_key(pkey, 0, algo);
    if (skey) init_ssh_key(skey, 0, algo);

    switch (algo->id) {

    case SSH_PKALGO_ID_RSA:

	return create_ssh_key_rsa(algo, pkey, skey);

    case SSH_PKALGO_ID_DSS:

	return create_ssh_key_dss(algo, pkey, skey);

    case SSH_PKALGO_ID_ED25519:
    case SSH_PKALGO_ID_CURVE25519:

	return create_ssh_key_ecc(algo, pkey, skey);

    }

    out:

    return -1;

}
