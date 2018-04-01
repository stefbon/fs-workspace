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

#include "asn1.h"

#include "ssh-datatypes.h"
#include "pk-types.h"
#include "pk-keys.h"
#include "pk-read-private.h"
#include "pk-utils.h"

static int asn1_read_mpint_from_tlv(struct asn1_tlv_s *tlv, struct ssh_mpint_s *mp)
{
    size_t count=0;

#if HAVE_LIBGCRYPT

    if (gcry_mpi_scan(&mp->lib.mpi, GCRYMPI_FMT_STD, (const unsigned char *) tlv->pos, (size_t) tlv->len, &count)==GPG_ERR_NO_ERROR) {

	return (int) count;

    } else {

	return -1;

    }

#endif

    return -1;

}

static int asn1_read_parameter(char *pos, unsigned int left, struct asn1_tlv_s *tlv, struct ssh_mpint_s *mp, const char *name)
{

    if (asn1_read_tlv(pos, left, tlv)==0) {

	if (tlv->tag == _ASN1_TAG_INTEGER) {

	    if (mp==NULL) return 0;

	    if (asn1_read_mpint_from_tlv(tlv, mp)==-1) {

		logoutput("asn1_read_parameter: failed to read %s mpint", name);
		return -1;

	    }

	} else {

	    logoutput("asn1_read_parameter: no integer found (%x)", tlv->tag);
	    return -1;

	}

    } else {

	logoutput("asn1_read_parameter: failed to read asn1 tlv");
	return -1;

    }

    return 0;

}


int read_skey_rsa_ASN1(struct ssh_key_s *skey, char *buffer, unsigned int size, unsigned int *error)
{
    char *pos=buffer;
    unsigned int left=size;
    struct asn1_tlv_s tlv;

    /*
	    rsa private key for ssh has the form: (ASN.1, DER-encoded in RFC3447)

	    Version ::= INTEGER { two-prime(0), multi(1) }
    		(CONSTRAINED BY
    		{-- version must be multi if otherPrimeInfos present --})

	    RSAPrivateKey ::= SEQUENCE {
    		version           Version,
    		modulus           INTEGER,  -- n
    		publicExponent    INTEGER,  -- e
    		privateExponent   INTEGER,  -- d
    		prime1            INTEGER,  -- p
    		prime2            INTEGER,  -- q
    		exponent1         INTEGER,  -- d mod (p-1)
    		exponent2         INTEGER,  -- d mod (q-1)
    		coefficient       INTEGER,  -- (inverse of q) mod p
    		otherPrimeInfos   OtherPrimeInfos OPTIONAL
	    }

    */

    /* first the header: 30 ASN.1 tag for sequence */

    if (asn1_read_tlv(pos, left, &tlv)==0) {

	if (tlv.tag == _ASN1_TAG_SEQUENCE) {

	    logoutput("read_skey_rsa_ASN1: read ASN1 sequence %i bytes", tlv.len);

	} else {

	    logoutput("read_skey_rsa_ASN1: starting ASN1 sequence not found");
	    goto error;

	}

    } else {

	logoutput("read_skey_rsa_ASN1: failed to read asn.1 tag %x", _ASN1_TAG_SEQUENCE);
	goto error;

    }

    pos += tlv.bytes;
    left -= tlv.bytes;

    /* inside sequence */

    /* version */

    if (asn1_read_tlv(pos, left, &tlv)==0) {

	if (tlv.tag == _ASN1_TAG_INTEGER) {

	    /* don't know howto print this version integer and what the version means for this format ... */

	    logoutput("read_skey_rsa_ASN1: read ASN1 version %i bytes", tlv.len);

	} else {

	    logoutput("read_skey_rsa_ASN1: failed to read version tag");
	    goto error;

	}

    } else {

	logoutput("read_skey_rsa_ASN1: failed to read version tag");
	goto error;

    }

    pos += tlv.bytes;
    left -= tlv.bytes;

    /* modulus */

    if (asn1_read_parameter(pos, left, &tlv, &skey->param.rsa.n, "public modulus")==-1) goto error;
    pos += tlv.bytes;
    left -= tlv.bytes;

    /* public exponent */

    if (asn1_read_parameter(pos, left, &tlv, &skey->param.rsa.e, "public exponent")==-1) goto error;
    pos += tlv.bytes;
    left -= tlv.bytes;

    /* private exponent */

    if (asn1_read_parameter(pos, left, &tlv, &skey->param.rsa.d, "private exponent")==-1) goto error;
    pos += tlv.bytes;
    left -= tlv.bytes;

    /* private prime p */

    if (asn1_read_parameter(pos, left, &tlv, &skey->param.rsa.p, "private prime p")==-1) goto error;
    pos += tlv.bytes;
    left -= tlv.bytes;

    /* private prime q */

    if (asn1_read_parameter(pos, left, &tlv, &skey->param.rsa.q, "private prime q")==-1) goto error;
    pos += tlv.bytes;
    left -= tlv.bytes;

    /* exponent 1 (ignore) */

    if (asn1_read_parameter(pos, left, &tlv, NULL, "exponent 1")==-1) goto error;
    pos += tlv.bytes;
    left -= tlv.bytes;

    /* exponent 2 (ignore) */

    if (asn1_read_parameter(pos, left, &tlv, NULL, "exponent 2")==-1) goto error;
    pos += tlv.bytes;
    left -= tlv.bytes;

    /* u: inverse of q */

    if (asn1_read_parameter(pos, left, &tlv, &skey->param.rsa.u, "u inverse of q")==-1) goto error;
    pos += tlv.bytes;
    left -= tlv.bytes;

    if (pk_mpint_get_nbits(&skey->param.rsa.p)==0 || pk_mpint_get_nbits(&skey->param.rsa.q)==0 || pk_mpint_get_nbits(&skey->param.rsa.u)==0) {

	/* p, q and u are optional, but all of these are defined or none of them */
	logoutput("read_skey_rsa_ASN1: one of p, q and/or u is empty");

	free_pk_mpint(&skey->param.rsa.p);
	free_pk_mpint(&skey->param.rsa.q);
	free_pk_mpint(&skey->param.rsa.u);

    }

#if HAVE_LIBGCRYPT

    if (pk_mpint_get_nbits(&skey->param.rsa.p)>0 && pk_mpint_get_nbits(&skey->param.rsa.q)>0) {

	/*
		recompute u and swap p and q when this asn.1 key is stored by openssl
		libgcrypt assumes that p<q, openssl q<p
	*/

	if (pk_mpint_cmp(&skey->param.rsa.p, &skey->param.rsa.q) > 0) {

	    /* p > q : swap and recalculate u */
	    logoutput("read_skey_rsa_ASN1: p is bigger then q; swap");

	    pk_mpint_swap(&skey->param.rsa.p, &skey->param.rsa.q);
	    pk_mpint_invm(&skey->param.rsa.u, &skey->param.rsa.p, &skey->param.rsa.q);

	}

    }

#endif

    return 0;

    error:

    logoutput("read_skey_rsa_ASN1:: error reading private key");

    return -1;

}

int read_param_skey_dss_ASN1(struct ssh_key_s *skey, char *buffer, unsigned int size, unsigned int *error)
{
    char *pos=buffer;
    unsigned int left=size;
    struct asn1_tlv_s tlv;

    /*
	    dss private key for ssh has the form: (ASN.1, DER-encoded in RFC3447)

	    Version ::= INTEGER { two-prime(0), multi(1) }
    		(CONSTRAINED BY
    		{-- version must be multi if otherPrimeInfos present --})

	    AlgorithmIdentifier ::= {
		algorithm ALGORITM.id
		parameters Dss-Parms

	    Dss-Parms ::= SEQUENCE {
    		p         INTEGER
    		q    	  INTEGER
    		g   	  INTEGER
	    }

	    DSAPrivateKey ::= OCTETSTRING {
		privateExponent INTEGER
	    }

    */

    /* first the header: 30 ASN.1 tag for sequence */

    if (asn1_read_tlv(pos, left, &tlv)==0) {

	if (tlv.tag == _ASN1_TAG_SEQUENCE) {

	    logoutput("read_skey_dss_ASN1: read ASN1 sequence %i bytes", tlv.len);

	} else {

	    logoutput("read_skey_dss_ASN1: starting ASN1 sequence not found");
	    goto error;

	}

    } else {

	logoutput("read_skey_dss_ASN1: failed to read asn.1 tag %x", _ASN1_TAG_SEQUENCE);
	goto error;

    }

    pos += tlv.bytes;
    left -= tlv.bytes;

    /* inside sequence */

    /* version */

    if (asn1_read_tlv(pos, left, &tlv)==0) {

	if (tlv.tag == _ASN1_TAG_INTEGER) {

	    /* don't know howto print this version integer and what the version means for this format ... */

	    logoutput("read_skey_dss_ASN1: read ASN1 version %i bytes", tlv.len);

	} else {

	    logoutput("read_skey_dss_ASN1: failed to read version tag");
	    goto error;

	}

    } else {

	logoutput("read_skey_dss_ASN1: failed to read version tag");
	goto error;

    }

    pos += tlv.bytes;
    left -= tlv.bytes;

    /* prime (p) */

    if (asn1_read_parameter(pos, left, &tlv, &skey->param.dss.p, "prime")==-1) goto error;
    pos += tlv.bytes;
    left -= tlv.bytes;

    /* order (q) */

    if (asn1_read_parameter(pos, left, &tlv, &skey->param.dss.q, "order")==-1) goto error;
    pos += tlv.bytes;
    left -= tlv.bytes;

    /* generator (g) */

    if (asn1_read_parameter(pos, left, &tlv, &skey->param.dss.g, "generator")==-1) goto error;
    pos += tlv.bytes;
    left -= tlv.bytes;

    /* public (y) */

    if (asn1_read_parameter(pos, left, &tlv, &skey->param.dss.y, "public")==-1) goto error;
    pos += tlv.bytes;
    left -= tlv.bytes;

    /* private (x) */

    if (asn1_read_parameter(pos, left, &tlv, &skey->param.dss.x, "private")==-1) goto error;
    pos += tlv.bytes;
    left -= tlv.bytes;

    return 0;

    error:
    logoutput("read_skey_dss_ASN1: error reading private key");

    return -1;

}

int read_skey_rsa(struct ssh_key_s *skey, char *buffer, unsigned int size, unsigned int format, unsigned int *error)
{

    switch (format) {

    case PK_DATA_FORMAT_DERASN1:

	return read_skey_rsa_ASN1(skey, buffer, size, error);

    default:

	*error=EINVAL;
	logoutput("read_skey_rsa: format not supported");

    }

    return -1;

}

int read_skey_dss(struct ssh_key_s *skey, char *buffer, unsigned int size, unsigned int format, unsigned int *error)
{

    switch (format) {

    case PK_DATA_FORMAT_DERASN1:

	return read_param_skey_dss_ASN1(skey, buffer, size, error);

    default:

	*error=EINVAL;
	logoutput("read_skey_dss: format not supported");

    }

    return -1;

}

int read_skey(struct ssh_key_s *skey, char *buffer, unsigned int size, unsigned int format, unsigned int *error)
{
    struct ssh_pkalgo_s *algo=skey->algo;

    switch (algo->id) {

    case SSH_PKALGO_ID_RSA:

	return read_skey_rsa(skey, buffer, size, format, error);

    case SSH_PKALGO_ID_DSS:

	return read_skey_dss(skey, buffer, size, format, error);

    }

    return -1;

}
