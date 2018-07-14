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

#define OPENSSH_KEY_V1					"openssh-key-v1"

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

    if (get_nbytes_ssh_mpint(&skey->param.rsa.p)==0 || get_nbytes_ssh_mpint(&skey->param.rsa.q)==0 || get_nbytes_ssh_mpint(&skey->param.rsa.u)==0) {

	/* p, q and u are optional, but all of these are defined or none of them */
	logoutput("read_skey_rsa_ASN1: one of p, q and/or u is empty");

	free_ssh_mpint(&skey->param.rsa.p);
	free_ssh_mpint(&skey->param.rsa.q);
	free_ssh_mpint(&skey->param.rsa.u);

    }

    if (get_nbytes_ssh_mpint(&skey->param.rsa.p)>0 && get_nbytes_ssh_mpint(&skey->param.rsa.q)>0) {

	/*
		recompute u and swap p and q when this asn.1 key is stored by openssl
		libgcrypt assumes that p<q, openssl q<p
	*/

	if (compare_ssh_mpint(&skey->param.rsa.p, &skey->param.rsa.q) > 0) {

	    /* p > q : swap and recalculate u */
	    logoutput("read_skey_rsa_ASN1: p is bigger then q; swap");

	    swap_ssh_mpint(&skey->param.rsa.p, &skey->param.rsa.q);
	    invm_ssh_mpint(&skey->param.rsa.u, &skey->param.rsa.p, &skey->param.rsa.q);

	}

    }

    return 0;

    error:

    logoutput("read_skey_rsa_ASN1:: error reading private key");

    return -1;

}

static void msg_read_param_skey_rsa_ssh(struct msg_buffer_s *mb, struct ssh_key_s *skey)
{

    msg_read_ssh_mpint(mb, &skey->param.rsa.n, NULL);
    msg_read_ssh_mpint(mb, &skey->param.rsa.e, NULL);
    msg_read_ssh_mpint(mb, &skey->param.rsa.d, NULL);

    /* p, q and u are optional */

    if (mb->pos < mb->len) msg_read_ssh_mpint(mb, &skey->param.rsa.p, NULL);
    if (mb->pos < mb->len) msg_read_ssh_mpint(mb, &skey->param.rsa.q, NULL);
    if (mb->pos < mb->len) msg_read_ssh_mpint(mb, &skey->param.rsa.u, NULL);

    if (get_nbytes_ssh_mpint(&skey->param.rsa.p)==0 || get_nbytes_ssh_mpint(&skey->param.rsa.q)==0 || get_nbytes_ssh_mpint(&skey->param.rsa.u)==0) {

	/* p, q and u are optional, but all of these are defined or none of them */
	logoutput("read_param_skey_rsa_ssh: one of p, q and/or u is empty");

	free_ssh_mpint(&skey->param.rsa.p);
	free_ssh_mpint(&skey->param.rsa.q);
	free_ssh_mpint(&skey->param.rsa.u);

    }

    if (get_nbytes_ssh_mpint(&skey->param.rsa.p)>0 && get_nbytes_ssh_mpint(&skey->param.rsa.q)>0) {

	/*
		recompute u and swap p and q when this asn.1 key is stored by openssl
		libgcrypt assumes that p<q, openssl q<p
	*/

	if (compare_ssh_mpint(&skey->param.rsa.p, &skey->param.rsa.q) > 0) {

	    /* p > q : swap and recalculate u */
	    logoutput("read_param_skey_rsa_ssh: p is bigger then q; swap");

	    swap_ssh_mpint(&skey->param.rsa.p, &skey->param.rsa.q);
	    invm_ssh_mpint(&skey->param.rsa.u, &skey->param.rsa.p, &skey->param.rsa.q);

	}

    }

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

static void msg_read_param_skey_dss_ssh(struct msg_buffer_s *mb, struct ssh_key_s *skey)
{
    msg_read_ssh_mpint(mb, &skey->param.dss.p, NULL);
    msg_read_ssh_mpint(mb, &skey->param.dss.q, NULL);
    msg_read_ssh_mpint(mb, &skey->param.dss.g, NULL);
    msg_read_ssh_mpint(mb, &skey->param.dss.y, NULL);
    msg_read_ssh_mpint(mb, &skey->param.dss.x, NULL);
}

static int read_param_skey_ecc_ssh(struct ssh_key_s *skey, char *buffer, unsigned int size, unsigned int *error)
{
    unsigned int count=buffer_count_strings(buffer, size, 2);
    int result=0;
    char *pos=buffer;
    unsigned int left=size;

    logoutput("read_param_skey_ecc_ssh: %i strings found", count);

    if (count==1) {

	result=read_ssh_mpint(&skey->param.ecc.d, pos, left, SSH_MPINT_FORMAT_SSH, error);

	if (result==-1) {

	    logoutput("read_param_skey_ecc_ssh: error reading buffer");
	    return -1;

	}

    } else if (count>=2) {

	result=read_ssh_mpoint(&skey->param.ecc.q, pos, left, SSH_MPINT_FORMAT_SSH, error);

	if (result==-1) {

	    logoutput("read_param_skey_ecc_ssh: error reading buffer");
	    return -1;

	}

	pos+=result;
	left-=result;

	result=read_ssh_mpint(&skey->param.ecc.d, pos, left, SSH_MPINT_FORMAT_SSH, error);

	if (result==-1) {

	    logoutput("read_param_skey_ecc_ssh: error reading buffer");
	    return -1;

	}

    }

    return 0;

}

static void msg_read_param_skey_ecc_ssh(struct msg_buffer_s *mb, struct ssh_key_s *skey)
{
    unsigned int count=msg_count_strings(mb, 2);

    logoutput("msg_read_param_skey_ecc_ssh: %i strings found", count);

    if (count==1) {

	/* only the required d */

	msg_read_ssh_mpint(mb, &skey->param.ecc.d, NULL);

    } else if (count>=2) {


	msg_read_ssh_mpoint(mb, &skey->param.ecc.q, NULL);
	msg_read_ssh_mpint(mb, &skey->param.ecc.d, NULL);

    } else {

	logoutput("msg_read_param_skey_ecc_ssh: error, %i strings found (1 or 2 possible)", count);

    }

}

static int read_keys_openssh_key_v1(char *buffer, unsigned int size, struct ssh_pkalgo_s *pkalgo, struct ssh_string_s *pk, struct ssh_string_s *sk)
{
    struct msg_buffer_s mb=INIT_SSH_MSG_BUFFER;
    struct ssh_string_s cipher;
    struct ssh_string_s kdf;
    struct ssh_string_s kdfoptions;
    unsigned int count;
    int result=-1;
    struct ssh_string_s esk; /* encrypted secret key*/
    unsigned int blocksize=8; /* default*/
    unsigned int checkint1=0;
    unsigned int checkint2=0;

    logoutput("read_keys_openssh_key_v1");

    set_msg_buffer(&mb, buffer, size);

    init_ssh_string(&cipher);
    init_ssh_string(&kdf);
    init_ssh_string(&kdfoptions);
    init_ssh_string(&esk);

    msg_read_ssh_string(&mb, &cipher);
    msg_read_ssh_string(&mb, &kdf);
    msg_read_ssh_string(&mb, &kdfoptions);
    msg_read_uint32(&mb, &count);

    if (mb.error>0) {

	logoutput("read_keys_openssh_key_v1: error reading openssh key (%i:%s)", mb.error, strerror(mb.error));
	goto out;

    } else if (!(ssh_string_compare(&cipher, 'c', "none")==0) || !(ssh_string_compare(&kdf, 'c', "none")==0)) {
	char string1[cipher.len+1];
	char string2[kdf.len+1];

	if (cipher.len>0) memcpy(string1, cipher.ptr, cipher.len);
	string1[cipher.len]='\0';
	if (kdf.len>0) memcpy(string2, kdf.ptr, kdf.len);
	string2[kdf.len]='\0';

	logoutput("read_keys_openssh_key_v1: cipher %s and or kdf %s not supported", string1, string2);
	goto out;

    } else if (kdfoptions.len>0) {

	logoutput("read_keys_openssh_key_v1: kdfoptions not empty");
	goto out;

    } else if (count==0) {

	logoutput("read_keys_openssh_key_v1: number of keys zero");
	goto out;

    } else if (count>1) {

	logoutput("read_keys_openssh_key_v1: number of keys more than one, not supported");
	goto out;

    }

    /* read public key as string 
	note that pk is encoded as string:
	- uint32		len (n)
	    - uint32		len name algo (m)
	    - byte[m]		name algo
	    - byte[n - 4 - m]	keymaterial */

    msg_read_ssh_string(&mb, pk);

    if (pk->len>0) {
	int read=0;
	struct ssh_pkalgo_s *algo=NULL;

	algo=read_pkalgo(pk->ptr, pk->len, &read);

	if ( algo != pkalgo) {

	    logoutput("read_keys_openssh_key_v1: expecting algo %s but algo %s found", pkalgo->name, algo->name);
	    goto out;

	}

	/* skip the algo part */

	pk->ptr += read;
	pk->len -= read;

    } else {

	logoutput("read_keys_openssh_key_v1: public key zero length");
	goto out;

    }

    /* read list of encrypted private keys */

    msg_read_ssh_string(&mb, &esk);

    logoutput("read_keys_openssh_key_v1: read pk (len=%i) and encrypted sk (len=%i)", pk->len, esk.len);

    if (mb.error>0) {

	logoutput("read_keys_openssh_key_v1: error reading openssh key (%i:%s)", mb.error, strerror(mb.error));
	goto out;

    } else if (esk.len==0) {

	logoutput("read_keys_openssh_key_v1: private encrypted key zero length");
	goto out;

    } else if (!(esk.len % blocksize == 0)) {

	logoutput("read_keys_openssh_key_v1: encrypted secret key has wrong size (remainder %i modulo %i = %i)", esk.len, blocksize, (esk.len % blocksize));
	goto out;

    }

	    /* format of esk is (when using one key) :
		- uint32		len (n)
		    - uint32		test integer
		    - uint32		test integer
		    - uint32		len name algo(m)
		    - byte[m]		name algo
		    - byte[?]		key material
		    - uint32		len comment
		    - byte[o]		padding so n % blocksize == 0


	    problem with this format is that the exact location of the private key is not known
	    because the public key may be here also
	    the way I've solved this is search for this public key, the remaining material is the private key
	    */

    logoutput("read_keys_openssh_key_v1: process encrypted sk");

    set_msg_buffer_string(&mb, &esk);

    msg_read_uint32(&mb, &checkint1);
    msg_read_uint32(&mb, &checkint2);

    logoutput("read_keys_openssh_key_v1: check two integers");

    if (!(checkint1 == checkint2)) {

	logoutput("read_keys_openssh_key_v1: check on two integers failed");
	goto out;

    }

    /* skip the two integers */

    esk.ptr += 8;
    esk.len -= 8;

    if (esk.len>0) {
	int read=0;
	struct ssh_pkalgo_s *algo=NULL;

	algo=read_pkalgo(esk.ptr, esk.len, &read);

	if ( algo != pkalgo) {

	    logoutput("read_keys_openssh_key_v1: expecting algo %s but algo %s found", pkalgo->name, algo->name);
	    goto out;

	}

	/* skip the algo part */

	logoutput("read_keys_openssh_key_v1: skip algo (%i bytes)", read);
	esk.ptr += read;
	esk.len -= read;

	/* esk contains key material and comment and padding */

	if (esk.len > pk->len + 4) {
	    char *pos=NULL;
	    unsigned int len=pk->len;

	    logoutput("read_keys_openssh_key_v1: check encryptes private key is starting with public key");

	    /* private key is starting with public key ? */

	    if (memcmp(esk.ptr, pk->ptr, pk->len)!=0) len=0;
	    pos=memmem((char *) (esk.ptr + len), (esk.len - len), (pk->ptr+4), (pk->len-4));

	    if (pos) {
		unsigned int slen=0;

		logoutput("read_keys_openssh_key_v1: pk found at %i", (unsigned int)(pos - esk.ptr));

		if (read_ssh_string_header((char *) (esk.ptr + len), (esk.len - len), &slen)>0) {

		    logoutput("read_keys_openssh_key_v1: slen %i", slen);

		    if (slen > pk->len - 4) {

			logoutput("read_keys_openssh_key_v1: correct the length of private key from %i to %i", slen, (slen-(pk->len - 4)));

			/* ignore the extra public key added to the private key */
			slen-= (pk->len - 4);
			write_ssh_string_header((char *) (esk.ptr + len), (esk.len - len), slen);

		    }

		}

	    }

	}

	result=0;
	logoutput("read_keys_openssh_key_v1: successfully encrypted sk");
	sk->ptr=esk.ptr;
	sk->len=esk.len;

    }

    out:

    return result;

}

static int read_skey_common_openssh_key(char *buffer, unsigned int size, struct ssh_pkalgo_s *pkalgo, struct ssh_string_s *pk, struct ssh_string_s *sk, unsigned int *error)
{
    unsigned int len=strlen(OPENSSH_KEY_V1);

    /* version openssh key v1 starts with a zero terminated AUTH_MAGIC */

    if ((size > len+1) && memcmp(buffer, OPENSSH_KEY_V1, len)==0 && (buffer[len]==0)) {

	return read_keys_openssh_key_v1((char *)(buffer + len + 1), size - len - 1, pkalgo, pk, sk);

    }

    logoutput("read_skey_common_openssh_key: buffer not starting with openssh key v1 (%s)", OPENSSH_KEY_V1);
    return -1;

}

static int read_skey_openssh_key(struct ssh_key_s *skey, char *buffer, unsigned int size, unsigned int *error)
{
    struct ssh_string_s pk;
    struct ssh_string_s sk;
    int result=-1;

    logoutput("read_skey_openssh_key");

    init_ssh_string(&pk);
    init_ssh_string(&sk);

    if (read_skey_common_openssh_key(buffer, size, skey->algo, &pk, &sk, error)==0) {
	struct ssh_key_s pkey;
	struct msg_buffer_s mb=INIT_SSH_MSG_BUFFER;

	logoutput("read_skey_openssh_key: read pk (len=%i)", pk.len);

	/* read pkey to test skey */

	init_ssh_key(&pkey, 0, skey->algo);
	set_msg_buffer_string(&mb, &pk);
	msg_read_pkey(&mb, &pkey, PK_DATA_FORMAT_PARAM);

	if (mb.error>0) {

	    logoutput("read_skey_openssh_key: error %i reading public key (%s)", mb.error, strerror(mb.error));
	    *error=mb.error;
	    free_ssh_key(&pkey);
	    goto out;

	}

	logoutput("read_skey_openssh_key: read sk (len=%i)", sk.len);

	set_msg_buffer_string(&mb, &sk);
	msg_read_skey(&mb, skey, PK_DATA_FORMAT_SSH);

	if (mb.error>0) {

	    logoutput("read_skey_openssh_key: error %i reading private key (%s)", mb.error, strerror(mb.error));
	    *error=mb.error;
	    free_ssh_key(&pkey);
	    goto out;

	}

	logoutput("read_skey_openssh_key: compare sk and pk");

	if ((* skey->compare_keys)(skey, &pkey)==-1) {

	    logoutput("read_skey_openssh_key: private and public keys don't match");
	    free_ssh_key(&pkey);
	    goto out;

	}

	free_ssh_key(&pkey);
	result=0;

    } else {

    }

    out:

    return result;

}

int read_skey_rsa(struct ssh_key_s *skey, char *buffer, unsigned int size, unsigned int format, unsigned int *error)
{

    switch (format) {

    case PK_DATA_FORMAT_DERASN1:

	return read_skey_rsa_ASN1(skey, buffer, size, error);

    case PK_DATA_FORMAT_OPENSSH_KEY:

	return read_skey_openssh_key(skey, buffer, size, error);

    default:

	*error=EINVAL;
	logoutput("read_skey_rsa: format not supported");

    }

    return -1;

}

void msg_read_skey_rsa(struct msg_buffer_s *mb, struct ssh_key_s *skey, unsigned int format)
{

    switch (format) {

    case PK_DATA_FORMAT_SSH:

	msg_read_param_skey_rsa_ssh(mb, skey);
	break;

    default:

	mb->error=EINVAL;
	logoutput("msg_read_skey_rsa: format not supported");

    }

}

int read_skey_dss(struct ssh_key_s *skey, char *buffer, unsigned int size, unsigned int format, unsigned int *error)
{

    switch (format) {

    case PK_DATA_FORMAT_DERASN1:

	return read_param_skey_dss_ASN1(skey, buffer, size, error);

    case PK_DATA_FORMAT_OPENSSH_KEY:

	return read_skey_openssh_key(skey, buffer, size, error);

    default:

	*error=EINVAL;
	logoutput("read_skey_dss: format not supported");

    }

    return -1;

}

void msg_read_skey_dss(struct msg_buffer_s *mb, struct ssh_key_s *skey, unsigned int format)
{

    switch (format) {

    case PK_DATA_FORMAT_SSH:

	msg_read_param_skey_dss_ssh(mb, skey);
	break;

    default:

	mb->error=EINVAL;
	logoutput("msg_read_skey_dss: format not supported");

    }

}

int read_skey_ecc(struct ssh_key_s *skey, char *buffer, unsigned int size, unsigned int format, unsigned int *error)
{

    /* for ecc (=ed25519 ea) DER/ASN1 is not supported. These keys are always written to openssh key format*/

    switch (format) {

    case PK_DATA_FORMAT_SSH:

	return read_param_skey_ecc_ssh(skey, buffer, size, error);

    case PK_DATA_FORMAT_OPENSSH_KEY:

	return read_skey_openssh_key(skey, buffer, size, error);

    default:

	*error=EINVAL;
	logoutput("read_skey_ecc: format not supported");

    }

    return -1;

}

void msg_read_skey_ecc(struct msg_buffer_s *mb, struct ssh_key_s *skey, unsigned int format)
{

    logoutput("msg_read_skey_ecc");

    switch (format) {

    case PK_DATA_FORMAT_SSH:

	msg_read_param_skey_ecc_ssh(mb, skey);
	break;

    default:

	mb->error=EINVAL;
	logoutput("msg_read_skey_ecc: format not supported");

    }

}

int read_skey(struct ssh_key_s *skey, char *buffer, unsigned int size, unsigned int format, unsigned int *error)
{
    struct ssh_pkalgo_s *algo=skey->algo;

    switch (algo->scheme) {

    case SSH_PKALGO_SCHEME_RSA:

	return read_skey_rsa(skey, buffer, size, format, error);

    case SSH_PKALGO_SCHEME_DSS:

	return read_skey_dss(skey, buffer, size, format, error);

    case SSH_PKALGO_SCHEME_ECC:

	return read_skey_ecc(skey, buffer, size, format, error);

    }

    return -1;

}
