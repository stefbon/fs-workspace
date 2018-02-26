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

#include "ctx-keystore.h"
#include "ssh-common.h"
#include "ssh-utils.h"
#include "ssh-pubkey-utils-libgcrypt.h"
#include "ssh-pubkey-utils.h"

/* reading of the servers public key and get the various parameters (like n, e p)
    note that the format used here is described in RFC 4253 6.6.  Public Key Algorithms */

    /*
	    rsa public key for ssh has the form:
	    string		"ssh-rsa"
	    mpint		e
	    mpint		n
    */

int read_parameters_public_rsa_ssh_libgcrypt(struct ssh_key_s *key, unsigned int *error)
{
    struct _rsa_public_key_s *rsa=(struct _rsa_public_key_s *) key->ptr;
    struct common_buffer_s *data=&key->data;
    unsigned char type=0;
    unsigned int len=0;
    unsigned int left=data->len;

    data->pos=data->ptr;
    len=read_ssh_type_pubkey_buffer(data, &type, error);

    if (len==0 || !(type==_PUBKEY_METHOD_SSH_RSA)) {

	logoutput_warning("read_parameters_public_rsa_ssh_libgcrypt: found wrong format");
	*error=EINVAL;
	return -1;

    }

    left-=len;

    if (! rsa) {

	rsa=malloc(sizeof(struct _rsa_public_key_s));

	if (rsa) {

	    memset(rsa, 0, sizeof(struct _rsa_public_key_s));
	    _init_rsa_public_key(rsa);

	    key->ptr=(void *) rsa;
	    key->free_ptr=free_rsa_public_key;

	} else {

	    logoutput_warning("read_parameters_public_rsa_ssh_libgcrypt: unable to allocate memory");
	    *error=ENOMEM;
	    return -1;

	}

    }

    if (left>4) {
	size_t size=0;
	gcry_error_t result=GPG_ERR_NO_ERROR;

	result=gcry_mpi_scan(&rsa->e, GCRYMPI_FMT_SSH, data->pos, (size_t) left, &size);

	if (result==GPG_ERR_NO_ERROR) {

	    data->pos+=size;
	    left-=size;

	} else {

	    logoutput_warning("read_parameters_public_rsa_ssh_libgcrypt: error (libgcrypt code %i) reading rsa->e", result);
	    *error=EIO;
	    return -1;

	}

    } else {

	logoutput_warning("read_parameters_public_rsa_ssh_libgcrypt: error key too small");
	*error=EINVAL;
	return -1;

    }

    if (left>4) {
	size_t size=0;
	gcry_error_t result=GPG_ERR_NO_ERROR;

	result=gcry_mpi_scan(&rsa->n, GCRYMPI_FMT_SSH, data->pos, (size_t) left, &size);

	if (result==GPG_ERR_NO_ERROR) {

	    data->pos+=size;
	    left-=size;

	} else {

	    logoutput_warning("read_parameters_public_rsa_ssh_libgcrypt: error (libgcrypt code %i) reading rsa->n", result);
	    *error=EIO;
	    return -1;

	}

    } else {

	logoutput_warning("read_parameters_public_rsa_ssh_libgcrypt: error key too small");
	*error=EINVAL;
	return -1;

    }

    return 0;

}

    /*
	    dss public key for ssh has format:
	    string 		"ssh-dss"
	    mpint		p
	    mpint		q
	    mpint		g
	    mpint		y
    */

int read_parameters_public_dss_ssh_libgcrypt(struct ssh_key_s *key, unsigned int *error)
{
    struct _dss_public_key_s *dss=(struct _dss_public_key_s *) key->ptr;
    struct common_buffer_s *data=&key->data;
    unsigned char type=0;
    unsigned int len=0;
    unsigned int left=data->len;

    logoutput("read_parameters_public_dss_ssh_libgcrypt");

    data->pos=data->ptr;
    len=read_ssh_type_pubkey_buffer(data, &type, error);

    if (len==0 || !(type==_PUBKEY_METHOD_SSH_DSS)) {

	logoutput_warning("read_parameters_public_dss_ssh_libgcrypt: found wrong format");
	*error=EINVAL;
	return -1;

    }

    left-=len;

    if (! dss) {

	dss=malloc(sizeof(struct _dss_public_key_s));

	if (dss) {

	    memset(dss, 0, sizeof(struct _dss_public_key_s));
	    _init_dss_public_key(dss);

	    key->ptr=(void *) dss;
	    key->free_ptr=free_dss_public_key;

	} else {

	    logoutput_warning("read_parameters_public_key_dss_libgcrypt: unable to allocate memory");
	    *error=ENOMEM;
	    return -1;

	}

    }

    if (left>4) {
	size_t size=0;
	gcry_error_t result=GPG_ERR_NO_ERROR;

	result=gcry_mpi_scan(&dss->p, GCRYMPI_FMT_SSH, data->pos, (size_t) left, &size);

	if (result==GPG_ERR_NO_ERROR) {

	    data->pos+=size;
	    left-=size;

	} else {

	    logoutput_warning("read_parameters_public_key_dss_libgcrypt: error (libgcrypt code %i) reading dss->p", result);
	    *error=EIO;
	    return -1;

	}

    } else {

	logoutput_warning("read_parameters_public_key_dss_libgcrypt: error key too small");
	*error=EINVAL;
	return -1;

    }

    if (left>4) {
	size_t size=0;
	gcry_error_t result=GPG_ERR_NO_ERROR;

	result=gcry_mpi_scan(&dss->q, GCRYMPI_FMT_SSH, data->pos, (size_t) left, &size);

	if (result==GPG_ERR_NO_ERROR) {

	    data->pos+=size;
	    left-=size;

	} else {

	    logoutput_warning("read_parameters_public_key_dss_libgcrypt: error (libgcrypt code %i) reading dss->q", result);
	    *error=EIO;
	    return -1;

	}

    } else {

	logoutput_warning("read_parameters_public_key_dss_libgcrypt: error key too small");
	*error=EINVAL;
	return -1;

    }

    if (left>4) {
	size_t size=0;
	gcry_error_t result=GPG_ERR_NO_ERROR;

	result=gcry_mpi_scan(&dss->g, GCRYMPI_FMT_SSH, data->pos, (size_t) left, &size);

	if (result==GPG_ERR_NO_ERROR) {

	    data->pos+=size;
	    left-=size;

	} else {

	    logoutput_warning("read_parameters_public_key_dss_libgcrypt: error (libgcrypt code %i) reading dss->g", result);
	    *error=EIO;
	    return -1;

	}

    } else {

	logoutput_warning("read_parameters_public_key_dss_libgcrypt: error key too small");
	*error=EINVAL;
	return -1;

    }

    if (left>4) {
	size_t size=0;
	gcry_error_t result=GPG_ERR_NO_ERROR;

	result=gcry_mpi_scan(&dss->y, GCRYMPI_FMT_SSH, data->pos, (size_t) left, &size);

	if (result==GPG_ERR_NO_ERROR) {

	    data->pos+=size;
	    left-=size;

	} else {

	    logoutput_warning("read_parameters_public_key_dss_libgcrypt: error (libgcrypt code %i) reading dss->y", result);
	    *error=EIO;
	    return -1;

	}

    } else {

	logoutput_warning("read_parameters_public_key_dss_libgcrypt: error key too small");
	*error=EINVAL;
	return -1;

    }

    return 0;

}

    /*
	ecc public key for ssh has format:
	string 		"ssh-ed25519"
	mpoint		q
    */

int read_parameters_public_ed25519_ssh_libgcrypt(struct ssh_key_s *key, unsigned int *error)
{
    struct _ecc_public_key_s *ecc=(struct _ecc_public_key_s *) key->ptr;
    struct common_buffer_s *data=&key->data;
    size_t len=0;
    unsigned char type=0;
    unsigned int left=data->len;

    data->pos=data->ptr;
    len=read_ssh_type_pubkey_buffer(data, &type, error);

    if (len==0 || !(type==_PUBKEY_METHOD_SSH_ED25519)) {

	logoutput_warning("read_parameters_public_ed25519_ssh_libgcrypt: found wrong format");
	*error=EINVAL;
	return -1;

    }

    left-=len;

    if (! ecc) {

	ecc=malloc(sizeof(struct _ecc_public_key_s));

	if (ecc) {

	    memset(ecc, 0, sizeof(struct _ecc_public_key_s));
	    _init_ecc_public_key(ecc);

	    key->ptr=(void *) ecc;
	    key->free_ptr=free_ecc_public_key;

	} else {

	    logoutput_warning("read_parameters_public_key_ed25519_libgcrypt: unable to allocate memory");
	    *error=ENOMEM;
	    return -1;

	}

    }

    if (left>4) {

	/* different: as gnupg/agent/command-ssh.c
	    store buffer and make it mpi and set opaque
	    TODO: test length to a max - error when larger than some value 
	*/

	len=get_uint32(data->pos);
	data->pos+=4;
	left-=4;

	if (len<=left) {
	    char *buffer=NULL;

	    buffer=malloc(len + 1);

	    if (buffer) {

		memcpy(&buffer[1], data->pos, len);
		buffer[0]=0x40; /* prefix for EdDSA in OpenPGP/libgcrypt */

		ecc->q=gcry_mpi_set_opaque(NULL, buffer, 8*(len+1));

	    } else {

		logoutput_warning("read_parameters_public_key_ed25519_libgcrypt: unable to allocate memory");
		*error=ENOMEM;
		return -1;

	    }

	} else {

	    logoutput_warning("read_parameters_public_key_ed25519_libgcrypt: error key too small");
	    *error=EINVAL;
	    return -1;

	}

    } else {

	logoutput_warning("read_parameters_public_key_ed25519_libgcrypt: error key too small");
	*error=EINVAL;
	return -1;

    }

    return 0;

}

static size_t asn_read_length(char *pos, unsigned int *integer, unsigned int left)
{
    unsigned char value=(unsigned char) *pos;
    unsigned char bit8=(value >> 7);

    if (bit8==1) {
	unsigned int result=0;

	/* number of fields */

	value -= (bit8 << 7);

	if (value>left) return 0;
	pos++;

	for (unsigned int i=0; i<value; i++) {

	    result = (result << 8) + (unsigned char) *pos;
	    pos++;

	}

	*integer=result;
	return (size_t) (1 + value); /* number of bytes for integer plus 1*/

    }

    *integer=value;
    return 1;

}

static size_t asn_read_integer(char *pos, unsigned int *integer, unsigned int left)
{
    return asn_read_length(pos, integer, left);
}

static size_t asn_read_integer_n(char *pos, unsigned int *integer, unsigned int left)
{
    unsigned char fields=0;

    fields=(unsigned char) *pos;

    logoutput("asn_read_integer: fields %i", fields);

    if (fields>left) return 0;
    pos++;

    if (fields>0) {
	int result=-1;

	for (unsigned int i=0; i<fields; i++) {

	    if (i==0) {

		result &= (char) *pos;

	    } else {

		result = (result << 8) & (unsigned char) *pos;

	    }

	    pos++;

	}

	*integer=result;
	return fields + 1;

    }

    *integer=0;
    return 1;

}

int read_private_rsa_ASN1_libgcrypt(struct ssh_key_s *key, unsigned int *error)
{
    struct common_buffer_s *data=&key->data;
    size_t left=(size_t) (data->ptr + data->size - data->pos);
    struct _rsa_private_key_s *rsa=(struct _rsa_private_key_s *) key->ptr;

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

    logoutput("read_private_rsa_ASN1_libgcrypt");

    if (! rsa) {

	rsa=malloc(sizeof(struct _rsa_private_key_s));

	if (rsa) {

	    memset(rsa, 0, sizeof(struct _rsa_private_key_s));
	    _init_rsa_private_key(rsa);

	    key->ptr=(void *) rsa;
	    key->free_ptr=free_rsa_private_key;

	} else {

	    logoutput_warning("read_private_rsa_ASN1_libgcrypt: unable to allocate memory");
	    *error=ENOMEM;
	    return -1;

	}

    }

    /* first the header: 30 ASN.1 tag for sequence */

    if ((unsigned char) *data->pos == 0x30 ) {

	data->pos+=1;
	left-=1;

    } else {

	goto error;

    }

    /* the length field */

    if (left>0) {
	size_t count=0;
	unsigned int len=0;

	/* get the number of field for length */

	count=asn_read_length(data->pos, &len, left);

	if (count==0) {

	    logoutput("read_rsa_private_ASN1: invalid length");
	    goto error;

	}

	/* leave the contents of the length: it should be pos + tmp + 1 + length == crypt->key + crypt->size*/

	data->pos += count;
	left-= count;

    } else {

	goto error;

    }

    /* version */

    if (left>0 && (unsigned char) *data->pos == 0x02) {
	unsigned int len=0;
	size_t count=0;

	data->pos++;
	count=asn_read_integer(data->pos, &len, left);

	data->pos+=count+len;
	left-=(count+len);

    } else {

	goto error;

    }

    /* modulus */

    if (left>0 && (unsigned char) *data->pos == 0x02) {
	unsigned int len=0;
	size_t count=0;

	data->pos++;
	count=asn_read_integer(data->pos, &len, left);
	data->pos+=count;
	left-=count;

	if (gcry_mpi_scan(&rsa->n, GCRYMPI_FMT_STD, data->pos, len, &count)==GPG_ERR_NO_ERROR) {

	    data->pos += count;
	    left -= count;

	} else {

	    goto error;

	}

    }

    /* public exponent */

    if (left>0 && (unsigned char) *data->pos == 0x02) {
	unsigned int len=0;
	size_t count=0;

	data->pos++;
	count=asn_read_integer(data->pos, &len, left);
	data->pos+=count;
	left-=count;

	if (gcry_mpi_scan(&rsa->e, GCRYMPI_FMT_STD, data->pos, len, &count)==GPG_ERR_NO_ERROR) {

	    data->pos += count;
	    left -= count;

	} else {

	    goto error;

	}

    }

    /* private exponent */

    if (left>0 && (unsigned char) *data->pos == 0x02) {
	unsigned int len=0;
	size_t count=0;

	data->pos++;
	count=asn_read_integer(data->pos, &len, left);
	data->pos+=count;
	left-=count;

	if (gcry_mpi_scan(&rsa->d, GCRYMPI_FMT_STD, data->pos, len, &count)==GPG_ERR_NO_ERROR) {

	    data->pos += count;
	    left -= count;

	} else {

	    goto error;

	}

    }

    /* prime 1 */

    if (left>0 && (unsigned char) *data->pos == 0x02) {
	unsigned int len=0;
	size_t count=0;

	data->pos++;
	count=asn_read_integer(data->pos, &len, left);
	data->pos+=count;
	left-=count;

	if (gcry_mpi_scan(&rsa->p, GCRYMPI_FMT_STD, data->pos, len, &count)==GPG_ERR_NO_ERROR) {

	    data->pos += count;
	    left -= count;

	} else {

	    goto error;

	}

    }

    /* prime 2 */

    if (left>0 && (unsigned char) *data->pos == 0x02) {
	unsigned int len=0;
	size_t count=0;

	data->pos++;
	count=asn_read_integer(data->pos, &len, left);
	data->pos+=count;
	left-=count;

	if (gcry_mpi_scan(&rsa->q, GCRYMPI_FMT_STD, data->pos, len, &count)==GPG_ERR_NO_ERROR) {

	    data->pos += count;
	    left -= count;

	} else {

	    goto error;

	}

    }

    /* exponent 1 */

    if (left>0 && (unsigned char) *data->pos == 0x02) {
	unsigned int len=0;
	size_t count=0;

	data->pos++;
	count=asn_read_integer(data->pos, &len, left);
	data->pos+=count;
	left-=count;

	if (gcry_mpi_scan(&rsa->exp1, GCRYMPI_FMT_STD, data->pos, len, &count)==GPG_ERR_NO_ERROR) {

	    data->pos += count;
	    left -= count;

	} else {

	    goto error;

	}

    }

    /* exponent 2 */

    if (left>0 && (unsigned char) *data->pos == 0x02) {
	unsigned int len=0;
	size_t count=0;

	data->pos++;
	count=asn_read_integer(data->pos, &len, left);
	data->pos+=count;
	left-=count;

	if (gcry_mpi_scan(&rsa->exp2, GCRYMPI_FMT_STD, data->pos, len, &count)==GPG_ERR_NO_ERROR) {

	    data->pos += count;
	    left -= count;

	} else {

	    goto error;

	}

    }

    /* u: inverse of q */

    if (left>0 && (unsigned char) *data->pos == 0x02) {
	unsigned int len=0;
	size_t count=0;

	data->pos++;
	count=asn_read_integer(data->pos, &len, left);
	data->pos+=count;
	left-=count;

	if (gcry_mpi_scan(&rsa->u, GCRYMPI_FMT_STD, data->pos, len, &count)==GPG_ERR_NO_ERROR) {

	    data->pos += count;
	    left -= count;

	} else {

	    goto error;

	}

    }

    /* some fields may be not defined like p, q and u */

    if (rsa->u==NULL || rsa->p==NULL || rsa->q==NULL) {

	if (rsa->q) {

	    gcry_mpi_release(rsa->q);
	    rsa->q=NULL;

	}

	if (rsa->p) {

	    gcry_mpi_release(rsa->p);
	    rsa->p=NULL;

	}

	if (rsa->u) {

	    gcry_mpi_release(rsa->u);
	    rsa->u=NULL;

	}

    } else {

	/*
	    recompute u and swap p and q when this asn.1 key is stored by openssl
	    libgcrypt assumes that p<q, openssl q<p
	*/

	if (gcry_mpi_cmp(rsa->p, rsa->q) > 0) {

	    gcry_mpi_swap(rsa->p, rsa->q);
	    gcry_mpi_invm(rsa->u, rsa->p, rsa->q);

	}

    }

    return 0;

    error:

    _free_rsa_private_key(rsa);
    logoutput("read_private_rsa_ASN1_libgcrypt: error reading private key");

    return -1;

}

int read_private_dss_ASN1_libgcrypt(struct ssh_key_s *key, unsigned int *error)
{
    struct common_buffer_s *data=&key->data;
    size_t left=(size_t) (data->ptr + data->size - data->pos);
    struct _dss_private_key_s *dss=(struct _dss_private_key_s *) key->ptr;

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

    logoutput("read_private_dss_ASN1_libgcrypt");

    if (! dss) {

	dss=malloc(sizeof(struct _dss_private_key_s));

	if (dss) {

	    memset(dss, 0, sizeof(struct _dss_private_key_s));
	    _init_dss_private_key(dss);

	    key->ptr=(void *) dss;
	    key->free_ptr=free_dss_private_key;

	} else {

	    logoutput_warning("read_private_dss_ASN1_libgcrypt: unable to allocate memory");
	    *error=ENOMEM;
	    return -1;

	}

    }

    /* first the header: 30 ASN.1 tag for sequence */

    if ((unsigned char) *data->pos == 0x30) {

	data->pos+=1;
	left-=1;

    } else {

	goto error;

    }

    /* the length field */

    if (left>0) {
	size_t count=0;
	unsigned int len=0;

	/* get the number of field for length */

	count=asn_read_length(data->pos, &len, left);

	if (count==0) {

	    logoutput("read_private_dss_ASN1_libgcrypt: invalid length");
	    goto error;

	}

	/* leave the contents of the length: it should be pos + tmp + 1 + length == crypt->key + crypt->size*/

	data->pos += count;
	left-= count;

    } else {

	goto error;

    }

    /* version */

    if (left>0 && (unsigned char) *data->pos == 0x02) {
	unsigned int len=0;
	size_t count=0;

	data->pos++;
	count=asn_read_integer(data->pos, &len, left);

	data->pos+=count+len;
	left-=(count+len);

    } else {

	goto error;

    }


    /* modulus */

    if (left>0 && (unsigned char) *data->pos == 0x02) {
	unsigned int len=0;
	size_t count=0;

	data->pos++;
	count=asn_read_integer(data->pos, &len, left);
	data->pos+=count;
	left-=count;

	logoutput("read_private_dss_ASN1_libgcrypt: (modules) integer len %i", len);

	if (gcry_mpi_scan(&dss->p, GCRYMPI_FMT_STD, data->pos, len, &count)==GPG_ERR_NO_ERROR) {

	    data->pos += count;
	    left -= count;

	} else {

	    goto error;

	}

    }

    /* order */

    if (left>0 && (unsigned char) *data->pos == 0x02) {
	unsigned int len=0;
	size_t count=0;

	data->pos++;
	count=asn_read_integer(data->pos, &len, left);
	data->pos+=count;
	left-=count;

	logoutput("read_private_dss_ASN1_libgcrypt: (order) integer len %i", len);

	if (gcry_mpi_scan(&dss->q, GCRYMPI_FMT_STD, data->pos, len, &count)==GPG_ERR_NO_ERROR) {

	    data->pos += count;
	    left -= count;

	} else {

	    goto error;

	}

    }

    /* generator */

    if (left>0 && (unsigned char) *data->pos == 0x02) {
	unsigned int len=0;
	size_t count=0;

	data->pos++;
	count=asn_read_integer(data->pos, &len, left);
	data->pos+=count;
	left-=count;

	logoutput("read_private_dss_ASN1_libgcrypt: (generator) integer len %i", len);

	if (gcry_mpi_scan(&dss->g, GCRYMPI_FMT_STD, data->pos, len, &count)==GPG_ERR_NO_ERROR) {

	    data->pos += count;
	    left -= count;

	} else {

	    goto error;

	}

    }

    /* public */

    if (left>0 && (unsigned char) *data->pos == 0x02) {
	unsigned int len=0;
	size_t count=0;

	data->pos++;
	count=asn_read_integer(data->pos, &len, left);
	data->pos+=count;
	left-=count;

	logoutput("read_private_dss_ASN1_libgcrypt: (public) integer len %i", len);

	if (gcry_mpi_scan(&dss->y, GCRYMPI_FMT_STD, data->pos, len, &count)==GPG_ERR_NO_ERROR) {

	    data->pos += count;
	    left -= count;

	} else {

	    goto error;

	}

    }

    /* private */

    if (left>0 && (unsigned char) *data->pos == 0x02) {
	unsigned int len=0;
	size_t count=0;

	data->pos++;
	count=asn_read_integer(data->pos, &len, left);
	data->pos+=count;
	left-=count;

	logoutput("read_private_dss_ASN1_libgcrypt: (private) integer len %i", len);

	if (gcry_mpi_scan(&dss->x, GCRYMPI_FMT_STD, data->pos, len, &count)==GPG_ERR_NO_ERROR) {

	    data->pos += count;
	    left -= count;

	} else {

	    goto error;

	}

    }

    return 0;

    error:

    _free_dss_private_key(dss);
    logoutput("read_private_dss_ASN1_libgcrypt: error reading private key");

    return -1;

}

    /* read private key ed25519 as stored by openssh which looks like:
	- string ssh-ed25519
	- string "q" (mpi-point)
	- string "d" (mpi)
    */

int read_private_ed25519_openssh_libgcrypt(struct ssh_key_s *key, unsigned int *error)
{
    struct common_buffer_s *data=&key->data;
    size_t left=(size_t) (data->ptr + data->size - data->pos);
    struct _ecc_private_key_s *ecc=(struct _ecc_private_key_s *) key->ptr;
    unsigned int len=0;

    if (! ecc) {

	ecc=malloc(sizeof(struct _ecc_private_key_s));

	if (ecc) {

	    memset(ecc, 0, sizeof(struct _ecc_private_key_s));
	    _init_ecc_private_key(ecc);

	    key->ptr=(void *) ecc;
	    key->free_ptr=free_ecc_private_key;

	} else {

	    logoutput_warning("read_private_ed25519_openssh_libgcrypt: unable to allocate memory");
	    *error=ENOMEM;
	    return -1;

	}

    }

    /* type check */

    if (left>4) {

	len=get_uint32(data->pos);
	data->pos+=4;
	left-=4;

	if (len<left) {

	    if (get_pubkey_type(data->pos, len)!=_PUBKEY_METHOD_SSH_ED25519) {
		char string[len+1];

		memcpy(string, data->pos, len);
		string[len]='\0';

		logoutput("read_private_ed25519_openssh_libgcrypt: error type %s mismatch", string);
		goto error;

	    }

	    data->pos+=len;
	    left-=len;

	} else {

	    logoutput("read_private_ed25519_openssh_libgcrypt: error not enough data");
	    goto error;

	}

    } else {

	logoutput("read_private_ed25519_openssh_libgcrypt: error not enough data");
	goto error;

    }

    /* string q mpi-point
	(same value as q in public key)*/

    if (left>4) {

	len=get_uint32(data->pos);
	data->pos+=4;
	left-=4;

	if (len<left) {
	    char *buffer=NULL;

	    buffer=malloc(len+1);

	    if (! buffer) {

		logoutput("read_private_ed25519_openssh_libgcrypt: error allocating memory");
		goto error;

	    }

	    buffer[0]=0x40;
	    memcpy(&buffer[1], data->pos, len);
	    ecc->q=gcry_mpi_set_opaque(NULL, buffer, 8 * (len+1));

	    data->pos+=len;
	    left-=len;

	} else {

	    logoutput("read_private_ed25519_openssh_libgcrypt: error not enough data");
	    goto error;

	}

    } else {

	logoutput("read_private_ed25519_openssh_libgcrypt: error not enough data");
	goto error;

    }

    /* string p mpi
	the actual private key */

    if (left>4) {

	len=get_uint32(data->pos);
	data->pos+=4;
	left-=4;

	if (len<left) {

	    if (len==32 || len==64) {
		char *buffer=NULL;

		buffer=malloc(32);

		if (! buffer) {

		    logoutput("read_private_ed25519_openssh_libgcrypt: error allocating memory");
		    goto error;

		}

		memcpy(buffer, data->pos, 32); /* only take the first 32 bytes.. also if 64 bytes are available.. the last 32 bytes are the public key */
		ecc->d=gcry_mpi_set_opaque(NULL, buffer, 8 * 32);

	    } else {

		logoutput("read_private_ed25519_openssh_libgcrypt: error bad key (expecting 32 or 64 bytes, got %i)", len);
		goto error;

	    }

	} else {

	    logoutput("read_private_ed25519_openssh_libgcrypt: error not enough data");
	    goto error;

	}

    } else {

	logoutput("read_private_ed25519_openssh_libgcrypt: error not enough data");
	goto error;

    }

    return 0;

    error:

    logoutput("read_private_ed25519_openssh_libgcrypt: failed to read private key");
    _free_ecc_private_key(ecc);
    return -1;

}

    /*
	format is described in PROTOCOL.key

	byte[]		AUTH_MAGIC
	string		ciphername (none)
	string		kdfname (none)
	string		kdfoptions
	int		number of keys (1)
	string		publickey1
	string		encrypted privatekey1, padded

	uint32		checkint
	uint32		checkint
	string		privatekey1
	string		comment1
	char		1
	char		2
	char		3
	....
	char		padlen % 255*/

static int read_private_openssh_key_v1(struct ssh_key_s *key, unsigned int *error)
{
    struct common_buffer_s *data=&key->data;
    size_t left=(size_t) (data->ptr + data->size - data->pos);
    unsigned int len=0;

    /* ciphername */

    if (left > 4) {

	len=get_uint32(data->pos);
	data->pos+=4;
	left-=4;

    } else {

	goto error;

    }

    if (len<left) {

	if (len==4 && strcmp(data->pos, "none")==0) {

	    data->pos+=len;
	    left-=len;

	} else {
	    char string[len+1];

	    memcpy(string, data->pos, len);
	    string[len]='\0';

	    logoutput("read_private_openssh_key_v1: error not supported cipher %s", string);
	    goto error;

	}

    } else {

	logoutput("read_private_openssh_key_v1: error not enough data");
	goto error;

    }

    /* kdfname */

    if (left > 4) {

	len=get_uint32(data->pos);
	data->pos+=4;
	left-=4;

    } else {

	goto error;

    }

    if (len<left) {

	if (len==4 && strcmp(data->pos, "none")==0) {

	    data->pos+=len;
	    left-=len;

	} else {
	    char string[len+1];

	    memcpy(string, data->pos, len);
	    string[len]='\0';

	    logoutput("read_private_openssh_key_v1: error not supported kdf %s", string);
	    goto error;

	}

    } else {

	logoutput("read_private_openssh_key_v1: error not enough data");
	goto error;

    }

    /* kdfoptions */

    if (left > 4) {

	len=get_uint32(data->pos);
	data->pos+=4;
	left-=4;

    } else {

	goto error;

    }

    if (len<left) {

	if (len>0) {
	    char string[len+1];

	    memcpy(string, data->pos, len);
	    string[len]='\0';

	    logoutput("read_private_openssh_key_v1: error not supported kdfoptions %s", string);
	    goto error;

	}

    }

    /* number of keys */

    if (left>4) {

	len=get_uint32(data->pos);
	data->pos+=4;
	left-=4;

    } else {

	goto error;

    }

    if (len==0 || len>1) {

	logoutput("read_private_openssh_key_v1: error not supported number of keys %i", len);
	goto error;

    }

    /* public key 1*/

    if (left>4) {

	len=get_uint32(data->pos);
	data->pos+=4;
	left-=4;

    } else {

	goto error;

    }

    if (len<left) {

	/* public key not needed, only check the type */

	if (len>4) {
	    unsigned int tmp=get_uint32(data->pos);

	    if (!(get_pubkey_type(data->pos+4, tmp) & key->type)) {
		char string[tmp+1];

		memcpy(string, data->pos, tmp);
		string[tmp]='\0';

		logoutput("read_private_openssh_key_v1: error type %s mismatch", string);
		goto error;

	    }

	} else {

	    goto error;

	}

	data->pos+=len;
	left-=len;

    } else {

	goto error;

    }

    /* list of private keys, padded */

    if (left>8) {

	len=get_uint32(data->pos);
	data->pos+=4;
	left-=4;

	if (len!=left) {

	    logoutput("read_private_openssh_key_v1: error length padded list (%i) does not match remaining number of bytes (%i)", len, left);
	    goto error;

	}

	/* TODO: additional check len is multiple of the blocksize (default 8?)*/

    }

    /* two integers */

    if (left>8) {
	unsigned int testinteger=get_uint32(data->pos);

	data->pos+=4;
	left-=4;
	if (get_uint32(data->pos) != testinteger) {

	    logoutput("read_private_openssh_key_v1: error two integers do not match");
	    goto error;

	}

	data->pos+=4;
	left-=4;

    }

    /* the first private key */

    /* TODO: use a generic function to read the private key of any type
	remaining bytes: left*/

    if (key->type&_PUBKEY_METHOD_SSH_ED25519) {

	if (read_private_ed25519_openssh_libgcrypt(key, error)==0) {

	    logoutput("read_private_openssh_key_v1: private key read");

	} else {

	    logoutput("read_private_openssh_key_v1: failed to read private key");
	    goto error;

	}

    } else {

	logoutput("read_private_openssh_key_v1: key type %s not supported in combination with openssh key v1 format", get_pubkey_name(key->type));
	goto error;

    }

    return 0;

    error:

    return -1;

}

#define OPENSSH_KEY_V1				"openssh-key-v1"

int read_private_openssh_key(struct ssh_key_s *key, unsigned int *error)
{
    struct common_buffer_s *data=&key->data;
    size_t left=(size_t) (data->ptr + data->size - data->pos);
    unsigned int len=strlen(OPENSSH_KEY_V1);

    /*	for now (20170710) only openssh key v1 is supported
    */

    if (left>len && strncmp(data->pos, OPENSSH_KEY_V1, len)==0) {

	data->pos+=len;
	return read_private_openssh_key_v1(key, error);

    }

    *error=EINVAL;
    return -1;

}

int read_parameters_private_key(struct ssh_key_s *key, unsigned int *error)
{

    if (key->format==_PUBKEY_FORMAT_OPENSSH_KEY) {

	return read_private_openssh_key(key, error);

    } else if (key->format==_PUBKEY_FORMAT_DER) {

	if (key->type & _PUBKEY_METHOD_SSH_DSS) {

	    return read_private_dss_ASN1_libgcrypt(key, error);

	} else if (key->type & _PUBKEY_METHOD_SSH_RSA) {

	    return read_private_rsa_ASN1_libgcrypt(key, error);

	}

    }

    return -1;

}
