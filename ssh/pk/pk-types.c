/*
  2010, 2011, 2012, 2103, 2014, 2015, 2016, 2017, 2018 Stef Bon <stefbon@gmail.com>

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
#include <ctype.h>
#include <inttypes.h>

#include <sys/param.h>
#include <sys/types.h>

#include "logging.h"
#include "main.h"
#include "utils.h"

#include "ssh-common.h"
#include "ssh-utils.h"
#include "pk-types.h"

/*	flags					name			id pkalgo			hash
					(if NULL name from pkalgo) 						*/

static struct ssh_pksign_s available_signs[] = {

    /* RSA: default sha1, and sha256 and sha512 possible */

    {.flags				=	SSH_PKSIGN_FLAG_DEFAULT,
     .name				=	NULL,
     .keyid 				=	SSH_PKALGO_ID_RSA,
     .hash 				=	SSH_ALGO_HASH_SHA1_160},

    {.flags				=	SSH_PKSIGN_FLAG_RECOMMENDED,
     .name 				=	"rsa-sha2-256",
     .keyid				=	SSH_PKALGO_ID_RSA,
     .hash 				=	SSH_ALGO_HASH_SHA2_256},

    {.flags				=	SSH_PKSIGN_FLAG_OPTIONAL,
     .name				=	"rsa-sha2-512",
     .keyid				=	SSH_PKALGO_ID_RSA,
     .hash				=	SSH_ALGO_HASH_SHA2_512},

    /* DSS: default sha1, no others possible */

    {.flags				=	SSH_PKSIGN_FLAG_DEFAULT,
     .name				=	NULL,
     .keyid				=	SSH_PKALGO_ID_DSS,
     .hash				=	SSH_ALGO_HASH_SHA1_160},

    /* ED25519: default sha512, no others possible */

    {.flags				=	SSH_PKSIGN_FLAG_DEFAULT,
     .name				=	NULL,
     .keyid				=	SSH_PKALGO_ID_ED25519,
     .hash				=	SSH_ALGO_HASH_SHA2_512},

    /* CURVE25519: default sha512, no others possible */

    {.flags				=	SSH_PKSIGN_FLAG_DEFAULT,
     .name				=	NULL,
     .keyid				=	SSH_PKALGO_ID_CURVE25519,
     .hash				=	SSH_ALGO_HASH_SHA2_512},

    {.flags				=	0,
     .name				=	NULL,
     .keyid				=	0,
     .hash				=	0},
};

static struct ssh_pkalgo_s available_algos[] = {

    {.flags				=	SSH_PKALGO_FLAG_SYSTEM,
     .scheme				=	SSH_PKALGO_SCHEME_RSA,
     .id				=	SSH_PKALGO_ID_RSA,
     .name				=	"ssh-rsa",
     .libname				=	"rsa",
     .len				=	7},

    {.flags				=	SSH_PKALGO_FLAG_SYSTEM,
     .scheme				=	SSH_PKALGO_SCHEME_DSS,
     .id				=	SSH_PKALGO_ID_DSS,
     .name				=	"ssh-dss",
     .libname				=	"dsa",
     .len				=	7},

    {.flags				=	SSH_PKALGO_FLAG_SYSTEM | SSH_PKALGO_FLAG_PREFERRED,
     .scheme				=	SSH_PKALGO_SCHEME_ECC,
     .id				=	SSH_PKALGO_ID_ED25519,
     .name				=	"ssh-ed25519",
     .libname				=	"ed25519",
     .len				=	11},

    {.flags				=	SSH_PKALGO_FLAG_SYSTEM | SSH_PKALGO_FLAG_SKIP,
     .scheme				=	SSH_PKALGO_SCHEME_ECC,
     .id				=	SSH_PKALGO_ID_CURVE25519,
     .name				=	"curve25519",
     .libname				=	"curve25519",
     .len				=	10},

    {.flags				=	0,
     .scheme				=	0,
     .id				=	0,
     .name				=	NULL,
     .libname				=	NULL,
     .len				=	0},
};

static struct ssh_pkcert_s available_certs[] = {

    {.flags				=	SSH_PKCERT_FLAG_SYSTEM | SSH_PKCERT_FLAG_OPENSSH_COM_CERTIFICATE,
     .id				=	SSH_PKCERT_ID_RSA_CERT_V01_OPENSSH_COM,
     .pkalgo_id				=	SSH_PKALGO_ID_RSA,
     .name				=	"ssh-rsa-cert-v01@openssh.com",
     .libname				=	NULL,
     .len				=	28},

    {.flags				=	SSH_PKCERT_FLAG_SYSTEM | SSH_PKCERT_FLAG_OPENSSH_COM_CERTIFICATE,
     .id				=	SSH_PKCERT_ID_DSS_CERT_V01_OPENSSH_COM,
     .pkalgo_id				=	SSH_PKALGO_ID_DSS,
     .name				=	"ssh-dss-cert-v01@openssh.com",
     .libname				=	NULL,
     .len				=	28},

    {.flags				=	SSH_PKCERT_FLAG_SYSTEM | SSH_PKCERT_FLAG_OPENSSH_COM_CERTIFICATE,
     .id				=	SSH_PKCERT_ID_ED25519_CERT_V01_OPENSSH_COM,
     .pkalgo_id				=	SSH_PKALGO_ID_ED25519,
     .name				=	"ssh-ed25519-cert-v01@openssh.com",
     .libname				=	NULL,
     .len				=	32},

    {.flags				=	0,
     .id				=	0,
     .pkalgo_id				=	0,
     .name				=	NULL,
     .libname				=	NULL,
     .len				=	0},
};

void copy_pkalgo(struct ssh_pkalgo_s *a, struct ssh_pkalgo_s *b)
{
    /* do not copy the system flag */
    a->flags				=	(b->flags & SSH_PKALGO_FLAG_SYSTEM ) ? (b->flags - SSH_PKALGO_FLAG_SYSTEM) : b->flags;
    a->scheme				=	b->scheme;
    a->id				=	b->id;
    a->name				=	b->name;
    a->libname				=	b->libname;
    a->len				=	b->len;
}

void set_pkoptions(struct ssh_pkoptions_s *options, struct ssh_pkalgo_s *pkalgo, unsigned int o)
{

    if (pkalgo->scheme==SSH_PKALGO_SCHEME_RSA) {

	o &= ( SSH_PKALGO_OPTION_RSA_BITS_1024 | SSH_PKALGO_OPTION_RSA_BITS_2048);
	if (o>0) options->options |= o;

    } else if (pkalgo->scheme==SSH_PKALGO_SCHEME_DSS) {

	o &= ( SSH_PKALGO_OPTION_DSS_BITS_1024 | SSH_PKALGO_OPTION_DSS_BITS_2048);
	if (o>0) options->options |= o;

    } else if (pkalgo->scheme==SSH_PKALGO_SCHEME_ECC) {

	o = 0; /* no extra options for ECC for now 20180711 SB */
	if (o>0) options->options |= o;

    } else {

	logoutput("set_pkoptions: setting option for %i/%s not supported", pkalgo->id, pkalgo->name);

    }

}

struct ssh_pkalgo_s *get_pkalgo(char *name, unsigned int len, int *index)
{
    unsigned int i=0;
    struct ssh_pkalgo_s *pkalgo=NULL;

    while (available_algos[i].id>0) {

	if (available_algos[i].len==len && strncmp(available_algos[i].name, name, len)==0) {

	    pkalgo=&available_algos[i];
	    if (index) *index=(int) i;
	    break;

	}

	i++;

    }

    return pkalgo;

}

struct ssh_pkalgo_s *get_pkalgo_string(struct ssh_string_s *s, int *index)
{
    return get_pkalgo(s->ptr, s->len, index);
}

struct ssh_pkalgo_s *get_pkalgo_byid(unsigned int id, int *index)
{
    unsigned int i=0;
    struct ssh_pkalgo_s *pkalgo=NULL;

    while (available_algos[i].id>0) {

	if (available_algos[i].id==id) {

	    pkalgo=&available_algos[i];
	    if (index) *index=(int) i;
	    break;

	}

	i++;

    }

    return pkalgo;

}

struct ssh_pkcert_s *get_pkcert(char *name, unsigned int len, int *index)
{
    unsigned int i=0;
    struct ssh_pkcert_s *pkcert=NULL;

    while (available_certs[i].id>0) {

	if (available_certs[i].len==len && strncmp(available_certs[i].name, name, len)==0) {

	    pkcert=&available_certs[i];
	    if (index) *index=(int) i;
	    break;

	}

	i++;

    }

    return pkcert;

}

struct ssh_pkcert_s *get_pkcert_string(struct ssh_string_s *s, int *index)
{
    return get_pkcert(s->ptr, s->len, index);
}

struct ssh_pkcert_s *get_pkcert_byid(unsigned int id, int *index)
{
    unsigned int i=0;
    struct ssh_pkcert_s *pkcert=NULL;

    while (available_certs[i].id>0) {

	if (available_certs[i].id==id) {

	    pkcert=&available_certs[i];
	    if (index) *index=(int) i;
	    break;

	}

	i++;

    }

    return pkcert;

}

struct ssh_pkalgo_s *get_next_pkalgo(struct ssh_pkalgo_s *algo, int *index)
{
    int i=-1;

    if (index && *index>=0) {

	i=*index + 1;

    } else if (algo==NULL) {

	i=0;

    } else {

	/* is it a system algo? only system algo's do have next ones */

	if ((algo->flags & SSH_PKALGO_FLAG_SYSTEM)==0) algo=get_pkalgo_byid(algo->id, NULL);

	if ((char *) algo >= (char *) available_algos) {

	    /* calculate the array index */
	    i = ((char *) algo - (char *) available_algos) / sizeof(struct ssh_pkalgo_s) + 1;

	}

    }

    if (i>=0 && i < (sizeof(available_algos) / sizeof(struct ssh_pkalgo_s)) && available_algos[i].id>0) {

	if (index) *index=i;
	return &available_algos[i];

    }

    if (index) *index=-1;
    return NULL;

}

int get_index_pkalgo(struct ssh_pkalgo_s *algo)
{
    int i=-1;

    if ((algo->flags & SSH_PKALGO_FLAG_SYSTEM)==0) {

	algo=get_pkalgo_byid(algo->id, NULL);
	if (algo==NULL) goto out;

    }

    if ((char *) algo >= (char *) available_algos) {

	i = ((char *) algo - (char *) available_algos) / sizeof(struct ssh_pkalgo_s);
	if (i>=0 && i < (sizeof(available_algos) / sizeof(struct ssh_pkalgo_s)) && available_algos[i].id>0) return i;

    }

    out:

    return -1;

}

struct ssh_pkcert_s *get_next_pkcert(struct ssh_pkcert_s *cert, int *index)
{
    int i=-1;

    if (index && *index>=0) {

	i=*index + 1;

    } else if (cert==NULL) {

	i=0;

    } else {

	/* is it a system algo? only system algo's do have next ones */

	if ((cert->flags & SSH_PKCERT_FLAG_SYSTEM)==0) cert=get_pkcert_byid(cert->id, NULL);

	if ((char *) cert >= (char *) available_certs) {

	    /* calculate the array index */
	    i = ((char *) cert - (char *) available_certs) / sizeof(struct ssh_pkcert_s) + 1;

	}

    }

    if (i>=0 && i < (sizeof(available_certs) / sizeof(struct ssh_pkcert_s)) && available_certs[i].id>0) {

	if (index) *index=i;
	return &available_certs[i];

    }

    if (index) *index=-1;
    return NULL;

}

int get_index_pkcert(struct ssh_pkcert_s *cert)
{
    int i=-1;

    if ((cert->flags & SSH_PKCERT_FLAG_SYSTEM)==0) {

	cert=get_pkcert_byid(cert->id, NULL);
	if (cert==NULL) goto out;

    }

    if ((char *) cert >= (char *) available_certs) {

	i = ((char *) cert - (char *) available_certs) / sizeof(struct ssh_pkcert_s);
	if (i>=0 && i < (sizeof(available_certs) / sizeof(struct ssh_pkcert_s)) && available_certs[i].id>0) return i;

    }

    out:

    return -1;

}

unsigned int write_pkalgo(char *buffer, struct ssh_pkalgo_s *pkalgo)
{

    if (buffer) {

	store_uint32(buffer, pkalgo->len);
	memcpy(buffer + 4, pkalgo->name, pkalgo->len);

    }

    return (pkalgo->len + 4);

}

void msg_write_pkalgo(struct msg_buffer_s *mb, struct ssh_pkalgo_s *pkalgo)
{
    (* mb->write_ssh_string)(mb, 'c', (void *) pkalgo->name);
}

void msg_write_pkcert(struct msg_buffer_s *mb, struct ssh_pkcert_s *pkcert)
{
    (* mb->write_ssh_string)(mb, 'c', (void *) pkcert->name);
}

struct ssh_pkalgo_s *read_pkalgo(char *buffer, unsigned int size, int *read)
{

    if (read) *read=0;

    if (size>4) {
	unsigned int len=get_uint32(buffer);

	if (read) *read+=4;

	if (len + 4 <= size) {

	    if (read) *read+=len;
	    return get_pkalgo(buffer + 4, len, NULL);

	}

    }

    return NULL;
}

struct ssh_pkalgo_s *read_pkalgo_string(struct ssh_string_s *name, int *read)
{
    struct ssh_pkalgo_s *pkalgo=NULL;

    if (read) *read=0;
    pkalgo=get_pkalgo(name->ptr, name->len, NULL);
    if (read) *read=get_ssh_string_length(name, SSH_STRING_FLAG_HEADER | SSH_STRING_FLAG_DATA);

    return pkalgo;

}

struct ssh_pkcert_s *read_pkcert(char *buffer, unsigned int size, int *read)
{

    if (read) *read=0;

    if (size>4) {
	unsigned int len=get_uint32(buffer);

	if (read) *read+=4;

	if (len + 4 <= size) {

	    if (read) *read+=len;
	    return get_pkcert(buffer + 4, len, NULL);

	}

    }

    return NULL;
}

struct ssh_pkcert_s *read_pkcert_string(struct ssh_string_s *name, int *read)
{
    struct ssh_pkcert_s *pkcert=NULL;

    if (read) *read=0;
    pkcert=get_pkcert(name->ptr, name->len, NULL);
    if (read) *read=get_ssh_string_length(name, SSH_STRING_FLAG_HEADER | SSH_STRING_FLAG_DATA);

    return pkcert;

}

struct ssh_pksign_s *get_next_pksign(struct ssh_pkalgo_s *pkalgo, struct ssh_pksign_s *pksign, int *index)
{
    int i=-1;

    if (index && *index>=0) {

	i=*index+1;

    } else if (pksign==NULL) {

	i=0;

    } else if ((char *) pksign >= (char *) available_signs) {

	i=((char *) pksign - (char *) available_signs) / sizeof(struct ssh_pksign_s) + 1;

    }

    pksign=NULL;

    if (i>=0 && i < (sizeof(available_signs) / sizeof(struct ssh_pksign_s)) && available_signs[i].keyid>0) {

	if (pkalgo) {

	    while (available_signs[i].keyid>0) {

		if (available_signs[i].keyid==pkalgo->id) {

		    if (index) *index=i;
		    return &available_signs[i];
		    break;

		}

		i++;

	    }

	} else {

	    if (index) *index=i;
	    return &available_signs[i];

	}

    }

    if (index) *index=-1;
    return NULL;

}

int get_index_pksign(struct ssh_pksign_s *pksign)
{
    int i=-1;

    if ((char *) pksign >= (char *) available_signs) {

	i=((char *) pksign - (char *) available_signs) / sizeof(struct ssh_pksign_s);
	if (i>0 && i < (sizeof(available_signs) / sizeof(struct ssh_pksign_s)) && available_signs[i].keyid>0) return i;

    }

    return -1;
}


/* walk every pksign to find the default one */

struct ssh_pksign_s *get_default_pksign(struct ssh_pkalgo_s *pkalgo)
{
    struct ssh_pksign_s *pksign=NULL;

    pksign=get_next_pksign(pkalgo, pksign, NULL);

    while (pksign) {

	if (pksign->flags & SSH_PKSIGN_FLAG_DEFAULT) break;
	pksign=get_next_pksign(pkalgo, pksign, NULL);

    }

    return pksign;

}

static int select_cb_dummy(void *ptr, char *pkalgo, char *signalgo)
{
    return 0;
}

struct ssh_pksign_s *check_signature_algo(struct ssh_pkalgo_s *pkalgo, struct ssh_string_s *signalgo,
						int (* select_cb)(void *ptr, char *pkalgo, char *signalgo), void *ptr)
{
    struct ssh_pksign_s *pksign=NULL;

    if (select_cb==NULL) select_cb=select_cb_dummy;

    pksign=get_next_pksign(pkalgo, pksign, NULL);

    while (pksign) {
	const char *name=(pksign->name) ? pksign->name : pkalgo->name;

	/* look at the non default pk sign's, the default is always supported */

	if ((pksign->flags & SSH_PKSIGN_FLAG_DEFAULT)==0) {

	    if (select_cb(ptr, pkalgo->name, name)==-1) goto next;

	}

	if (strlen(name)==signalgo->len && strncmp(name, signalgo->ptr, signalgo->len)==0) break;

	next:
	pksign=get_next_pksign(pkalgo, pksign, NULL);

    }

    if (pksign==NULL) {

	logoutput_info("check_signature_algo: fatal error: pk sign %.*s not supported", signalgo->len, signalgo->ptr);

    } else {

	logoutput_info("check_signature_algo: found pk sign %.*s using hash %s", signalgo->len, signalgo->ptr, get_hashname_sign(pksign));

    }

    return pksign;

}


/* fallback to the algo name when sign name is not defined (see: https://tools.ietf.org/html/draft-ietf-curdle-rsa-sha2-12) */

void msg_write_pksign(struct msg_buffer_s *mb, struct ssh_pksign_s *pksign)
{

    if (pksign->name) {

	(* mb->write_ssh_string)(mb, 'c', (void *) pksign->name);

    } else {
	struct ssh_pkalgo_s *pkalgo = get_pkalgo_byid(pksign->keyid, NULL);

	(* mb->write_ssh_string)(mb, 'c', (void *) pkalgo->name);

    }

}

void msg_write_pksignature(struct msg_buffer_s *mb, struct ssh_pksign_s *pksign, struct ssh_string_s *signature)
{
    unsigned int pos=0;

    if (signature==NULL || signature->ptr==NULL) return;

    pos=(* mb->start_ssh_string)(mb);
    msg_write_pksign(mb, pksign);
    msg_write_ssh_string(mb, 's', (void *) signature);
    (* mb->complete_ssh_string)(mb, pos);

}

void msg_read_pksignature(struct msg_buffer_s *mb, struct ssh_string_s *pksign, struct ssh_string_s *signature)
{
    struct ssh_string_s tmp;

    init_ssh_string(&tmp);

    msg_read_ssh_string(mb, &tmp);

    // logoutput("msg_read_pksignature: len %i (ptr %s)", tmp.len, (tmp.ptr) ? "defined" : "notdefined");

    if (tmp.len>8) {
	struct msg_buffer_s mb_tmp=INIT_SSH_MSG_BUFFER;

	set_msg_buffer(&mb_tmp, tmp.ptr, tmp.len);
	msg_read_ssh_string(&mb_tmp, pksign);
	msg_read_ssh_string(&mb_tmp, signature);

	// logoutput("msg_read_pksignature: len pksignalgo %i", pksignalgo->len);
	// logoutput("msg_read_pksignature: len signature %i", signature->len);

    }

}

const char *get_hashname_sign(struct ssh_pksign_s *pksign)
{

    switch (pksign->hash) {

    case SSH_ALGO_HASH_SHA1_160:

	return "sha1";

    case SSH_ALGO_HASH_SHA2_256:

	return "sha256";

    case SSH_ALGO_HASH_SHA2_512:

	return "sha512";

    }

    return NULL;
}
