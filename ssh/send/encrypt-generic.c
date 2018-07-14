/*
  2016, 2017, 2018 Stef Bon <stefbon@gmail.com>

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

#include "logging.h"
#include "main.h"
#include "utils.h"

#include "ssh-common.h"
#include "ssh-utils.h"
#include "ssh-send.h"

#ifdef HAVE_LIBGCRYPT
#include "gcrypt.h"

struct encrypt_handle_s {
    gcry_cipher_hd_t		c_handle;
    unsigned int		c_algo;
    unsigned int		c_mode;
    gcry_mac_hd_t		m_handle;
    unsigned int		m_algo;
};

static int test_cipher_algo(const char *name)
{
    int result=-1;
    int algo=0;

    algo=gcry_cipher_map_name(name);
    if (algo>0 && gcry_cipher_algo_info(algo, GCRYCTL_TEST_ALGO, NULL, NULL)==0) result=0;

    return result;

}

static int get_cipher_param(const char *name, unsigned int *mode)
{
    unsigned int len=strlen(name);
    char *sep=NULL;
    char tmp[len+1];

    memset(tmp, '\0', len+1);
    memcpy(tmp, name, len);
    sep=memchr(tmp, '-', len);

    if (sep) {

	*sep='\0';

	if (mode) {

	    if (strcmp(sep+1, "cbc")==0) {

		*mode=GCRY_CIPHER_MODE_CBC;

	    } else if (strcmp(sep+1, "ctr")==0) {

		*mode=GCRY_CIPHER_MODE_CTR;

	    } else if (strcmp(sep+1, "ecb")==0) {

		*mode=GCRY_CIPHER_MODE_ECB;

	    }

	}

    }

    return gcry_cipher_map_name(tmp);

}

static int get_hmac_param(const char *name, unsigned int *maclen)
{
    int algo=0;
    unsigned int m=0;

    if (strcmp(name, "hmac-sha1")==0) {

	algo=GCRY_MAC_HMAC_SHA1;
	m=gcry_mac_get_algo_maclen(GCRY_MAC_HMAC_SHA1);

    } else if (strlen(name)>10 && strncmp(name, "hmac-sha1-", 10)==0) {

	m=atoi(name + 10);

	if (m>0 && (m % 8 == 0) && (m <= gcry_mac_get_algo_maclen(GCRY_MAC_HMAC_SHA1))) {

	    algo=GCRY_MAC_HMAC_SHA1;

	}

    } else if (strcmp(name, "hmac-md5")==0) {

	algo=GCRY_MAC_HMAC_MD5;
	m=gcry_mac_get_algo_maclen(GCRY_MAC_HMAC_MD5);

    } else if (strncmp(name, "hmac-md5-", 9)==0) {

	m=atoi(name + 9);

	if (m>0 && (m % 8 == 0) && (m <= gcry_mac_get_algo_maclen(GCRY_MAC_HMAC_MD5))) {

	    algo=GCRY_MAC_HMAC_MD5;

	}

    } else if (strcmp(name, "hmac-sha256")==0) {

	algo=GCRY_MAC_HMAC_SHA256;
	m=gcry_mac_get_algo_maclen(GCRY_MAC_HMAC_SHA256);

    } else if (strcmp(name, "hmac-sha224")==0) {

	algo=GCRY_MAC_HMAC_SHA224;
	m=gcry_mac_get_algo_maclen(GCRY_MAC_HMAC_SHA224);

    } else if (strcmp(name, "hmac-sha512")==0) {

	algo=GCRY_MAC_HMAC_SHA512;
	m=gcry_mac_get_algo_maclen(GCRY_MAC_HMAC_SHA512);

    } else if (strcmp(name, "hmac-sha384")==0) {

	algo=GCRY_MAC_HMAC_SHA384;
	m=gcry_mac_get_algo_maclen(GCRY_MAC_HMAC_SHA384);

    } else {

	algo=gcry_mac_map_name(name);
	if (algo>0) m=gcry_mac_get_algo_maclen(algo);

    }

    if (maclen) *maclen=m;
    return algo;

}

static int test_hmac_algo(const char *name)
{
    int algo=0;
    int result=-1;

    algo=get_hmac_param(name, NULL);
    if (algo>0 && gcry_mac_test_algo(algo)==0) result=0;

    return result;
}

static unsigned int populate_cipher(struct ssh_session_s *session, struct encrypt_ops_s *ops, struct algo_list_s *alist, unsigned int start)
{

    if (alist) {

	alist[start].type=SSH_ALGO_TYPE_CIPHER_C2S;
	alist[start].order=SSH_ALGO_ORDER_LOW;
	alist[start].sshname="none";
	alist[start].libname="none";
	alist[start].ptr=(void *)ops;

    }

    start++;

    if (test_cipher_algo("3des")==0) {

	if (alist) {

	    alist[start].type=SSH_ALGO_TYPE_CIPHER_C2S;
	    alist[start].order=SSH_ALGO_ORDER_MEDIUM;
	    alist[start].sshname="3des-cbc";
	    alist[start].libname="3des";
	    alist[start].ptr=(void *)ops;

	}

	start++;

    }

    if (test_cipher_algo("aes128")==0) {

	if (alist) {

	    alist[start].type=SSH_ALGO_TYPE_CIPHER_C2S;
	    alist[start].order=SSH_ALGO_ORDER_MEDIUM;
	    alist[start].sshname="aes128-cbc";
	    alist[start].libname="aes128";
	    alist[start].ptr=(void *)ops;

	    alist[start+1].type=SSH_ALGO_TYPE_CIPHER_C2S;
	    alist[start].order=SSH_ALGO_ORDER_MEDIUM;
	    alist[start+1].sshname="aes128-ctr";
	    alist[start+1].libname="aes128";
	    alist[start+1].ptr=(void *)ops;

	}

	start+=2;

    }

    if (test_cipher_algo("aes192")==0) {

	if (alist) {

	    alist[start].type=SSH_ALGO_TYPE_CIPHER_C2S;
	    alist[start].order=SSH_ALGO_ORDER_MEDIUM;
	    alist[start].sshname="aes192-cbc";
	    alist[start].libname="aes192";
	    alist[start].ptr=(void *)ops;

	    alist[start+1].type=SSH_ALGO_TYPE_CIPHER_C2S;
	    alist[start].order=SSH_ALGO_ORDER_MEDIUM;
	    alist[start+1].sshname="aes192-ctr";
	    alist[start+1].libname="aes192";
	    alist[start+1].ptr=(void *)ops;

	}

	start+=2;

    }

    if (test_cipher_algo("aes256")==0) {

	if (alist) {

	    alist[start].type=SSH_ALGO_TYPE_CIPHER_C2S;
	    alist[start].order=SSH_ALGO_ORDER_MEDIUM;
	    alist[start].sshname="aes256-cbc";
	    alist[start].libname="aes256";
	    alist[start].ptr=(void *)ops;

	    alist[start+1].type=SSH_ALGO_TYPE_CIPHER_C2S;
	    alist[start].order=SSH_ALGO_ORDER_MEDIUM;
	    alist[start+1].sshname="aes256-ctr";
	    alist[start+1].libname="aes256";
	    alist[start+1].ptr=(void *)ops;

	}

	start+=2;

    }

    return start;

}

static unsigned int populate_hmac(struct ssh_session_s *session, struct encrypt_ops_s *ops, struct algo_list_s *alist, unsigned int start)
{

    if (alist) {

	alist[start].type=SSH_ALGO_TYPE_HMAC_C2S;
	alist[start].order=SSH_ALGO_ORDER_LOW;
	alist[start].sshname="none";
	alist[start].libname="none";
	alist[start].ptr=(void *)ops;

    }

    start++;

    if (test_hmac_algo("hmac-sha1")==0) {

	if (alist) {

	    alist[start].type=SSH_ALGO_TYPE_HMAC_C2S;
	    alist[start].order=SSH_ALGO_ORDER_MEDIUM;
	    alist[start].sshname="hmac-sha1";
	    alist[start].libname="hmac-sha1";
	    alist[start].ptr=(void *)ops;

	}

	start++;

    }

    if (test_hmac_algo("hmac-sha256")==0) {

	if (alist) {

	    alist[start].type=SSH_ALGO_TYPE_HMAC_C2S;
	    alist[start].order=SSH_ALGO_ORDER_MEDIUM;
	    alist[start].sshname="hmac-sha256";
	    alist[start].libname="hmac-sha256";
	    alist[start].ptr=(void *)ops;

	}

	start++;

    }

    if (test_hmac_algo("hmac-md5")==0) {

	if (alist) {

	    alist[start].type=SSH_ALGO_TYPE_HMAC_C2S;
	    alist[start].order=SSH_ALGO_ORDER_MEDIUM;
	    alist[start].sshname="hmac-md5";
	    alist[start].libname="hmac-md5";
	    alist[start].ptr=(void *)ops;

	}

	start++;

    }

    return start;

}

static unsigned int get_handle_size(struct ssh_encrypt_s *e)
{
    return sizeof(struct encrypt_handle_s);
}

static void clear_cipher_generic(struct encrypt_handle_s *cipher)
{

    if (cipher->c_handle) {

	gcry_cipher_close(cipher->c_handle);
	cipher->c_handle=NULL;

    }

    if (cipher->m_handle) {

	gcry_mac_close(cipher->m_handle);
	cipher->m_handle=NULL;

    }

}

static int write_hmac_none(struct ssh_encryptor_s *encryptor, struct ssh_packet_s *packet)
{
    return 0;
}

static int write_hmac_pre(struct ssh_encryptor_s *e, struct ssh_packet_s *packet)
{
    struct encrypt_handle_s *cipher=(struct encrypt_handle_s *) e->buffer;
    char tmp[4];

    memset(tmp, '\0', 4);
    store_uint32(tmp, packet->sequence);

    gcry_mac_write(cipher->m_handle, (void *)&tmp[0], 4);
    gcry_mac_write(cipher->m_handle, (void *)packet->buffer, packet->len);

    return 0;
}

static int encrypt_packet_none(struct ssh_encryptor_s *encryptor, struct ssh_packet_s *packet)
{
    return 0;
}

static int encrypt_packet(struct ssh_encryptor_s *e, struct ssh_packet_s *packet)
{
    struct encrypt_handle_s *cipher=(struct encrypt_handle_s *) e->buffer;
    gcry_error_t result=0;

    result=gcry_cipher_encrypt(cipher->c_handle, packet->buffer, packet->len, NULL, 0);
    if (result==GPG_ERR_NO_ERROR) return 0;

    logoutput("encrypt_packet: error %s/%s", gcry_strsource(result), gcry_strerror(result));
    return -1;

}

static int write_hmac_post(struct ssh_encryptor_s *e, struct ssh_packet_s *packet)
{
    struct encrypt_handle_s *cipher=(struct encrypt_handle_s *) e->buffer;
    size_t maclen=e->hmac_maclen;
    gcry_error_t result=0;

    result=gcry_mac_read(cipher->m_handle, (void *) (packet->buffer + packet->len), &maclen);
    if (result==0) return 0;

    logoutput("copy_hmac_out: error %s/%s", gcry_strsource(result), gcry_strerror(result));
    return -1;
}

/* default padding; see https://tools.ietf.org/html/rfc4253#section-6:
    "padding, such that the total length of (packet_length || padding_length || payload || random pading)
    is a multiple of the cipher block size or 8, whichever is larger. There MUST be at least four bytes of padding." */

static unsigned char get_message_padding(struct ssh_encryptor_s *encryptor, unsigned int len)
{
    unsigned int mod=0;
    unsigned char padding=0;

    mod=len % encryptor->cipher_blocksize;
    padding =  (unsigned char) (encryptor->cipher_blocksize - mod);

    if ( padding < 4) {

	/* the remainder is too less (< 4): add an extra block */

	padding+=encryptor->cipher_blocksize;

    }

    return padding;
}

static void clear_encryptor(struct ssh_encryptor_s *e)
{
    struct encrypt_handle_s *cipher=(struct encrypt_handle_s *) e->buffer;
    clear_cipher_generic(cipher);
    memset(e->buffer, 0, e->size);
}

static int init_encryptor(struct ssh_encryptor_s *encryptor)
{
    struct ssh_encrypt_s *encrypt=encryptor->encrypt;
    struct encrypt_handle_s *cipher=(struct encrypt_handle_s *) encryptor->buffer;

    logoutput("init_encryptor: %s / %s", encrypt->ciphername, encrypt->hmacname);

    cipher->c_handle=NULL;
    cipher->c_algo=0;
    cipher->c_mode=0;
    cipher->m_handle=NULL;
    cipher->m_algo=0;

    if (strcmp(encrypt->ciphername, "none") == 0) {

	encryptor->cipher_blocksize=8;
	encryptor->encrypt_packet=encrypt_packet_none;

    } else {
	struct ssh_string_s *cipher_key=&encrypt->cipher_key;
	struct ssh_string_s *cipher_iv=&encrypt->cipher_iv;
	gcry_error_t result=0;
	int c_algo=0;
	unsigned int c_mode=0;

	c_algo=get_cipher_param(encrypt->ciphername, &c_mode);
	if (c_algo==0 || c_mode==0) goto error;
	cipher->c_algo=c_algo;
	cipher->c_mode=c_mode;

	result=gcry_cipher_open(&cipher->c_handle, cipher->c_algo, cipher->c_mode, 0);

	if (result) {

	    logoutput("init_encryptor: open cipher error %s/%s", gcry_strsource(result), gcry_strerror(result));
	    goto error;

	}

	result=gcry_cipher_setkey(cipher->c_handle, cipher_key->ptr, cipher_key->len);

	if (result) {

	    logoutput("init_encryptor: set key cipher error %s/%s", gcry_strsource(result), gcry_strerror(result));
	    goto error;

	}

	result=gcry_cipher_setiv(cipher->c_handle, cipher_iv->ptr, cipher_iv->len);

	if (result) {

	    logoutput("init_encryptor: set iv cipher error %s/%s", gcry_strsource(result), gcry_strerror(result));
	    goto error;

	}

	encryptor->cipher_blocksize=gcry_cipher_get_algo_blklen(c_algo);
	encryptor->encrypt_packet=encrypt_packet;

    }

    if (strcmp(encrypt->hmacname, "none")==0) {

	encryptor->hmac_maclen=0;
	encryptor->write_hmac_pre=write_hmac_none;
	encryptor->write_hmac_post=write_hmac_none;

    } else {
	struct ssh_string_s *hmac_key=&encrypt->hmac_key;
	int m_algo=0;
	unsigned int m_maclen=0;
	gcry_error_t result=0;

	m_algo=get_hmac_param(encrypt->hmacname, &m_maclen);
	if (m_algo==0) goto error;

	cipher->m_algo=m_algo;

	result=gcry_mac_open(&cipher->m_handle, cipher->m_algo, 0, NULL);

	if (result) {

	    logoutput("init_encryptor: open mac error %s/%s", gcry_strsource(result), gcry_strerror(result));
	    goto error;

	}

	result=gcry_mac_setkey(cipher->m_handle, hmac_key->ptr, hmac_key->len);

	if (result) {

	    logoutput("init_encryptor: set key mac error %s/%s", gcry_strsource(result), gcry_strerror(result));
	    goto error;

	}

	encryptor->hmac_maclen=m_maclen;
	encryptor->write_hmac_pre=write_hmac_pre;
	encryptor->write_hmac_post=write_hmac_post;

    }

    encryptor->get_message_padding=get_message_padding;
    encryptor->clear=clear_encryptor;

    return 0;

    error:

    clear_cipher_generic(cipher);
    return -1;

}

static unsigned int get_cipher_blocksize(const char *name)
{

    if (strcmp(name, "none")==0) {

	return 0;

    } else {
	int algo=get_cipher_param(name, NULL);

	return (algo>0) ? gcry_cipher_get_algo_blklen(algo) : 0;

    }

}

static unsigned int get_cipher_keysize(const char *name)
{

    if (strcmp(name, "none")==0) {

	return 0;

    } else {
	int algo=get_cipher_param(name, NULL);

	return (algo>0) ? gcry_cipher_get_algo_keylen(algo) : 0;

    }

}

static unsigned int get_cipher_ivsize(const char *name)
{
    return get_cipher_blocksize(name);
}

static unsigned int get_hmac_keysize(const char *name)
{

    if (strcmp(name, "none")==0) {

	return 0;

    } else {
	int algo=get_hmac_param(name, NULL);

	return (algo>0) ? gcry_mac_get_algo_keylen(algo) : 0;

    }

    return 0;
}

static unsigned int get_encrypt_flag(const char *ciphername, const char *hmacname, const char *what)
{

    if (strcmp(what, "parallel")==0) {

	if (strcmp(ciphername, "none")==0) {

	    return 1; /* of course no encryption is parallel */

	} else {
	    int c_algo=0;
	    unsigned int mode=0;

	    c_algo=get_cipher_param(ciphername, &mode);
	    if (c_algo>0 && mode==GCRY_CIPHER_MODE_CTR) return 1; /* if ctr mode then parallel; more ciphers/mode are possible here?? */

	}

    }

    return 0;

}

#else

static unsigned int populate_cipher(struct ssh_session_s *session, struct encrypt_ops_s *ops, struct algo_list_s *list, unsigned int start, unsigned int count)
{
    return 0;
}
static unsigned int populate_hmac(struct ssh_session_s *session, struct encrypt_ops_s *ops, struct algo_list_s *list, unsigned int start, unsigned int count)
{
    return 0;
}
static unsigned int get_handle_size(struct ssh_encrypt_s *e)
{
    return 0;
}

static int init_encryptor(struct ssh_encryptor_s *encryptor)
{
    return -1;
}

static unsigned int get_cipher_blocksize(const char *name)
{
    return 0;
}

static unsigned int get_cipher_keysize(const char *name)
{
    return 0;
}

static unsigned int get_cipher_ivsize(const char *name)
{
    return 0;
}

static unsigned int get_hmac_keysize(const char *name)
{
    return 0;
}

static unsigned int get_encrypt_flag(const char *ciphername, const char *hmacname, const char *what)
{
    return 0;
}

#endif

static struct encrypt_ops_s generic_e_ops = {
    .name			= "generic",
    .populate_cipher		= populate_cipher,
    .populate_hmac		= populate_hmac,
    .get_handle_size		= get_handle_size,
    .init_encryptor		= init_encryptor,
    .get_cipher_blocksize	= get_cipher_blocksize,
    .get_cipher_keysize		= get_cipher_keysize,
    .get_cipher_ivsize		= get_cipher_ivsize,
    .get_hmac_keysize		= get_hmac_keysize,
    .get_encrypt_flag		= get_encrypt_flag,
    .list			= {NULL, NULL},
};

void init_encrypt_generic()
{
    add_encrypt_ops(&generic_e_ops);
}

void set_encrypt_generic(struct ssh_encrypt_s *encrypt)
{
    encrypt->ops=&generic_e_ops;
}
