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
#include "ssh-receive.h"

#ifdef HAVE_LIBGCRYPT
#include "gcrypt.h"

#define POLY1305_TAGLEN			16
#define POLY1305_KEYLEN			32

#define CHACHA20_BLOCKSIZE		64
#define CHACHA20_KEYSIZE		32
#define CHACHA20_HEADERSIZE		4

struct decrypt_handle_s {
    gcry_cipher_hd_t		c_headerhandle;
    gcry_cipher_hd_t		c_packethandle;
    unsigned int		c_algo;
    unsigned int		c_mode;
    gcry_mac_hd_t		m_handle;
    unsigned int		m_algo;
};

static int test_cipher_algo(const char *name)
{
    int result=-1;

    if (strcmp(name, "chacha20-poly1305@openssh.com")==0) {
	int algo=0;

	algo=gcry_cipher_map_name("chacha20");
	if (algo>0 && gcry_cipher_algo_info(algo, GCRYCTL_TEST_ALGO, NULL, NULL)==0) result=0;

    }

    return result;

}

static int get_cipher_param(const char *name, unsigned int *mode)
{

    if (strcmp(name, "chacha20-poly1305@openssh.com")==0) {

	if (mode) *mode=GCRY_CIPHER_MODE_STREAM;
	return gcry_cipher_map_name("chacha20");

    }

    return 0;

}

static int test_hmac_algo(const char *name)
{
    int result=-1;

    if (strcmp(name, "chacha20-poly1305@openssh.com")==0) {
	int algo=0;

	algo=gcry_mac_map_name("poly1305");
	if (algo>0 && gcry_mac_test_algo(algo)==0) result=0;

    }

    return result;
}

static int get_hmac_param(const char *name, unsigned int *maclen)
{
    int algo=0;

    if (strcmp(name, "chacha20-poly1305@openssh.com")==0) {

	algo=GCRY_MAC_POLY1305;
	if (maclen) *maclen=POLY1305_TAGLEN;

    }

    return algo;

}

static unsigned int populate_cipher(struct ssh_session_s *session, struct decrypt_ops_s *ops, struct algo_list_s *alist, unsigned int start)
{

    if (test_cipher_algo("chacha20-poly1305@openssh.com")==0) {

	if (alist) {

	    alist[start].type=SSH_ALGO_TYPE_CIPHER_S2C;
	    alist[start].order=SSH_ALGO_ORDER_HIGH;
	    alist[start].sshname="chacha20-poly1305@openssh.com";
	    alist[start].libname="chacha20";
	    alist[start].ptr=(void *)ops;

	}

	start++;

    }

    return start;

}

static unsigned int populate_hmac(struct ssh_session_s *session, struct decrypt_ops_s *d_ops, struct algo_list_s *alist, unsigned int start)
{
    /* no hmac (cipher is hmac and decrypt at the same time) */
    return start;
}

static unsigned int get_handle_size(struct ssh_decrypt_s *d)
{
    return sizeof(struct decrypt_handle_s);
}

static void clear_cipher(struct decrypt_handle_s *cipher)
{

    if (cipher->c_headerhandle) {

	gcry_cipher_close(cipher->c_headerhandle);
	cipher->c_headerhandle=NULL;

    }

    if (cipher->c_packethandle) {

	gcry_cipher_close(cipher->c_packethandle);
	cipher->c_packethandle=NULL;

    }

    if (cipher->m_handle) { 

	gcry_mac_close(cipher->m_handle);
	cipher->m_handle=NULL;

    }

}

static int verify_hmac_pre(struct ssh_decryptor_s *d, struct ssh_packet_s *packet)
{
    struct decrypt_handle_s *cipher=(struct decrypt_handle_s *) d->buffer;
    gcry_error_t result;

    gcry_mac_write(cipher->m_handle, packet->buffer, packet->len + 4);
    result=gcry_mac_verify(cipher->m_handle, (void *)(packet->buffer + packet->len + 4), d->hmac_maclen);

    if (result==GPG_ERR_NO_ERROR) return 0;
    logoutput("verify_hmac_pre: error %s/%s", gcry_strsource(result), gcry_strerror(result));
    return -1;

}

static int decrypt_length(struct ssh_decryptor_s *d, struct ssh_packet_s *packet, char *buffer, unsigned int len)
{
    struct decrypt_handle_s *cipher=(struct decrypt_handle_s *) d->buffer;
    gcry_error_t result=0;
    char seqbuff[8];

    memset(seqbuff, '\0', 8);
    store_uint64(seqbuff, packet->sequence);

    gcry_cipher_setiv(cipher->c_headerhandle, (const void *)seqbuff, 8);
    gcry_cipher_setiv(cipher->c_packethandle, (const void *)seqbuff, 8);

    result=gcry_cipher_decrypt(cipher->c_headerhandle, (unsigned char *)buffer, (size_t) len, (unsigned char *)packet->buffer, (size_t) len);

    if (result==0) {
	unsigned char poly1305_key[CHACHA20_BLOCKSIZE];

	memset(poly1305_key, 0, CHACHA20_BLOCKSIZE);

	gcry_cipher_encrypt(cipher->c_packethandle, poly1305_key, CHACHA20_BLOCKSIZE, NULL, 0);
	gcry_mac_setkey(cipher->m_handle, poly1305_key, POLY1305_KEYLEN);

	packet->decrypted=len;
	return 0;

    }

    logoutput("decrypt_length: error %s/%s", gcry_strsource(result), gcry_strerror(result));
    return -1;

}

static int decrypt_packet(struct ssh_decryptor_s *d, struct ssh_packet_s *packet)
{
    struct decrypt_handle_s *cipher=(struct decrypt_handle_s *) d->buffer;
    gcry_error_t result=0;
    size_t len=(size_t) (packet->len - packet->decrypted);

    result=gcry_cipher_decrypt(cipher->c_packethandle, (unsigned char *)(packet->buffer + packet->decrypted), len, NULL, 0);

    if (result==0) {

	packet->decrypted+=len;
	return 0;

    }

    logoutput("decrypt_packet: error %s/%s", gcry_strsource(result), gcry_strerror(result));
    return -1;

}

static int verify_hmac_post(struct ssh_decryptor_s *d, struct ssh_packet_s *packet)
{
    return 0;
}

static void clear_decryptor(struct ssh_decryptor_s *d)
{
    struct decrypt_handle_s *cipher=(struct decrypt_handle_s *) d->buffer;
    clear_cipher(cipher);
    memset(d->buffer, 0, d->size);
}

static int init_decryptor(struct ssh_decryptor_s *decryptor)
{
    struct ssh_decrypt_s *decrypt=decryptor->decrypt;
    struct decrypt_handle_s *cipher=(struct decrypt_handle_s *) decryptor->buffer;
    gcry_error_t result=0;
    struct ssh_string_s *cipher_key=&decrypt->cipher_key;
    struct ssh_string_s *hmac_key=&decrypt->hmac_key;
    int c_algo=0;
    unsigned int c_mode=0;
    int m_algo=0;
    unsigned int m_maclen=0;

    logoutput("init_decryptor (chacha20-poly1305@openssh.com) %s:%s", decrypt->ciphername, decrypt->hmacname);

    memset(cipher, 0, sizeof(struct decrypt_handle_s));
    cipher->c_headerhandle=NULL;
    cipher->c_packethandle=NULL;
    cipher->c_algo=0;
    cipher->c_mode=0;
    cipher->m_handle=NULL;
    cipher->m_algo=0;

    c_algo=get_cipher_param(decrypt->ciphername, &c_mode);
    if (c_algo==0 || c_mode==0) goto error;
    cipher->c_algo=c_algo;
    cipher->c_mode=c_mode;

    result=gcry_cipher_open(&cipher->c_headerhandle, cipher->c_algo, cipher->c_mode, 0);

    if (result) {

	logoutput("init_decryptor: open cipher error %s/%s", gcry_strsource(result), gcry_strerror(result));
	goto error;

    }

    result=gcry_cipher_open(&cipher->c_packethandle, cipher->c_algo, cipher->c_mode, 0);

    if (result) {

	logoutput("init_decryptor: open cipher error %s/%s", gcry_strsource(result), gcry_strerror(result));
	goto error;

    }

    if (cipher_key->len != (2 * CHACHA20_KEYSIZE)) {

	logoutput("init_decryptor: key cipher wromg size (expecting %i got %i)", 2 * CHACHA20_KEYSIZE, cipher_key->len);
	goto error;

    }

    result=gcry_cipher_setkey(cipher->c_packethandle, (void *)cipher_key->ptr, CHACHA20_KEYSIZE);

    if (result) {

	logoutput("init_decryptor: set key cipher error %s/%s", gcry_strsource(result), gcry_strerror(result));
	goto error;

    }

    result=gcry_cipher_setkey(cipher->c_headerhandle, (void *)(cipher_key->ptr + CHACHA20_KEYSIZE), CHACHA20_KEYSIZE);

    if (result) {

	logoutput("init_decryptor: set key cipher error %s/%s", gcry_strsource(result), gcry_strerror(result));
	goto error;

    }

    m_algo=get_hmac_param(decrypt->ciphername, &m_maclen); /* take the name of cipher: this is a special case cause it's a combined cipher and hmac */
    if (m_algo==0) goto error;
    cipher->m_algo=m_algo;

    result=gcry_mac_open(&cipher->m_handle, cipher->m_algo, 0, NULL);

    if (result) {

	logoutput("init_decryptor: open mac error %s/%s", gcry_strsource(result), gcry_strerror(result));
	goto error;

    }

    decryptor->hmac_maclen=m_maclen;
    decryptor->cipher_blocksize=CHACHA20_BLOCKSIZE;
    decryptor->cipher_headersize=CHACHA20_HEADERSIZE; /* hardcoded */
    decryptor->verify_hmac_pre=verify_hmac_pre;
    decryptor->decrypt_length=decrypt_length;
    decryptor->decrypt_packet=decrypt_packet;
    decryptor->verify_hmac_post=verify_hmac_post;
    decryptor->clear=clear_decryptor;

    return 0;

    error:

    clear_cipher(cipher);
    return -1;

}

static unsigned int get_cipher_blocksize(const char *name)
{
    if (strcmp(name, "chacha20-poly1305@openssh.com")==0) return CHACHA20_BLOCKSIZE;
    return 0;
}
static unsigned int get_cipher_keysize(const char *name)
{
    if (strcmp(name, "chacha20-poly1305@openssh.com")==0) return (2 * CHACHA20_KEYSIZE);
    return 0;
}
static unsigned int get_cipher_ivsize(const char *name)
{
    return 0;
}
static unsigned int get_hmac_keysize(const char *name)
{
    if (strcmp(name, "chacha20-poly1305@openssh.com")==0) return POLY1305_TAGLEN;
    return 0;
}
static unsigned int get_decrypt_flag(const char *cname, const char *hname, const char *what)
{
    if (strcmp(what, "parallel")==0) return 1;
    return 0;
}

#else

static unsigned int populate_cipher(struct ssh_session_s *session, struct decrypt_ops_s *d_ops, struct cipher_list_s *clist, unsigned int start, unsigned int count)
{
    return 0;
}
static unsigned int populate_hmac(struct ssh_session_s *session, struct decrypt_ops_s *d_ops, struct hmac_list_s *clist, unsigned int start, unsigned int count)
{
    return 0;
}
static unsigned int get_handle_size(struct ssh_decryptor_s *d)
{
    return 0;
}

static int init_decryptor(struct ssh_decryptor_s *decryptor)
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
static unsigned int get_decrypt_flag(const char *cname, const char *hname, const char *what)
{
    return 0
}

#endif

static struct decrypt_ops_s special_d_ops = {
    .name			= "chacha20-poly1305@openssh.com",
    .populate_cipher		= populate_cipher,
    .populate_hmac		= populate_hmac,
    .get_handle_size		= get_handle_size,
    .init_decryptor		= init_decryptor,
    .get_cipher_blocksize	= get_cipher_blocksize,
    .get_cipher_keysize		= get_cipher_keysize,
    .get_cipher_ivsize		= get_cipher_ivsize,
    .get_hmac_keysize		= get_hmac_keysize,
    .get_decrypt_flag		= get_decrypt_flag,
    .list			= {NULL, NULL},
};

void init_decrypt_chacha20_poly1305_openssh_com()
{
    add_decrypt_ops(&special_d_ops);
}

void set_decrypt_chacha20_poly1305_openssh_com(struct ssh_decrypt_s *decrypt)
{
    decrypt->ops=&special_d_ops;
}
