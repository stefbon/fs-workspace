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

#define POLY1305_TAGLEN			16
#define POLY1305_KEYLEN			32

#define CHACHA20_BLOCKSIZE		64
#define CHACHA20_KEYSIZE		32

#define CHACHA20_HEADERSIZE		4

struct encrypt_handle_s {
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

static unsigned int populate_cipher(struct ssh_connection_s *c, struct encrypt_ops_s *ops, struct algo_list_s *alist, unsigned int start)
{

    if (test_cipher_algo("chacha20-poly1305@openssh.com")==0) {

	if (alist) {

	    alist[start].type=SSH_ALGO_TYPE_CIPHER_C2S;
	    alist[start].order=SSH_ALGO_ORDER_HIGH;
	    alist[start].sshname="chacha20-poly1305@openssh.com";
	    alist[start].libname="chacha20";
	    alist[start].ptr=(void *)ops;

	}

	start++;

    }

    return start;

}

static unsigned int populate_hmac(struct ssh_connection_s *connection, struct encrypt_ops_s *ops, struct algo_list_s *alist, unsigned int start)
{
    /* no hmac (cipher is hmac and encrypt at the same time) */
    return start;
}

static unsigned int get_handle_size(struct ssh_encrypt_s *e)
{
    return sizeof(struct encrypt_handle_s);
}

static void clear_cipher(struct encrypt_handle_s *cipher)
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

static int write_hmac_pre(struct ssh_encryptor_s *encryptor, struct ssh_packet_s *packet)
{
    return 0;
}

static int write_hmac_post(struct ssh_encryptor_s *e, struct ssh_packet_s *packet)
{
    struct encrypt_handle_s *cipher=(struct encrypt_handle_s *) e->buffer;
    size_t maclen=e->hmac_maclen;
    gcry_error_t result=0;

    result=gcry_mac_write(cipher->m_handle, packet->buffer, packet->len);
    if (result) goto error;

    result=gcry_mac_read(cipher->m_handle, (void *) (packet->buffer + packet->len), &maclen);
    if (result) goto error;

    return 0;

    error:

    logoutput("write_hmac_post: error %s/%s", gcry_strsource(result), gcry_strerror(result));
    return -1;
}

/* custom padding */

static unsigned char get_message_padding_custom(struct ssh_encryptor_s *encryptor, unsigned int len)
{
    unsigned int mod=0;
    unsigned char padding=0;

    mod=(len - 4) % encryptor->cipher_blocksize;
    padding = (unsigned char)(encryptor->cipher_blocksize - mod);
    if (padding < 4) padding+=encryptor->cipher_blocksize;
    return padding;
}

static int encrypt_packet(struct ssh_encryptor_s *encryptor, struct ssh_packet_s *packet)
{
    struct encrypt_handle_s *cipher=(struct encrypt_handle_s *) encryptor->buffer;
    gcry_error_t result=0;
    char seqbuff[8];
    unsigned char poly1305_key[CHACHA20_BLOCKSIZE];

    memset(seqbuff, 0, 8);
    store_uint64(seqbuff, packet->sequence);

    gcry_cipher_setiv(cipher->c_headerhandle, seqbuff, 8);
    gcry_cipher_setiv(cipher->c_packethandle, seqbuff, 8);

    memset(poly1305_key, 0, CHACHA20_BLOCKSIZE);

    gcry_cipher_encrypt(cipher->c_packethandle, poly1305_key, CHACHA20_BLOCKSIZE, NULL, 0);
    gcry_mac_setkey(cipher->m_handle, poly1305_key, POLY1305_KEYLEN);

    result=gcry_cipher_encrypt(cipher->c_headerhandle, packet->buffer, CHACHA20_HEADERSIZE, NULL, 0);
    if (result) goto error;

    result=gcry_cipher_encrypt(cipher->c_packethandle, packet->buffer + CHACHA20_HEADERSIZE, packet->len - CHACHA20_HEADERSIZE, NULL, 0);
    if (result) goto error;

    return 0;

    error:

    logoutput("encrypt_packet: error %s/%s", gcry_strsource(result), gcry_strerror(result));
    return -1;

}

static void clear_encryptor(struct ssh_encryptor_s *e)
{
    struct encrypt_handle_s *cipher=(struct encrypt_handle_s *) e->buffer;
    clear_cipher(cipher);
    memset(e->buffer, 0, e->size);
}

static int init_encryptor(struct ssh_encryptor_s *encryptor)
{
    struct ssh_encrypt_s *encrypt=encryptor->encrypt;
    struct encrypt_handle_s *cipher=(struct encrypt_handle_s *) encryptor->buffer;
    gcry_error_t result=0;
    struct ssh_string_s *cipher_key=&encrypt->cipher_key;
    struct ssh_string_s *hmac_key=&encrypt->hmac_key;
    int c_algo=0;
    unsigned int c_mode=0;
    int m_algo=0;
    unsigned int m_maclen=0;

    logoutput("init_encryptor (chacha20-poly1305@openssh.com) %s:%s", encrypt->ciphername, encrypt->hmacname);

    memset(cipher, 0, sizeof(struct encrypt_handle_s));
    cipher->c_headerhandle=NULL;
    cipher->c_packethandle=NULL;
    cipher->c_algo=0;
    cipher->c_mode=0;
    cipher->m_handle=NULL;
    cipher->m_algo=0;

    c_algo=get_cipher_param(encrypt->ciphername, &c_mode);
    if (c_algo==0 || c_mode==0) goto error;
    cipher->c_algo=c_algo;
    cipher->c_mode=c_mode;

    result=gcry_cipher_open(&cipher->c_headerhandle, cipher->c_algo, cipher->c_mode, 0);

    if (result) {

	logoutput("init_encryptor: open cipher error %s/%s", gcry_strsource(result), gcry_strerror(result));
	goto error;

    }

    result=gcry_cipher_open(&cipher->c_packethandle, cipher->c_algo, cipher->c_mode, 0);

    if (result) {

	logoutput("init_encryptor: open cipher error %s/%s", gcry_strsource(result), gcry_strerror(result));
	goto error;

    }

    if (cipher_key->len != (2 * CHACHA20_KEYSIZE)) {

	logoutput("init_encryptor: key cipher wromg size (expecting %i got %i)", 2 * CHACHA20_KEYSIZE, cipher_key->len);
	goto error;

    }

    result=gcry_cipher_setkey(cipher->c_packethandle, (void *)cipher_key->ptr, CHACHA20_KEYSIZE);

    if (result) {

	logoutput("init_encryptor: set key cipher error %s/%s", gcry_strsource(result), gcry_strerror(result));
	goto error;

    }

    result=gcry_cipher_setkey(cipher->c_headerhandle, (void *)(cipher_key->ptr + CHACHA20_KEYSIZE), CHACHA20_KEYSIZE);

    if (result) {

	logoutput("init_encryptor: set key cipher error %s/%s", gcry_strsource(result), gcry_strerror(result));
	goto error;

    }

    m_algo=get_hmac_param(encrypt->ciphername, &m_maclen); /* take the name of cipher: this is a special case cause it's a combined cipher and hmac */
    if (m_algo==0) goto error;
    cipher->m_algo=m_algo;

    result=gcry_mac_open(&cipher->m_handle, cipher->m_algo, 0, NULL);

    if (result) {

	logoutput("init_encryptor: open mac error %s/%s", gcry_strsource(result), gcry_strerror(result));
	goto error;

    }

    encryptor->hmac_maclen=m_maclen;
    encryptor->cipher_blocksize=CHACHA20_BLOCKSIZE;
    encryptor->write_hmac_pre=write_hmac_pre;
    encryptor->encrypt_packet=encrypt_packet;
    encryptor->write_hmac_post=write_hmac_post;
    encryptor->get_message_padding=get_message_padding_custom;
    encryptor->clear=clear_encryptor;

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
    if (strcmp(name, "chacha20-poly1305@openssh.com")==0) return (2 * CHACHA20_KEYSIZE); /* two keys are required, one for header and one for packet handle */
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
static unsigned int get_encrypt_flag(const char *cname, const char *hname, const char *what)
{
    if (strcmp(what, "parallel")==0) return 1;
    return 0;
}

#else

static unsigned int populate_cipher(struct ssh_session_s *session, struct encrypt_ops_s *ops, struct algo_list_s *alist, unsigned int start, unsigned int count)
{
    return 0;
}
static unsigned int populate_hmac(struct ssh_session_s *session, struct encrypt_ops_s *ops, struct algo_list_s *alist, unsigned int start, unsigned int count)
{
    return 0;
}
static unsigned int get_handle_size(struct ssh_encryptor_s *e)
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
static unsigned int get_encrypt_flag(const char *cname, const char *hname, const char *what)
{
    return 0;
}

#endif

static struct encrypt_ops_s special_e_ops = {
    .name			= "chacha20-poly1305@openssh.com",
    .populate_cipher		= populate_cipher,
    .populate_hmac		= populate_hmac,
    .get_handle_size		= get_handle_size,
    .init_encryptor		= init_encryptor,
    .get_cipher_blocksize	= get_cipher_blocksize,
    .get_cipher_keysize		= get_cipher_keysize,
    .get_cipher_ivsize		= get_cipher_ivsize,
    .get_hmac_keysize		= get_hmac_keysize,
    .get_encrypt_flag		= get_encrypt_flag,
};

void init_encrypt_chacha20_poly1305_openssh_com()
{
    add_encrypt_ops(&special_e_ops);
}

void set_encrypt_chacha20_poly1305_openssh_com(struct ssh_encrypt_s *encrypt)
{
    encrypt->ops=&special_e_ops;
}
