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

#include "logging.h"
#include "main.h"
#include "utils.h"

#include "ssh-common.h"
#include "ssh-utils.h"
#include "ssh-data.h"
#include "gcrypt.h"

#define CHACHA20_BLOCKSIZE			64
#define POLY1305_KEYLEN				32
#define POLY1305_TAGLEN				16

struct libgcrypt_cipher_s {
    gcry_cipher_hd_t		header_handle;
    gcry_cipher_hd_t		main_handle;
    gcry_mac_hd_t		mac_handle;
};

static void _close_cipher(struct libgcrypt_cipher_s *cipher)
{
    if (cipher->header_handle) {

	gcry_cipher_close(cipher->header_handle);
	cipher->header_handle=NULL;

    }

    if (cipher->main_handle) {

	gcry_cipher_close(cipher->main_handle);
	cipher->main_handle=NULL;

    }

    if (cipher->mac_handle) {

	gcry_mac_close(cipher->mac_handle);
	cipher->mac_handle=NULL;

    }

}

static void _free_cipher(struct libgcrypt_cipher_s *cipher)
{
    _close_cipher(cipher);
    free(cipher);
}

static unsigned char get_padding_custom(unsigned int len, unsigned int blocksize)
{
    unsigned int mod=0;
    unsigned char padding=0;

    mod=(len - 4) % blocksize;
    padding =  (unsigned char) (blocksize - mod);

    if ( padding < 4) {

	/* the remainder is too less (< 4): add an extra block */

	padding+=blocksize;

    }

    return padding;
}

/*
    decrypt length for chacha20-poly1305@openssh.com
    - set iv for both header and main cipher from seq
    - decrypt the first 4 bytes (and no more than that)
*/

static int _decrypt_length(struct rawdata_s *data, unsigned char *buffer, unsigned int len)
{
    struct ssh_decrypt_s *decrypt=&data->session->crypto.encryption.decrypt;
    struct libgcrypt_cipher_s *cipher=(struct libgcrypt_cipher_s *) decrypt->library.ptr;
    gcry_error_t result=0;
    unsigned char seqbuff[8];

    memset(seqbuff, 0, 8);
    store_uint64(seqbuff, data->sequence);

    gcry_cipher_setiv(cipher->header_handle, seqbuff, 8);
    gcry_cipher_setiv(cipher->main_handle, seqbuff, 8);

    result=gcry_cipher_decrypt(cipher->header_handle, buffer, len, data->buffer, len);

    if (result==0) {
	unsigned char poly1305_key[CHACHA20_BLOCKSIZE];

	memset(poly1305_key, 0, CHACHA20_BLOCKSIZE);

	gcry_cipher_encrypt(cipher->main_handle, poly1305_key, CHACHA20_BLOCKSIZE, NULL, 0);
	gcry_mac_setkey(cipher->mac_handle, poly1305_key, POLY1305_KEYLEN);

	data->decrypted=len;
	return 0;

    } else {

	logoutput("_decrypt_length: error %s/%s", gcry_strsource(result), gcry_strerror(result));

    }

    return -1;

}

static int _decrypt_packet(struct rawdata_s *data)
{
    struct ssh_decrypt_s *decrypt=&data->session->crypto.encryption.decrypt;
    struct libgcrypt_cipher_s *cipher=(struct libgcrypt_cipher_s *) decrypt->library.ptr;
    gcry_error_t result=0;

    result=gcry_cipher_decrypt(cipher->main_handle, data->buffer + data->decrypted, data->len - data->decrypted - data->maclen, NULL, 0);

    if (result==0) {

	data->decrypted=data->len - data->maclen;
	return 0;

    } else {

	logoutput("_decrypt_packet: error %s/%s", gcry_strsource(result), gcry_strerror(result));

    }

    return -1;

}

static void _reset_decrypt(struct ssh_encryption_s *encryption)
{
    /* is the cipher reset here?*/
}

static void _close_decrypt(struct ssh_encryption_s *encryption)
{
    struct libgcrypt_cipher_s *cipher=(struct libgcrypt_cipher_s *) encryption->decrypt.library.ptr;
    if (cipher) _close_cipher(cipher);
}

static void _free_decrypt(struct ssh_encryption_s *encryption)
{
    struct libgcrypt_cipher_s *cipher=(struct libgcrypt_cipher_s *) encryption->decrypt.library.ptr;
    if (cipher) _free_cipher(cipher);
    free_ssh_string(&encryption->decrypt.key);
}

static int _encrypt_packet(struct ssh_encryption_s *encryption, struct ssh_packet_s *packet)
{
    struct libgcrypt_cipher_s *cipher=(struct libgcrypt_cipher_s *) encryption->encrypt.library.ptr;
    gcry_error_t result=0;
    unsigned char seqbuff[8];
    unsigned char poly1305_key[CHACHA20_BLOCKSIZE];

    memset(seqbuff, 0, 8);
    store_uint64(seqbuff, packet->sequence);

    gcry_cipher_setiv(cipher->header_handle, seqbuff, 8);
    gcry_cipher_setiv(cipher->main_handle, seqbuff, 8);

    memset(poly1305_key, 0, CHACHA20_BLOCKSIZE);

    gcry_cipher_encrypt(cipher->main_handle, poly1305_key, CHACHA20_BLOCKSIZE, NULL, 0);
    gcry_mac_setkey(cipher->mac_handle, poly1305_key, POLY1305_KEYLEN);

    gcry_cipher_encrypt(cipher->header_handle, packet->buffer, 4, NULL, 0);

    result=gcry_cipher_encrypt(cipher->main_handle, packet->buffer+4, packet->len-4, NULL, 0);

    if (result==0) {

	return 0;

    } else {

	logoutput("_encrypt_packet: error %s/%s", gcry_strsource(result), gcry_strerror(result));

    }

    return -1;

}

static void _reset_encrypt(struct ssh_encryption_s *encryption)
{
    /* is the cipher reset here? */

}

static void _close_encrypt(struct ssh_encryption_s *encryption)
{
    struct libgcrypt_cipher_s *cipher=(struct libgcrypt_cipher_s *) encryption->encrypt.library.ptr;
    if (cipher) _close_cipher(cipher);
}

static void _free_encrypt(struct ssh_encryption_s *encryption)
{
    struct libgcrypt_cipher_s *cipher=(struct libgcrypt_cipher_s *) encryption->encrypt.library.ptr;
    if (cipher) _free_cipher(cipher);
    free_ssh_string(&encryption->encrypt.key);
}

/*
    algo: GCRY_CIPHER_CHACHA20
    mode: GCRY_CIPHER_MODE_STREAM
*/

static unsigned int get_gcrypt_algo_x_chacha20_poly1305(unsigned int *mode)
{
    *mode=GCRY_CIPHER_MODE_STREAM;
    return GCRY_CIPHER_CHACHA20;
}

unsigned int _get_cipher_blocksize_chacha20_poly1305()
{
    return (unsigned int) CHACHA20_BLOCKSIZE;
}

unsigned int _get_cipher_keysize_chacha20_poly1305()
{

    /*
	    here a key is required of 512 bits: 64 bytes
	    the first 32 are used for the main cipher
	    the second 32 are used for the header cipher
    */

    return 64;


}

/* setting iv not required */
unsigned int _get_cipher_ivsize_chacha20_poly1305()
{
    return 0;
}

static int _init_encryption_chacha20_poly1305(struct library_s *library, unsigned int *error)
{
    struct libgcrypt_cipher_s *cipher=NULL;

    cipher=malloc(sizeof(struct libgcrypt_cipher_s));

    if (cipher) {

	memset(cipher, 0, sizeof(struct libgcrypt_cipher_s));

	if (gcry_cipher_open(&cipher->header_handle, GCRY_CIPHER_CHACHA20, GCRY_CIPHER_MODE_STREAM, 0)==0 && 
	    gcry_cipher_open(&cipher->main_handle, GCRY_CIPHER_CHACHA20, GCRY_CIPHER_MODE_STREAM, 0)==0 && 
	    gcry_mac_open(&cipher->mac_handle, GCRY_MAC_POLY1305, 0, NULL)==0) {

	    library->type=_LIBRARY_LIBGCRYPT;
	    library->ptr=(void *) cipher;


	} else {

	    _free_cipher(cipher);
	    *error=EIO;
	    goto error;

	}

    }

    return 0;

    error:

    return -1;

}

int _set_encryption_c2s_chacha20_poly1305(struct ssh_encryption_s *encryption, unsigned int *error)
{

    if (_init_encryption_chacha20_poly1305(&encryption->encrypt.library, error)==0) {
	struct session_crypto_s *crypto=(struct session_crypto_s *) ( ((char *) encryption) - offsetof(struct session_crypto_s, encryption));
	struct libgcrypt_cipher_s *cipher=(struct libgcrypt_cipher_s *) encryption->encrypt.library.ptr;
	struct ssh_hmac_s *hmac=&crypto->hmac;

	encryption->encrypt.encrypt=_encrypt_packet;
	encryption->encrypt.reset_encrypt=_reset_encrypt;
	encryption->encrypt.close_encrypt=_close_encrypt;
	encryption->encrypt.free_encrypt=_free_encrypt;

	/* divide the 64 bytes key into two 32 bytes */

	gcry_cipher_setkey(cipher->main_handle, encryption->encrypt.key.ptr, 32);
	gcry_cipher_setkey(cipher->header_handle, encryption->encrypt.key.ptr+32, 32);

	encryption->encrypt.blocksize=CHACHA20_BLOCKSIZE;
	encryption->encrypt.get_message_padding=get_padding_custom; /* padding is different */

	_reset_encrypt(encryption);

	/* set also the mac: they are combined here */

	hmac->library_c2s.ptr=(void *) cipher->mac_handle;

    } else {

	logoutput("_set_encryption_c2s_chacha20_poly1305: error setting backend library");
	return -1;

    }

    return 0;

}

int _set_encryption_s2c_chacha20_poly1305(struct ssh_encryption_s *encryption, unsigned int *error)
{

    if (_init_encryption_chacha20_poly1305(&encryption->decrypt.library, error)==0) {
	struct session_crypto_s *crypto=(struct session_crypto_s *) ( ((char *) encryption) - offsetof(struct session_crypto_s, encryption));
	struct libgcrypt_cipher_s *cipher=(struct libgcrypt_cipher_s *) encryption->decrypt.library.ptr;
	struct ssh_hmac_s *hmac=&crypto->hmac;

	encryption->decrypt.decrypt_length=_decrypt_length;
	encryption->decrypt.decrypt_packet=_decrypt_packet;
	encryption->decrypt.reset_decrypt=_reset_decrypt;
	encryption->decrypt.close_decrypt=_close_decrypt;
	encryption->decrypt.free_decrypt=_free_decrypt;
	encryption->decrypt.size_firstbytes=4;

	gcry_cipher_setkey(cipher->main_handle, encryption->decrypt.key.ptr, 32);
	gcry_cipher_setkey(cipher->header_handle, encryption->decrypt.key.ptr+32, 32);

	encryption->decrypt.blocksize=CHACHA20_BLOCKSIZE;

	_reset_decrypt(encryption);

	/* set also the mac: they are combined here */

	hmac->library_s2c.ptr=(void *) cipher->mac_handle;

    } else {

	logoutput("set_encryption_s2c_chacha20_poly1305: error setting backend library");
	return -1;

    }

    return 0;

}

signed char test_algo_chacha20_poly1305()
{
    unsigned int c_algo=0;
    unsigned int m_algo=0;
    signed char result=-1;

    c_algo=gcry_cipher_map_name("chacha20");
    m_algo=gcry_mac_map_name("poly1305");

    if (c_algo>0 && m_algo>0) {

	if (gcry_cipher_algo_info(c_algo, GCRYCTL_TEST_ALGO, NULL, NULL)==0 && gcry_mac_test_algo(m_algo)==0) result=0;

    }

    return result;
}
