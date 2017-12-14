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

#include "ssh-encryption-chacha20-poly1305-libgcrypt.h"

extern unsigned int check_add_ciphername(const char *name, struct commalist_s *clist);

struct libgcrypt_cipher_s {
    gcry_cipher_hd_t		handle;
    unsigned int		algo;
    unsigned int		mode;
};

static void _close_cipher(struct libgcrypt_cipher_s *cipher)
{
    if (cipher->handle) {

	gcry_cipher_close(cipher->handle);
	cipher->handle=NULL;

    }
}

static void _free_cipher(struct libgcrypt_cipher_s *cipher)
{
    _close_cipher(cipher);
    free(cipher);
}

/* generic decrypt of the first block to get the length */

static int _decrypt_length(struct rawdata_s *data, unsigned char *buffer, unsigned int len)
{
    struct ssh_decrypt_s *decrypt=&data->session->crypto.encryption.decrypt;
    struct libgcrypt_cipher_s *cipher=(struct libgcrypt_cipher_s *) decrypt->library.ptr;
    gcry_error_t result=0;

    result=gcry_cipher_decrypt(cipher->handle, buffer, len, data->buffer, len);

    if (result==0) {

	data->decrypted=len;
	return 0;

    } else {

	logoutput("decrypt_length: error %s/%s", gcry_strsource(result), gcry_strerror(result));

    }

    return -1;

}

static int _decrypt_packet(struct rawdata_s *data)
{
    struct ssh_decrypt_s *decrypt=&data->session->crypto.encryption.decrypt;
    struct libgcrypt_cipher_s *cipher=(struct libgcrypt_cipher_s *) decrypt->library.ptr;
    gcry_error_t result=0;

    result=gcry_cipher_decrypt(cipher->handle, data->buffer + data->decrypted, data->len - data->decrypted - data->maclen, NULL, 0);

    if (result==0) {

	data->decrypted=data->len - data->maclen;
	return 0;

    } else {

	logoutput("decrypt_packet: error %s/%s", gcry_strsource(result), gcry_strerror(result));

    }

    return -1;

}

static void _reset_decrypt(struct ssh_encryption_s *encryption)
{
    struct libgcrypt_cipher_s *cipher=(struct libgcrypt_cipher_s *) encryption->decrypt.library.ptr;

    gcry_cipher_reset(cipher->handle);
    gcry_cipher_setiv(cipher->handle, encryption->decrypt.iv.ptr, encryption->decrypt.iv.len);

}

static void _close_decrypt(struct ssh_encryption_s *encryption)
{
    struct libgcrypt_cipher_s *cipher=(struct libgcrypt_cipher_s *) encryption->decrypt.library.ptr;
    if (cipher) _close_cipher(cipher);
}

static void _free_decrypt(struct ssh_encryption_s *encryption)
{
    struct libgcrypt_cipher_s *cipher=(struct libgcrypt_cipher_s *) encryption->decrypt.library.ptr;

    if (cipher) {

	_free_cipher(cipher);
	encryption->decrypt.library.ptr=NULL;

    }

    free_ssh_string(&encryption->decrypt.iv);
    free_ssh_string(&encryption->decrypt.key);

}

static int _encrypt_packet(struct ssh_encryption_s *encryption, struct ssh_packet_s *packet)
{
    struct libgcrypt_cipher_s *cipher=(struct libgcrypt_cipher_s *) encryption->encrypt.library.ptr;
    gcry_error_t result=0;

    result=gcry_cipher_encrypt(cipher->handle, packet->buffer, packet->len, NULL, 0);

    if (result==0) {

	return 0;

    } else {

	logoutput("encrypt_packet: error %s/%s", gcry_strsource(result), gcry_strerror(result));
	packet->error=EIO;

    }

    return -1;

}

static void _reset_encrypt(struct ssh_encryption_s *encryption)
{
    struct libgcrypt_cipher_s *cipher=(struct libgcrypt_cipher_s *) encryption->encrypt.library.ptr;

    gcry_cipher_reset(cipher->handle);
    gcry_cipher_setiv(cipher->handle, encryption->encrypt.iv.ptr, encryption->encrypt.iv.len);

}

static void _close_encrypt(struct ssh_encryption_s *encryption)
{
    struct libgcrypt_cipher_s *cipher=(struct libgcrypt_cipher_s *) encryption->encrypt.library.ptr;
    if (cipher) _close_cipher(cipher);
}

static void _free_encrypt(struct ssh_encryption_s *encryption)
{
    struct libgcrypt_cipher_s *cipher=(struct libgcrypt_cipher_s *) encryption->encrypt.library.ptr;

    if (cipher) {

	_free_cipher(cipher);
	encryption->encrypt.library.ptr=NULL;

    }

    free_ssh_string(&encryption->encrypt.iv);
    free_ssh_string(&encryption->encrypt.key);

}

/*
    get the gcrypt algo number for a name
    the name is a combination of the name and the mode
    for example:

    3des-cbc
*/

static unsigned int get_gcrypt_algo_x(const char *name, unsigned int *mode)
{
    unsigned int len=strlen(name);
    char tmp[len+1];
    char *sep=NULL;
    unsigned int algo=0;

    memcpy(tmp, name, len+1);

    sep=strchr(tmp, '-');

    if (sep) {

	if (strcmp(sep+1, "ecb")==0) {

	    *mode=GCRY_CIPHER_MODE_ECB;

	} else if (strcmp(sep+1, "cfb")==0) {

	    *mode=GCRY_CIPHER_MODE_CFB;

	} else if (strcmp(sep+1, "cbc")==0) {

	    *mode=GCRY_CIPHER_MODE_CBC;

	} else if (strcmp(sep+1, "ofb")==0) {

	    *mode=GCRY_CIPHER_MODE_OFB;

	} else if (strcmp(sep+1, "ctr")==0) {

	    *mode=GCRY_CIPHER_MODE_CTR;

	} else {

	    goto notsupported;

	}

	*sep='\0';
	algo=gcry_cipher_map_name(tmp);
	*sep='-';

    } else {

	algo=gcry_cipher_map_name(tmp);
	*mode=0;

    }

    return algo;

    notsupported:

    logoutput("get_gcrypt_algo_x: unable to get mode from %s", name);

    return 0;

}

static unsigned int _get_cipher_blocksize(const char *name)
{

    /* handle specials first */

    if (strcmp(name, "chacha20-poly1305@openssh.com")==0) {

	return _get_cipher_blocksize_chacha20_poly1305();

    } else {
	unsigned int algo=0;
	unsigned int mode=0;

	algo=get_gcrypt_algo_x(name, &mode);

	if (algo>0) {

	    return (unsigned int) gcry_cipher_get_algo_blklen(algo);

	}

    }

    return 0;

}

static unsigned int _get_cipher_keysize(const char *name)
{

    /* handle specials first */

    if (strcmp(name, "chacha20-poly1305@openssh.com")==0) {

	return _get_cipher_keysize_chacha20_poly1305();

    } else {
	unsigned int algo=0;
	unsigned int mode=0;

	algo=get_gcrypt_algo_x(name, &mode);

	if (algo>0) {

	    return (unsigned int) gcry_cipher_get_algo_keylen(algo);

	}

    }

    return 0;

}

static unsigned int _get_cipher_ivsize(const char *name)
{

    /* handle specials first */

    if (strcmp(name, "chacha20-poly1305@openssh.com")==0) {

	return _get_cipher_ivsize_chacha20_poly1305();

    } else {
	unsigned int algo=0;
	unsigned int mode=0;

	algo=get_gcrypt_algo_x(name, &mode);

	if (algo>0) {

	    /* default the iv size is equal to the block size */

	    return (unsigned int) gcry_cipher_get_algo_blklen(algo);

	}

    }

    return 0;

}

static int _setdata_key(struct ssh_string_s *key, char *name, struct ssh_string_s *new)
{

    if (_get_cipher_keysize(name)>0) {

	key->ptr=realloc(key->ptr, new->len);

	if (key->ptr) {

	    memcpy(key->ptr, new->ptr, new->len);
	    key->len=new->len;

	} else {

	    key->len=0;
	    return -1;

	}

	return key->len;

    }

    return 0;

}

static int _setdata_iv(struct ssh_string_s *key, char *name, struct ssh_string_s *new)
{

    if (_get_cipher_ivsize(name)>0) {

	key->ptr=realloc(key->ptr, new->len);

	if (key->ptr) {

	    memcpy(key->ptr, new->ptr, new->len);
	    key->len=new->len;

	} else {

	    key->len=0;
	    return -1;

	}

	return key->len;

    }

    return 0;

}

static int _init_encryption_generic(struct library_s *library, const char *name, unsigned int *error)
{
    unsigned int algo=0;
    unsigned int mode=0;
    struct libgcrypt_cipher_s *cipher=NULL;

    if (strcmp(name, "none")==0) {

	/* should not happen */
	return -1;

    } else {

	algo=get_gcrypt_algo_x(name, &mode);

	if (algo==0 || mode==0) {

	    /* not supported */
	    *error=EINVAL;
	    return -1;

	}

    }

    cipher=malloc(sizeof(struct libgcrypt_cipher_s));

    if (cipher) {

	memset(cipher, 0, sizeof(struct libgcrypt_cipher_s));

	if (gcry_cipher_open(&cipher->handle, algo, mode, 0)==0) {

	    library->type=_LIBRARY_LIBGCRYPT;
	    library->ptr=(void *) cipher;

	    cipher->algo=algo;
	    cipher->mode=mode;

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

static int init_encryption_c2s(struct ssh_encryption_s *encryption, const char *name, unsigned int *error)
{

    /* handle specials first */

    if (strcmp(name, "chacha20-poly1305@openssh.com")==0) {

	return init_encryption_c2s_chacha20_poly1305(encryption, error);

    }

    if (_init_encryption_generic(&encryption->encrypt.library, name, error)==0) {
	struct libgcrypt_cipher_s *cipher=(struct libgcrypt_cipher_s *) encryption->encrypt.library.ptr;
	struct ssh_string_s *key=&encryption->encrypt.key;

	encryption->encrypt.encrypt=_encrypt_packet;
	encryption->encrypt.reset_encrypt=_reset_encrypt;
	encryption->encrypt.close_encrypt=_close_encrypt;
	encryption->encrypt.free_encrypt=_free_encrypt;

	gcry_cipher_setkey(cipher->handle, key->ptr, key->len);

	encryption->encrypt.blocksize=(unsigned int) gcry_cipher_get_algo_blklen(cipher->algo);

	_reset_encrypt(encryption);

    } else {

	logoutput("set_encryption_c2s: error setting backend library");
	return -1;

    }

    return 0;

}

static int init_encryption_s2c(struct ssh_encryption_s *encryption, const char *name, unsigned int *error)
{

    /* handle specials first */

    if (strcmp(name, "chacha20-poly1305@openssh.com")==0) {

	return init_encryption_s2c_chacha20_poly1305(encryption, error);

    }

    if (_init_encryption_generic(&encryption->decrypt.library, name, error)==0) {
	struct libgcrypt_cipher_s *cipher=(struct libgcrypt_cipher_s *) encryption->decrypt.library.ptr;
	struct ssh_string_s *key=&encryption->decrypt.key;

	encryption->decrypt.decrypt_length=_decrypt_length;
	encryption->decrypt.decrypt_packet=_decrypt_packet;
	encryption->decrypt.reset_decrypt=_reset_decrypt;
	encryption->decrypt.close_decrypt=_close_decrypt;
	encryption->decrypt.free_decrypt=_free_decrypt;

	gcry_cipher_setkey(cipher->handle, key->ptr, key->len);

	encryption->decrypt.blocksize=(unsigned int) gcry_cipher_get_algo_blklen(cipher->algo);
	encryption->decrypt.size_firstbytes=8;

	_reset_decrypt(encryption);

    } else {

	logoutput("set_encryption_s2c: error setting backend library");
	return -1;

    }

    return 0;

}

void init_encryption_libgcrypt(struct ssh_encryption_s *encryption)
{
    encryption->encrypt.init=init_encryption_c2s;
    encryption->decrypt.init=init_encryption_s2c;

    encryption->get_cipher_blocksize=_get_cipher_blocksize;
    encryption->get_cipher_keysize=_get_cipher_keysize;
    encryption->get_cipher_ivsize=_get_cipher_ivsize;

    encryption->encrypt.setkey=_setdata_key;
    encryption->decrypt.setkey=_setdata_key;
    encryption->encrypt.setiv=_setdata_iv;
    encryption->decrypt.setiv=_setdata_iv;
}

static signed char test_algo_libgcrypt(const char *name)
{
    signed char result=-1;

    if (strcmp(name, "chacha20-poly1305@openssh.com")==0) {

	result=test_algo_chacha20_poly1305();

    } else {
	unsigned int algo=0;

	algo=gcry_cipher_map_name(name);

	if (algo>0) {

	    if (gcry_cipher_algo_info(algo, GCRYCTL_TEST_ALGO, NULL, NULL)==0) result=0;

	}

    }

    return result;
}

unsigned int ssh_get_cipher_list_libgcrypt(struct commalist_s *clist)
{
    unsigned int len=0;

    if (test_algo_libgcrypt("chacha20-poly1305@openssh.com")==0) {

	len+=check_add_ciphername("chacha20-poly1305@openssh.com", clist);

    }

    if (test_algo_libgcrypt("3des")==0) {

	len+=check_add_ciphername("3des-cbc", clist);

    }

    if (test_algo_libgcrypt("blowfish")==0) {

	len+=check_add_ciphername("blowfish-cbc", clist);

    }

    if (test_algo_libgcrypt("idea")==0) {

	len+=check_add_ciphername("idea-cbc", clist);

    }

    if (test_algo_libgcrypt("twofish")==0) {

	len+=check_add_ciphername("twofish256-cbc", clist);

    }

    if (test_algo_libgcrypt("twofish128")==0) {

	len+=check_add_ciphername("twofish128-cbc", clist);

    }

    if (test_algo_libgcrypt("aes128")==0) {

	len+=check_add_ciphername("aes128-cbc", clist);
	len+=check_add_ciphername("aes128-ctr", clist);

    }

    if (test_algo_libgcrypt("aes256")==0) {

	len+=check_add_ciphername("aes256-cbc", clist);
	len+=check_add_ciphername("aes256-ctr", clist);

    }

    if (test_algo_libgcrypt("serpent128")==0) {

	len+=check_add_ciphername("serpent128-cbc", clist);

    }

    if (test_algo_libgcrypt("serpent256")==0) {

	len+=check_add_ciphername("serpent256-cbc", clist);

    }

    return len;

}
