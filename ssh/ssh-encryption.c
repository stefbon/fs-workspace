/*
  2010, 2011, 2012, 2103, 2014, 2015, 2016, 2017 Stef Bon <stefbon@gmail.com>

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
#include "ssh-encryption.h"
#include "ssh-encryption-libgcrypt.h"

#include "ctx-options.h"

static int decrypt_length_none(struct rawdata_s *data, unsigned char *buffer, unsigned int len)
{
    memcpy(buffer, data->buffer, len);
    data->decrypted=len;
    return 0;
}

static int decrypt_packet_none(struct rawdata_s *data)
{
    data->decrypted=data->len - data->maclen;
    return 0;
}

static void reset_none(struct ssh_encryption_s *encryption)
{
}

static void free_none(struct ssh_encryption_s *encryption)
{
}

static void close_none(struct ssh_encryption_s *encryption)
{
}

static int encrypt_none(struct ssh_encryption_s *encryption, struct ssh_packet_s *packet)
{
    return 0;
}

static unsigned char get_padding_default(unsigned int len, unsigned int blocksize)
{
    unsigned int mod=0;
    unsigned char padding=0;

    mod=len % blocksize;
    padding =  (unsigned char) (blocksize - mod);

    if ( padding < 4) {

	/* the remainder is too less (< 4): add an extra block */

	padding+=blocksize;

    }

    return padding;
}

static void set_decrypt_none(struct ssh_encryption_s *encryption)
{
    struct ssh_decrypt_s *decrypt=&encryption->decrypt;

    decrypt->library.type=_LIBRARY_NONE;
    decrypt->library.ptr=NULL;
    decrypt->decrypt_length=decrypt_length_none;
    decrypt->decrypt_packet=decrypt_packet_none;
    decrypt->reset_decrypt=reset_none;
    decrypt->close_decrypt=close_none;
    decrypt->free_decrypt=free_none;
    decrypt->blocksize=8; /* just take a convenient value */
    decrypt->size_firstbytes=8;
}

static void set_encrypt_none(struct ssh_encryption_s *encryption)
{
    struct ssh_encrypt_s *encrypt=&encryption->encrypt;

    encrypt->library.type=_LIBRARY_NONE;
    encrypt->library.ptr=NULL;
    encrypt->encrypt=encrypt_none;
    encrypt->reset_encrypt=reset_none;
    encrypt->close_encrypt=close_none;
    encrypt->free_encrypt=free_none;
    encrypt->blocksize=8; /* just take a convenient value */
    encrypt->get_message_padding=get_padding_default;
}

void init_encryption(struct ssh_session_s *session)
{
    struct ssh_encryption_s *encryption=&session->crypto.encryption;

    set_decrypt_none(encryption);
    set_encrypt_none(encryption);

    /* initialization vectors are stored on a central location */

    encryption->decrypt.iv=&session->crypto.keydata.iv_s2c;
    encryption->encrypt.iv=&session->crypto.keydata.iv_c2s;

    init_encryption_libgcrypt(encryption);

}

int set_encryption(struct ssh_session_s *session, const char *name, unsigned int *error)
{

    if (strcmp(name, "none")==0) {
	struct ssh_encryption_s *encryption=&session->crypto.encryption;

	logoutput("set_encryption: setting to none");
	set_encrypt_none(encryption);

    } else {
	struct ssh_encryption_s *encryption=&session->crypto.encryption;
	struct ssh_encrypt_s *encrypt=&encryption->encrypt;

	return (* encrypt->set_encrypt)(encryption, name, error);

    }

    return 0;

}

int set_decryption(struct ssh_session_s *session, const char *name, unsigned int *error)
{

    if (strcmp(name, "none")==0) {
	struct ssh_encryption_s *encryption=&session->crypto.encryption;

	logoutput("set_decryption: setting to none");
	set_decrypt_none(encryption);

    } else {
	struct ssh_encryption_s *encryption=&session->crypto.encryption;
	struct ssh_decrypt_s *decrypt=&encryption->decrypt;

	return (* decrypt->set_decrypt)(encryption, name, error);

    }

    return 0;

}

/* encryption/c2s functions */

int ssh_encrypt(struct ssh_session_s *session, struct ssh_packet_s *packet)
{
    struct ssh_encryption_s *encryption=&session->crypto.encryption;
    struct ssh_encrypt_s *encrypt=&encryption->encrypt;
    return  (* encrypt->encrypt)(encryption, packet);
}

void reset_encrypt(struct ssh_session_s *session)
{
    struct ssh_encryption_s *encryption=&session->crypto.encryption;
    struct ssh_encrypt_s *encrypt=&encryption->encrypt;
    (* encrypt->reset_encrypt)(encryption);
}

void close_encrypt(struct ssh_session_s *session)
{
    struct ssh_encryption_s *encryption=&session->crypto.encryption;
    struct ssh_encrypt_s *encrypt=&encryption->encrypt;
    (* encrypt->close_encrypt)(encryption);
}

void free_encrypt(struct ssh_session_s *session)
{
    struct ssh_encryption_s *encryption=&session->crypto.encryption;
    struct ssh_encrypt_s *encrypt=&encryption->encrypt;
    (* encrypt->free_encrypt)(encryption);
}

unsigned int get_cipher_blocksize_c2s(struct ssh_session_s *session)
{
    struct ssh_encryption_s *encryption=&session->crypto.encryption;
    struct ssh_encrypt_s *encrypt=&encryption->encrypt;
    return encrypt->blocksize;
}

int set_cipher_key_c2s(struct ssh_session_s *session, char *name, struct ssh_string_s *key)
{
    struct ssh_encryption_s *encryption=&session->crypto.encryption;
    struct ssh_encrypt_s *encrypt=&encryption->encrypt;
    return (* encrypt->setkey)(&encrypt->key, name, key);
}

int set_cipher_iv_c2s(struct ssh_session_s *session, char *name, struct ssh_string_s *iv)
{
    struct ssh_encryption_s *encryption=&session->crypto.encryption;
    struct ssh_encrypt_s *encrypt=&encryption->encrypt;
    return (* encrypt->setiv)(encrypt->iv, name, iv);
}

unsigned char get_message_padding(struct ssh_session_s *session, unsigned int len, unsigned int blocksize)
{
    struct ssh_encryption_s *encryption=&session->crypto.encryption;
    struct ssh_encrypt_s *encrypt=&encryption->encrypt;
    return (* encrypt->get_message_padding)(len, blocksize);
}

/* decryption/s2c functions */

int ssh_decrypt_length(struct rawdata_s *data, unsigned char *buffer, unsigned int len)
{
    struct ssh_encryption_s *encryption=&data->session->crypto.encryption;
    struct ssh_decrypt_s *decrypt=&encryption->decrypt;
    return  (* decrypt->decrypt_length)(data, buffer, len);
}

int ssh_decrypt_packet(struct rawdata_s *data)
{
    struct ssh_encryption_s *encryption=&data->session->crypto.encryption;
    struct ssh_decrypt_s *decrypt=&encryption->decrypt;
    return  (* decrypt->decrypt_packet)(data);
}

void reset_decrypt(struct ssh_session_s *session)
{
    struct ssh_encryption_s *encryption=&session->crypto.encryption;
    struct ssh_decrypt_s *decrypt=&encryption->decrypt;
    (* decrypt->reset_decrypt)(encryption);
}

void close_decrypt(struct ssh_session_s *session)
{
    struct ssh_encryption_s *encryption=&session->crypto.encryption;
    struct ssh_decrypt_s *decrypt=&encryption->decrypt;
    (* decrypt->close_decrypt)(encryption);
}

void free_decrypt(struct ssh_session_s *session)
{
    struct ssh_encryption_s *encryption=&session->crypto.encryption;
    struct ssh_decrypt_s *decrypt=&encryption->decrypt;
    (* decrypt->free_decrypt)(encryption);
}

unsigned int get_cipher_blocksize_s2c(struct ssh_session_s *session)
{
    struct ssh_encryption_s *encryption=&session->crypto.encryption;
    struct ssh_decrypt_s *decrypt=&encryption->decrypt;
    return decrypt->blocksize;
}

int set_cipher_key_s2c(struct ssh_session_s *session, char *name, struct ssh_string_s *key)
{
    struct ssh_encryption_s *encryption=&session->crypto.encryption;
    struct ssh_decrypt_s *decrypt=&encryption->decrypt;
    return (* decrypt->setkey)(&decrypt->key, name, key);
}

int set_cipher_iv_s2c(struct ssh_session_s *session, char *name, struct ssh_string_s *iv)
{
    struct ssh_encryption_s *encryption=&session->crypto.encryption;
    struct ssh_decrypt_s *decrypt=&encryption->decrypt;
    return (* decrypt->setiv)(decrypt->iv, name, iv);
}

unsigned int get_size_firstbytes(struct ssh_session_s *session)
{
    struct ssh_encryption_s *encryption=&session->crypto.encryption;
    struct ssh_decrypt_s *decrypt=&encryption->decrypt;
    return decrypt->size_firstbytes;
}

/* common functions */

unsigned int get_cipher_keysize(struct ssh_session_s *session, const char *name)
{
    struct ssh_encryption_s *encryption=&session->crypto.encryption;
    return (*encryption->get_cipher_keysize)(name);
}

unsigned int get_cipher_blocksize(struct ssh_session_s *session, const char *name)
{
    struct ssh_encryption_s *encryption=&session->crypto.encryption;
    return (*encryption->get_cipher_blocksize)(name);
}

unsigned int get_cipher_ivsize(struct ssh_session_s *session, const char *name)
{
    struct ssh_encryption_s *encryption=&session->crypto.encryption;
    return (*encryption->get_cipher_ivsize)(name);
}

unsigned int check_add_ciphername(const char *name, struct commalist_s *clist)
{
    return check_add_generic(get_ssh_options("ciphers"), name, clist);
}

unsigned int ssh_get_cipher_list(struct commalist_s *clist)
{
    unsigned int len=0;
    unsigned int error=0;

    len+=add_name_to_commalist("none", clist, &error);
    len+=ssh_get_cipher_list_libgcrypt(clist);
    return len;

}
