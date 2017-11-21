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
#include "ssh-encryption.h"
#include "ssh-encryption-libgcrypt.h"

#include "ctx-options.h"

static int decrypt_length_none(struct rawdata_s *data, unsigned char *buffer, unsigned int len)
{
    memcpy(buffer, data, len);
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
    encryption->library_s2c.type=_LIBRARY_NONE;
    encryption->library_s2c.ptr=NULL;
    encryption->decrypt_length=decrypt_length_none;
    encryption->decrypt_packet=decrypt_packet_none;
    encryption->reset_decrypt=reset_none;
    encryption->close_encrypt=close_none;
    encryption->free_decrypt=free_none;
    encryption->blocksize_s2c=8; /* just take a convenient value */
}

static void set_encrypt_none(struct ssh_encryption_s *encryption)
{
    encryption->library_c2s.type=_LIBRARY_NONE;
    encryption->library_c2s.ptr=NULL;
    encryption->encrypt=encrypt_none;
    encryption->reset_encrypt=reset_none;
    encryption->close_encrypt=close_none;
    encryption->free_encrypt=free_none;
    encryption->blocksize_c2s=8; /* just take a convenient value */
    encryption->get_message_padding=get_padding_default;
    encryption->size_firstbytes=8;
}

void init_encryption(struct ssh_session_s *session)
{
    struct ssh_encryption_s *encryption=&session->crypto.encryption;

    set_decrypt_none(encryption);
    set_encrypt_none(encryption);

    /* initialization vectors are stored in a central location */

    encryption->iv_s2c=&session->crypto.keydata.iv_s2c;
    encryption->iv_c2s=&session->crypto.keydata.iv_c2s;

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

	return (* encryption->set_encrypt)(encryption, name, error);

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
	return (* encryption->set_decrypt)(encryption, name, error);

    }

    return 0;

}

int ssh_encrypt(struct ssh_session_s *session, struct ssh_packet_s *packet)
{
    struct ssh_encryption_s *encryption=&session->crypto.encryption;
    return  (* encryption->encrypt)(encryption, packet);
}

int ssh_decrypt_length(struct rawdata_s *data, unsigned char *buffer, unsigned int len)
{
    struct ssh_encryption_s *encryption=&data->session->crypto.encryption;
    return  (* encryption->decrypt_length)(data, buffer, len);
}

int ssh_decrypt_packet(struct rawdata_s *data)
{
    struct ssh_encryption_s *encryption=&data->session->crypto.encryption;
    return  (* encryption->decrypt_packet)(data);
}

void reset_encrypt(struct ssh_session_s *session)
{
    struct ssh_encryption_s *encryption=&session->crypto.encryption;
    (* encryption->reset_encrypt)(encryption);
}

void reset_decrypt(struct ssh_session_s *session)
{
    struct ssh_encryption_s *encryption=&session->crypto.encryption;
    (* encryption->reset_decrypt)(encryption);
}

void close_encrypt(struct ssh_session_s *session)
{
    struct ssh_encryption_s *encryption=&session->crypto.encryption;
    (* encryption->close_encrypt)(encryption);
}

void close_decrypt(struct ssh_session_s *session)
{
    struct ssh_encryption_s *encryption=&session->crypto.encryption;
    (* encryption->close_decrypt)(encryption);
}

void free_encrypt(struct ssh_session_s *session)
{
    struct ssh_encryption_s *encryption=&session->crypto.encryption;
    (* encryption->free_encrypt)(encryption);
}

void free_decrypt(struct ssh_session_s *session)
{
    struct ssh_encryption_s *encryption=&session->crypto.encryption;
    (* encryption->free_decrypt)(encryption);
}

unsigned int get_cipher_blocksize_c2s(struct ssh_session_s *session)
{
    struct ssh_encryption_s *encryption=&session->crypto.encryption;
    return encryption->blocksize_c2s;
}

unsigned int get_cipher_blocksize_s2c(struct ssh_session_s *session)
{
    struct ssh_encryption_s *encryption=&session->crypto.encryption;
    return encryption->blocksize_s2c;
}

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

int set_cipher_key_c2s(struct ssh_session_s *session, char *name, struct ssh_string_s *key)
{
    struct ssh_encryption_s *encryption=&session->crypto.encryption;
    return (* encryption->setkey_c2s)(&encryption->key_c2s, name, key);
}

int set_cipher_key_s2c(struct ssh_session_s *session, char *name, struct ssh_string_s *key)
{
    struct ssh_encryption_s *encryption=&session->crypto.encryption;
    return (* encryption->setkey_s2c)(&encryption->key_s2c, name, key);
}

int set_cipher_iv_c2s(struct ssh_session_s *session, char *name, struct ssh_string_s *key)
{
    struct ssh_encryption_s *encryption=&session->crypto.encryption;
    return (* encryption->setiv_c2s)(encryption->iv_c2s, name, key);
}

int set_cipher_iv_s2c(struct ssh_session_s *session, char *name, struct ssh_string_s *key)
{
    struct ssh_encryption_s *encryption=&session->crypto.encryption;
    return (* encryption->setiv_s2c)(encryption->iv_s2c, name, key);
}

unsigned char get_message_padding(struct ssh_session_s *session, unsigned int len, unsigned int blocksize)
{
    struct ssh_encryption_s *encryption=&session->crypto.encryption;
    return (* encryption->get_message_padding)(len, blocksize);
}

unsigned int get_size_firstbytes(struct ssh_session_s *session)
{
    struct ssh_encryption_s *encryption=&session->crypto.encryption;
    return encryption->size_firstbytes;
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
