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
#include <sys/uio.h>
#include <gcrypt.h>

#include "logging.h"
#include "main.h"

#include "utils.h"

#include "ssh-common.h"
#include "ssh-mac.h"
#include "ssh-mac-chacha20-poly1305-libgcrypt.h"
#include "ssh-utils.h"

struct libgcrypt_mac_s {
    gcry_mac_hd_t		handle;
    unsigned int		algo;
};

static void _close_mac(struct libgcrypt_mac_s *ll_mac)
{
    if (ll_mac->handle) {

	gcry_mac_close(ll_mac->handle);
	ll_mac->handle=NULL;

    }
}

static void _free_mac(struct libgcrypt_mac_s *ll_mac)
{
    _close_mac(ll_mac);
    free(ll_mac);
}

static void _reset_s2c(struct ssh_hmac_s *hmac)
{
    struct libgcrypt_mac_s *ll_mac=(struct libgcrypt_mac_s *) hmac->library_s2c.ptr;
    gcry_mac_reset(ll_mac->handle);
}

static void _free_s2c(struct ssh_hmac_s *hmac)
{
    struct ssh_string_s *key=&hmac->key_s2c;

    if (hmac->library_s2c.ptr) {
	struct libgcrypt_mac_s *ll_mac=(struct libgcrypt_mac_s *) hmac->library_s2c.ptr;

	_free_mac(ll_mac);
	hmac->library_s2c.ptr=NULL;

    }

    free_ssh_string(key);

}

/*
    verify mac by creating the mac by reading the packet and compare with the appended mac
    there are two functions to do this:
    - _verify_mac_pre: before decryption (done in some mac handlers like chacha20-poly1305@openssh.com)
    - _verify_mac_post: after decryption (default as described in https://tools.ietf.org/html/rfc4253#section-6.4)
*/

static int _verify_mac_pre(struct rawdata_s *data)
{
    return 0;
}

static int _verify_mac_post(struct rawdata_s *data)
{
    struct ssh_session_s *session=data->session;
    struct ssh_hmac_s *hmac=&session->crypto.hmac;
    struct libgcrypt_mac_s *ll_mac=(struct libgcrypt_mac_s *) hmac->library_s2c.ptr;
    char tmp[4];
    gcry_error_t result=0;

    memset(tmp, '\0', 4);
    store_uint32(tmp, data->sequence);

    gcry_mac_write(ll_mac->handle, (void *)&tmp[0], 4);
    gcry_mac_write(ll_mac->handle, (void *)data->buffer, data->len - data->maclen);

    result=gcry_mac_verify(ll_mac->handle, (void *)(data->buffer + data->len - data->maclen), data->maclen);

    if (result==GPG_ERR_CHECKSUM) {

	return -1;

    } else if (result>0) {

	logoutput("compare_in_gcrypt: error %s/%s", gcry_strsource(result), gcry_strerror(result));

    }

    return 0;
}

static void _reset_c2s(struct ssh_hmac_s *hmac)
{
    struct libgcrypt_mac_s *ll_mac=(struct libgcrypt_mac_s *) hmac->library_c2s.ptr;
    gcry_mac_reset(ll_mac->handle);
}

/* create the mac 
    default the mac is created before encryption */

static void _write_mac_pre(struct ssh_hmac_s *hmac, struct ssh_packet_s *packet)
{
    struct libgcrypt_mac_s *ll_mac=(struct libgcrypt_mac_s *) hmac->library_c2s.ptr;
    char tmp[4];

    memset(tmp, '\0', 4);
    store_uint32(tmp, packet->sequence);

    gcry_mac_write(ll_mac->handle, (void *)&tmp[0], 4);
    gcry_mac_write(ll_mac->handle, (void *)packet->buffer, packet->len);

}

static void _write_mac_post(struct ssh_hmac_s *hmac, struct ssh_packet_s *packet)
{
}

/* send the outgoing packet including the mac */

static ssize_t _send_c2s(struct ssh_session_s *session, struct ssh_packet_s *packet)
{
    struct ssh_hmac_s *hmac=&session->crypto.hmac;
    struct libgcrypt_mac_s *ll_mac=(struct libgcrypt_mac_s *) hmac->library_c2s.ptr;
    ssize_t written=0;
    size_t size=hmac->maclen_c2s;
    char mac[size];

    if (gcry_mac_read(ll_mac->handle, (void *)&mac[0], &size)==0) {
	struct iovec iov[2];

	iov[0].iov_base=(void *) packet->buffer;
	iov[0].iov_len=packet->len;
	iov[1].iov_base=(void *) &mac[0];
	iov[1].iov_len=hmac->maclen_c2s;

	written=writev(session->connection.fd, iov, 2);
	if (written==-1) packet->error=errno;

    } else {

	packet->error=EIO;
	written=-1;

    }

    return written;

}

static void _free_c2s(struct ssh_hmac_s *hmac)
{
    struct ssh_string_s *key=&hmac->key_c2s;

    if (hmac->library_c2s.ptr) {
	struct libgcrypt_mac_s *ll_mac=(struct libgcrypt_mac_s *) hmac->library_c2s.ptr;

	_free_mac(ll_mac);
	hmac->library_c2s.ptr=NULL;

    }

    free_ssh_string(key);

}

static unsigned int _get_mac(const char *name, unsigned int *maclen)
{
    unsigned int algo=0;

    if (strcmp(name, "hmac-sha1")==0) {

	algo=GCRY_MAC_HMAC_SHA1;
	*maclen=gcry_mac_get_algo_maclen(algo);

    } else if (strncmp(name, "hmac-sha1-", 10)==0) {

	*maclen=atoi(name + 10);

	if (*maclen>0 && *maclen % 8 == 0 && *maclen < gcry_mac_get_algo_maclen(GCRY_MAC_HMAC_SHA1)) {

	    algo=GCRY_MAC_HMAC_SHA1;

	}

    } else if (strcmp(name, "hmac-md5")==0) {

	algo=GCRY_MAC_HMAC_MD5;
	*maclen=gcry_mac_get_algo_maclen(algo);

    } else if (strncmp(name, "hmac-md5-", 9)==0) {

	*maclen=atoi(name + 9);

	if (*maclen>0 && *maclen % 8 == 0 && *maclen < gcry_mac_get_algo_maclen(GCRY_MAC_HMAC_MD5)) {

	    algo=GCRY_MAC_HMAC_MD5;

	}

    } else if (strcmp(name, "hmac-sha256")==0) {

	algo=GCRY_MAC_HMAC_SHA256;
	*maclen=gcry_mac_get_algo_maclen(algo);

    } else if (strcmp(name, "hmac-sha224")==0) {

	algo=GCRY_MAC_HMAC_SHA224;
	*maclen=gcry_mac_get_algo_maclen(algo);

    } else if (strcmp(name, "hmac-sha512")==0) {

	algo=GCRY_MAC_HMAC_SHA512;
	*maclen=gcry_mac_get_algo_maclen(algo);

    } else if (strcmp(name, "hmac-sha384")==0) {

	algo=GCRY_MAC_HMAC_SHA384;
	*maclen=gcry_mac_get_algo_maclen(algo);

    }

    return algo;

}

static int _init_hmac(struct library_s *library, const char *name, unsigned int *maclen, unsigned int *error)
{
    int algo=0;
    struct libgcrypt_mac_s *ll_mac=NULL;

    if (strcmp(name, "none")==0) {

	*error=EINVAL;
	return -1;

    } else {

	algo=_get_mac(name, maclen);

	if (algo==0) {

	    logoutput("_init_hmac: hmac name %s not found", name);

	    *error=EINVAL;
	    goto error;

	}

    }

    ll_mac=malloc(sizeof(struct libgcrypt_mac_s));

    if (ll_mac) {

	memset(ll_mac, 0, sizeof(struct libgcrypt_mac_s));

	if (gcry_mac_open(&ll_mac->handle, algo, 0, NULL)==0) {

	    library->type = _LIBRARY_LIBGCRYPT;
	    library->ptr = (void *) ll_mac;

	    ll_mac->algo=algo;

	} else {

	    _free_mac(ll_mac);
	    *error=EIO;
	    goto error;

	}

    }

    return 0;

    error:

    if (*error==0) *error=EIO;
    logoutput_warning("_init_hmac: error (%i:%s)", *error, strerror(*error));
    return -1;

}

static int _set_hmac_c2s(struct ssh_hmac_s *hmac, const char *name, unsigned int *error)
{
    unsigned int maclen=0;

    if (strcmp(name, "chacha20-poly1305@openssh.com")==0) {

	return _set_hmac_c2s_chacha20_poly1305(hmac, error);

    }

    if (_init_hmac(&hmac->library_c2s, name, &maclen, error)==0) {
	struct libgcrypt_mac_s *ll_mac=(struct libgcrypt_mac_s *) hmac->library_c2s.ptr;
	struct ssh_string_s *key=&hmac->key_c2s;

	hmac->reset_c2s 		= _reset_c2s;
	hmac->write_mac_pre 		= _write_mac_pre;
	hmac->write_mac_post 		= _write_mac_post;
	hmac->send_c2s 			= _send_c2s;
	hmac->free_c2s 			= _free_c2s;

	gcry_mac_setkey(ll_mac->handle, key->ptr, key->len);
	free_ssh_string(key); /* not needed anymore */
	hmac->maclen_c2s=maclen;

	_reset_c2s(hmac);

    } else {

	logoutput("_set_hmac_c2s: unable to set backend library");
	return -1;

    }

    return 0;

}

static int _set_hmac_s2c(struct ssh_hmac_s *hmac, const char *name, unsigned int *error)
{
    unsigned int maclen=0;

    if (strcmp(name, "chacha20-poly1305@openssh.com")==0) {

	return _set_hmac_s2c_chacha20_poly1305(hmac, error);

    }

    if (_init_hmac(&hmac->library_s2c, name, &maclen, error)==0) {
	struct libgcrypt_mac_s *ll_mac=(struct libgcrypt_mac_s *) hmac->library_s2c.ptr;
	struct ssh_string_s *key=&hmac->key_s2c;

	hmac->reset_s2c 		= _reset_s2c;
	hmac->verify_mac_pre 		= _verify_mac_pre;
	hmac->verify_mac_post 		= _verify_mac_post;
	hmac->free_s2c 			= _free_s2c;

	gcry_mac_setkey(ll_mac->handle, key->ptr, key->len);
	free_ssh_string(key); /* not needed anymore */
	hmac->maclen_s2c=maclen;

	_reset_s2c(hmac);

    } else {

	logoutput("_set_hmac_s2c: unable to set backend library");
	return -1;

    }

    return 0;

}

unsigned int _get_mac_keylen(char *name)
{

    if (strcmp(name, "chacha20-poly1305@openssh.com")==0) {

	return _get_mac_keylen_chacha20_poly1305();

    } else if (strcmp(name, "hmac-sha1")==0 || strcmp(name, "hmac-sha1-96")==0) {

	return 20;

    } else if (strcmp(name, "hmac-md5")==0 || strcmp(name, "hmac-md5-96")==0) {

	return 16;

    } else {
	unsigned int maclen=0;
	unsigned int algo=_get_mac(name, &maclen);

	return gcry_mac_get_algo_keylen(algo);

    }

    return 0;

}

static int _setkey(struct ssh_string_s *key, char *name, struct ssh_string_s *new)
{

    if (_get_mac_keylen(name)>0) {

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

void init_mac_libgcrypt(struct ssh_hmac_s *hmac)
{
    hmac->set_mac_s2c=_set_hmac_s2c;
    hmac->set_mac_c2s=_set_hmac_c2s;
    hmac->get_mac_keylen=_get_mac_keylen;
    hmac->setkey_c2s=_setkey;
    hmac->setkey_s2c=_setkey;
}

static signed char test_algo_libgcrypt(const char *name)
{
    signed char result=-1;

    if (strcmp(name, "chacha20-poly1305@openssh.com")==0) {

	result=-1;

    } else {
	unsigned int algo=0;

	algo=gcry_mac_map_name(name);

	if (algo>0) {

	    if (gcry_mac_test_algo(algo)==0) result=0;

	}

    }

    return result;
}

unsigned int ssh_get_mac_list_libgcrypt(struct commalist_s *clist)
{
    unsigned int len=0;

    if (test_algo_libgcrypt("chacha20-poly1305@openssh.com")==0) {

	len+=check_add_macname("chacha20-poly1305@openssh.com", clist);

    }

    if (gcry_mac_test_algo(GCRY_MAC_HMAC_SHA1)==0) {

	len+=check_add_macname("hmac-sha1", clist);

    }

    if (gcry_mac_test_algo(GCRY_MAC_HMAC_SHA256)==0) {

	len+=check_add_macname("hmac-sha256", clist);

    }

    if (gcry_mac_test_algo(GCRY_MAC_HMAC_MD5)==0) {

	len+=check_add_macname("hmac-md5", clist);

    }

    return len;

}
