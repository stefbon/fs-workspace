/*
  2010, 2011, 2012, 2013, 2014, 2015, 2016, 2017 Stef Bon <stefbon@gmail.com>

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

#ifndef FS_WORKSPACE_SSH_PK_KEYS_H
#define FS_WORKSPACE_SSH_PK_KEYS_H

#include "ssh-datatypes.h"
#include "pk-types.h"

/* layout of the data containing keymaterial (headers, footer, encoding, ...)
    as used for example to store private keys in files */

#define PK_DATA_LAYOUT_OPENSSH					1

/* the way key parameters are stored */

/* only parameters, no header for size and no name for algo */

#define PK_DATA_FORMAT_PARAM					1

/* format SSH defined by protocol SSH
    - first string is name of algo
    - every parameter is written with 4 bytes header for length */

#define PK_DATA_FORMAT_SSH					2

/* as PK_DATA_FORMAT_SSH, with a 4 byte header for the total length of the keymaterial */

#define PK_DATA_FORMAT_SSH_STRING				3

/* format DER/ASN1 is used by openssh/openssl to store private keys */

#define PK_DATA_FORMAT_DERASN1					4

/* format openssh key is used by openssh to store private keys
    it's a successor of the DER/ASN1 format */

#define PK_DATA_FORMAT_OPENSSH_KEY				5

/* public or private/secret */

#define SSH_KEY_TYPE_PUBLIC					0
#define SSH_KEY_TYPE_PRIVATE					1

/* hostkey is a pk or cert*/

#define SSH_HOSTKEY_TYPE_PK					1
#define SSH_HOSTKEY_TYPE_OPENSSH_COM_CERT			2

struct ssh_key_s {
    struct ssh_pkalgo_s			*algo;
    unsigned char			secret;
    struct ssh_pkoptions_s		options;
    union {
	struct rsa_param_s {
	    struct ssh_mpint_s		n;
	    struct ssh_mpint_s		e;
	    struct ssh_mpint_s		d;
	    struct ssh_mpint_s		p;
	    struct ssh_mpint_s		q;
	    struct ssh_mpint_s		u;
	} rsa;
	struct dss_param_s {
	    struct ssh_mpint_s		p;
	    struct ssh_mpint_s		q;
	    struct ssh_mpint_s		g;
	    struct ssh_mpint_s		y;
	    struct ssh_mpint_s		x;
	} dss;
	struct ecc_param_s {
	    struct ssh_mpoint_s		q;
	    struct ssh_mpint_s		d;
	} ecc;
    } param;
    void				(* set_algo)(struct ssh_key_s *key, struct ssh_pkalgo_s *algo);
    void				(* free_param)(struct ssh_key_s *key);
    int 				(* read_key)(struct ssh_key_s *key, char *buffer, unsigned int size, unsigned int format, unsigned int *error);
    int					(* write_key)(struct ssh_key_s *key, char *buffer, unsigned int size, unsigned int format, unsigned int *error);
    void 				(* msg_write_key)(struct msg_buffer_s *mb, struct ssh_key_s *pkey, unsigned int format);
    void 				(* msg_read_key)(struct msg_buffer_s *mb, struct ssh_key_s *pkey, unsigned int format);
    int 				(* sign)(struct ssh_key_s *key, char *b, unsigned int size, struct ssh_string_s *sig, const char *hashname, unsigned int *error);
    int					(* verify)(struct ssh_key_s *key, char *b, unsigned int size, struct ssh_string_s *sig, const char *hashname, unsigned int *error);
    int					(* compare_keys)(struct ssh_key_s *a, struct ssh_key_s *b);
    int					(* compare_key_data)(struct ssh_key_s *a, char *buffer, unsigned int len, unsigned int format);
};

struct openssh_cert_s {
    struct ssh_pkcert_s			*pkcert;
    struct ssh_string_s			nonce;
    struct ssh_key_s			key;
    uint64_t				serial;
    uint32_t				type;
    struct ssh_string_s			key_id;
    struct ssh_string_s			valid_principals;
    uint64_t				valid_after;
    uint64_t				valid_before;
    struct ssh_string_s			critical_options;
    struct ssh_string_s			extensions;
    struct ssh_string_s			reserved;
    struct ssh_string_s			signature_key;
    struct ssh_string_s			signature;
};

struct ssh_hostkey_s {
    unsigned int			type;
    union {
	struct openssh_cert_s		openssh_cert;
	struct ssh_key_s		key;
    } data;
};

/* prototypes */

void init_ssh_key(struct ssh_key_s *key, unsigned char secret, struct ssh_pkalgo_s *algo);
void free_ssh_key(struct ssh_key_s *key);
void msg_write_pkey(struct msg_buffer_s *mb, struct ssh_key_s *key, unsigned int format);

void msg_read_pkey(struct msg_buffer_s *mb, struct ssh_key_s *key, unsigned int format);
void msg_read_skey(struct msg_buffer_s *mb, struct ssh_key_s *key, unsigned int format);

#endif
