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

#if HAVE_LIBGCRYPT
#include <gcrypt.h>
#endif

#include "ssh-datatypes.h"

/* layout of the data containing keymaterial (headers, footer, encoding, ...)
    as used for example to store private keys in files */

#define PK_DATA_LAYOUT_OPENSSH					1

/* the way key parameters are stored */

/* only parameters, no header for size */

#define PK_DATA_FORMAT_PARAM					1

/* format SSH defined by protocol SSH
    is writing parameters including 4 bytes header for length */

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

struct ssh_key_s {
    struct ssh_pkalgo_s			*algo;
    unsigned char			secret;
    unsigned int			format;
    struct common_buffer_s		data;
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
    } param;
    void				(* set_algo)(struct ssh_key_s *key, struct ssh_pkalgo_s *algo);
    void				(* free_param)(struct ssh_key_s *key);
    int 				(* read_key)(struct ssh_key_s *key, char *buffer, unsigned int size, unsigned int format, unsigned int *error);
    int					(* write_key)(struct ssh_key_s *key, char *buffer, unsigned int size, unsigned int format, unsigned int *error);
    int 				(* sign)(struct ssh_key_s *key, char *b, unsigned int size, struct ssh_string_s *sig, const char *hashname, unsigned int *error);
    int					(* verify)(struct ssh_key_s *key, char *b, unsigned int size, struct ssh_string_s *sig, const char *hashname, unsigned int *error);
    int					(* compare_keys)(struct ssh_key_s *a, struct ssh_key_s *b);
    int					(* compare_key_data)(struct ssh_key_s *a, char *buffer, unsigned int len, unsigned int format);
};

/* prototypes */

void init_ssh_key(struct ssh_key_s *key, unsigned char secret, struct ssh_pkalgo_s *algo);
void free_ssh_key(struct ssh_key_s *key);

#endif
