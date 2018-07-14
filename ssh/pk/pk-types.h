/*
  2010, 2011, 2012, 2013, 2014, 2015, 2016, 2017, 2018 Stef Bon <stefbon@gmail.com>

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

#ifndef FS_WORKSPACE_SSH_PK_TYPES_H
#define FS_WORKSPACE_SSH_PK_TYPES_H

#define SSH_PKALGO_SCHEME_RSA				1
#define SSH_PKALGO_SCHEME_DSS				2
#define SSH_PKALGO_SCHEME_ECC				3

#define SSH_PKALGO_ID_DSS				1
#define SSH_PKALGO_ID_RSA				2
#define SSH_PKALGO_ID_ED25519				3
#define SSH_PKALGO_ID_CURVE25519			4

#define SSH_PKALGO_FLAG_PREFERRED			1
#define SSH_PKALGO_FLAG_SKIP				2
#define SSH_PKALGO_FLAG_SYSTEM				4

/* rsa options */

#define SSH_PKALGO_OPTION_RSA_BITS_UNKNOWN		1
#define SSH_PKALGO_OPTION_RSA_BITS_1024			2
#define SSH_PKALGO_OPTION_RSA_BITS_2048			4

/* dss options */

#define SSH_PKALGO_OPTION_DSS_BITS_UNKNOWN		1
#define SSH_PKALGO_OPTION_DSS_BITS_1024			2
#define SSH_PKALGO_OPTION_DSS_BITS_2048			4

/* ecc flags
    ecc does not use bits */

/* flags for pk sign */

#define SSH_PKSIGN_FLAG_DEFAULT				1
#define SSH_PKSIGN_FLAG_RECOMMENDED			2
#define SSH_PKSIGN_FLAG_OPTIONAL			3

#define SSH_PKCERT_ID_RSA_CERT_V01_OPENSSH_COM		1
#define SSH_PKCERT_ID_DSS_CERT_V01_OPENSSH_COM		2
#define SSH_PKCERT_ID_ED25519_CERT_V01_OPENSSH_COM	3

/* flags for certificates */

#define SSH_PKCERT_FLAG_HOST				1
#define SSH_PKCERT_FLAG_USER				2
#define SSH_PKCERT_FLAG_OPENSSH_COM_CERTIFICATE		4
#define SSH_PKCERT_FLAG_SYSTEM				8

#define SSH_PKAUTH_TYPE_PKALGO				1
#define SSH_PKAUTH_TYPE_PKCERT				2

struct ssh_pksign_s {
    unsigned int			flags;
    const char				*name;
    unsigned int			keyid;
    unsigned char			hash;
};

struct ssh_pkalgo_s {
    unsigned int			flags;
    unsigned int			scheme;
    unsigned int			id;
    const char				*name;
    const char				*libname;
    unsigned int			len;
};

struct ssh_pkcert_s {
    unsigned int 			flags;
    unsigned int			id;
    unsigned int			pkalgo_id;
    const char				*name;
    const char				*libname;
    unsigned int			len;
};

struct ssh_pkoptions_s {
    unsigned int			options;
};

struct ssh_pkauth_s {
    unsigned int			type;
    union {
	struct ssh_pkalgo_s		*pkalgo;
	struct ssh_pkcert_s		*pkcert;
    } method;
};

void copy_pkalgo(struct ssh_pkalgo_s *a, struct ssh_pkalgo_s *b);
void set_pkoptions(struct ssh_pkoptions_s *options, struct ssh_pkalgo_s *pkalgo, unsigned int o);

struct ssh_pkalgo_s *get_pkalgo(char *algo, unsigned int len, int *index);
struct ssh_pkalgo_s *get_pkalgo_string(struct ssh_string_s *s, int *index);
struct ssh_pkalgo_s *get_pkalgo_byid(unsigned int id, int *index);

struct ssh_pkcert_s *get_pkcert(char *name, unsigned int len, int *index);
struct ssh_pkcert_s *get_pkcert_string(struct ssh_string_s *s, int *index);
struct ssh_pkcert_s *get_pkcert_byid(unsigned int id, int *index);

int get_index_pkalgo(struct ssh_pkalgo_s *algo);
struct ssh_pkalgo_s *get_next_pkalgo(struct ssh_pkalgo_s *algo, int *index);

struct ssh_pkcert_s *get_next_pkcert(struct ssh_pkcert_s *cert, int *index);
int get_index_pkcert(struct ssh_pkcert_s *cert);

unsigned int write_pkalgo(char *buffer, struct ssh_pkalgo_s *pkalgo);
void msg_write_pkalgo(struct msg_buffer_s *mb, struct ssh_pkalgo_s *pkalgo);
struct ssh_pkalgo_s *read_pkalgo(char *buffer, unsigned int size, int *read);
struct ssh_pkalgo_s *read_pkalgo_string(struct ssh_string_s *algo, int *read);

void msg_write_pkcert(struct msg_buffer_s *mb, struct ssh_pkcert_s *pkcert);
struct ssh_pkcert_s *read_pkcert(char *buffer, unsigned int size, int *read);
struct ssh_pkcert_s *read_pkcert_string(struct ssh_string_s *name, int *read);

struct ssh_pksign_s *get_default_pksign(struct ssh_pkalgo_s *algo);
struct ssh_pksign_s *get_next_pksign(struct ssh_pkalgo_s *algo, struct ssh_pksign_s *pksign, int *index);
int get_index_pksign(struct ssh_pksign_s *pksign);
struct ssh_pksign_s *check_signature_algo(struct ssh_pkalgo_s *p, struct ssh_string_s *s, int (* select_cb)(void *ptr, char *p, char *s), void *ptr);

void msg_read_pksignature(struct msg_buffer_s *mb, struct ssh_string_s *pksign, struct ssh_string_s *signature);
void msg_write_pksign(struct msg_buffer_s *mb, struct ssh_pksign_s *pksign);
void msg_write_pksignature(struct msg_buffer_s *mb, struct ssh_pksign_s *pksign, struct ssh_string_s *signature);

const char *get_hashname_sign(struct ssh_pksign_s *pksign);

#endif
