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

#ifndef FS_WORKSPACE_SSH_PK_KEYSTORE_H
#define FS_WORKSPACE_SSH_PK_KEYSTORE_H

/* define the different sources of public keys
    - public keys stored in files by openssh ($HOME/.ssh/id_rsa.pub)
    - ....

    what sources are there? ssh-agent? a special daemon? gnome-keyring?
*/

#define PK_IDENTITY_SOURCE_OPENSSH_LOCAL			1

#define PK_IDENTITY_SCOPE_HOST					0
#define PK_IDENTITY_SCOPE_USER					1

/* key is found by just looking at standard locations */
#define PK_IDENTITY_FLAG_OPENSSH_STANDARD			1
/* key is found by parsing the config files */
#define PK_IDENTITY_FLAG_OPENSSH_CONFIG				2
/* key is found in the config by using a wildcard */
#define PK_IDENTITY_FLAG_OPENSSH_WILDCARD			4
/* key is found in the config by using the default section */
#define PK_IDENTITY_FLAG_OPENSSH_DEFAULT			8

struct pk_list_s {
    unsigned int			flags;
    struct passwd			*pwd;
    struct list_header_s		user_list_header;
    struct list_header_s		host_list_header;
};

struct pk_identity_s {
    unsigned char			source;
    unsigned char			scope;
    union {
	struct openssh_local_s	{
	    char			*file;
	    char			*user;
	    unsigned int		flags;
	} openssh_local;
    } pk;
    struct list_element_s		list;
    struct pk_list_s			*pk_list;
    unsigned int			size;
    char				buffer[];
};

void free_lists_public_keys(struct pk_list_s *pkeys);
void init_list_public_keys(struct passwd *pwd, struct pk_list_s *pkeys);
int populate_list_public_keys(struct pk_list_s *pkeys, unsigned char source, const char *what);

struct pk_identity_s *get_next_pk_identity(struct pk_list_s *pkeys, const char *what);
struct pk_identity_s *create_pk_identity(struct pk_list_s *pk_list, unsigned char source, unsigned char scope, unsigned int size);

char *get_pk_identity_file(struct pk_identity_s *identity);
char *get_pk_identity_user(struct pk_identity_s *identity);

int read_key_param(struct pk_identity_s *identity, struct ssh_key_s *key);

#endif
