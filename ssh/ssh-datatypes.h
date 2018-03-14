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

#ifndef FS_WORKSPACE_SSH_DATATYPES_H
#define FS_WORKSPACE_SSH_DATATYPES_H

#define _PUBKEY_METHOD_NONE		0
#define _PUBKEY_METHOD_PRIVATE		1
#define _PUBKEY_METHOD_SSH_DSS		2
#define _PUBKEY_METHOD_SSH_RSA		4
#define _PUBKEY_METHOD_SSH_ED25519	8

#define _PUBKEY_FORMAT_NONE		0
#define _PUBKEY_FORMAT_OPENSSH_KEY	1
#define _PUBKEY_FORMAT_SSH		2
#define _PUBKEY_FORMAT_DER		3

struct ssh_string_s {
    unsigned int			flags;
    unsigned int			len;
    char				*ptr;
};

struct commalist_s {
    char 				*list;
    unsigned int 			len;
    unsigned int 			size;
};

struct ssh_pkalgo_s {
    unsigned int			type;
    const char				*name;
    unsigned int			len;
};

struct ssh_key_s {
    unsigned int			type;
    unsigned int			format;
    struct common_buffer_s		data;
    void				*ptr;
    void				(* free_ptr)(struct ssh_key_s *key);
};

/* prototypes */

#endif
