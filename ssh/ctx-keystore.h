/*
  2010, 2011, 2012, 2013, 2014, 2015, 2016 Stef Bon <stefbon@gmail.com>

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

#ifndef CTX_KEYSTORE_H
#define CTX_KEYSTORE_H

#include <pwd.h>
#include "simple-list.h"

#define _IDENTITY_FLAG_GENERIC					1
#define _IDENTITY_FLAG_USER					2
#define _IDENTITY_FLAG_OPENSSH					4
#define _IDENTITY_FLAG_WILDCARD					8
#define _IDENTITY_FLAG_DEFAULT					16

#define _KNOWN_HOST_FLAG_HOSTCOMMASEPERATED			1
#define _KNOWN_HOST_FLAG_KEYBASE64ENCODED			2

#define _HOSTADDRESS_TYPE_IPV4					1
#define _HOSTADDRESS_TYPE_IPV6					2

struct hostaddress_s {
    unsigned char			type;
    char				*hostname;
    char				*ip;
};

struct common_identity_s {
    unsigned int			flags;
    void				*ptr;
    char				*file;
    char				*user;
    struct list_element_s		list;
};

struct known_host_s {
    unsigned int			flags;
    char				*host;
    char				*type;
    char				*key;
};

void *init_identity_records(struct passwd *pwd, struct hostaddress_s *hostaddress, const char *what, unsigned int *error);
struct common_identity_s *get_next_identity_record(void *ptr);
int get_public_key(struct common_identity_s *i, char *b, unsigned int l);
int get_private_key(struct common_identity_s *i, char *b, unsigned int l);
void free_identity_record(struct common_identity_s *i);
void finish_identity_records(void *ptr);

void *init_known_hosts(struct passwd *pwd, unsigned int *error);
struct known_host *get_next_known_host(void *ptr, unsigned int *error);
void finish_known_hosts(void *ptr);

#endif
