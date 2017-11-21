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

#ifndef CTX_KEYSTORE_OPENSSH_H
#define CTX_KEYSTORE_OPENSSH_H

#include <pwd.h>

#define _OPENSSH_CONFIG_SYSTEM 					0
#define _OPENSSH_CONFIG_USER					1

struct public_keys_s {
    unsigned int		flags;
    struct passwd		*pwd;
    struct list_element_s	*head;
    struct list_element_s	*tail;
};

/* prototypes */

void *init_identity_records_openssh(struct passwd *pwd, struct hostaddress_s *hostaddress, const char *what, unsigned int *error);
struct common_identity_s *get_next_identity_openssh(void *ptr);
void free_identity_record_openssh(struct common_identity_s *identity);
int get_public_key_openssh(struct common_identity_s *i, char *b, unsigned int l);
int get_private_key_openssh(struct common_identity_s *i, char *b, unsigned int l);
void finish_identity_records_openssh(void *ptr);

#endif
