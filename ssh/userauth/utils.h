/*
  2016, 2017, 2018 Stef Bon <stefbon@gmail.com>

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

#ifndef _SSH_USERAUTH_UTILS_H
#define _SSH_USERAUTH_UTILS_H

#define PW_TYPE_GLOBAL		1
#define PW_TYPE_DOMAIN		2
#define PW_TYPE_HOSTNAME	3
#define PW_TYPE_IPV4		4

struct pword_s {
    char			*user;
    char			*pw;
};

struct pw_list_s {
    unsigned char		type;
    struct pword_s		pword;
    struct pw_list_s		*next;
};

/* prototypes */

int handle_auth_failure(struct ssh_payload_s *payload, struct ssh_auth_s *auth);

unsigned int read_private_pwlist(struct ssh_connection_s *c, struct pw_list_s **pwlist);
struct pw_list_s *get_next_pwlist(struct pw_list_s *pwlist, struct pw_list_s *element);
void free_pwlist(struct pw_list_s *pwlist);
int handle_auth_reply(struct ssh_connection_s *connection, struct ssh_payload_s *payload);

#endif
