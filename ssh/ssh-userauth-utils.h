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

#ifndef FS_WORKSPACE_SSH_USERAUTH_UTILS_H
#define FS_WORKSPACE_SSH_USERAUTH_UTILS_H

/* prototypes */

unsigned int get_required_auth_methods(unsigned char *namelist, unsigned int len);
void log_userauth_banner(struct ssh_payload_s *payload);
int handle_userauth_failure_message(struct ssh_session_s *session, struct ssh_payload_s *payload, unsigned int *methods);

int read_public_key_helper(struct common_identity_s *identity, struct ssh_key_s *key);
int read_private_key_helper(struct common_identity_s *identity, struct ssh_key_s *key);

#endif
