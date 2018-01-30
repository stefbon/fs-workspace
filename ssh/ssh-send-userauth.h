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

#ifndef FS_WORKSPACE_SSH_SEND_USERAUTH_H
#define FS_WORKSPACE_SSH_SEND_USERAUTH_H

/* prototypes */

unsigned int write_userauth_pubkey_request(struct common_buffer_s *buffer, struct ssh_string_s *user, const char *service, struct ssh_key_s *public_key);
int send_userauth_pubkey_message(struct ssh_session_s *session, struct ssh_string_s *user, const char *service, struct ssh_key_s *public_key, struct ssh_string_s *sig, unsigned int *seq);

int send_userauth_none_message(struct ssh_session_s *session, struct ssh_string_s *user, const char *service, unsigned int *seq);

unsigned int write_userauth_hostbased_request(struct common_buffer_s *buffer, struct ssh_string_s *ruser, const char *service, struct ssh_key_s *key, struct ssh_string_s *hostname, struct ssh_string_s *luser);
int send_userauth_hostbased_message(struct ssh_session_s *session, struct ssh_string_s *ruser, const char *service, struct ssh_key_s *key, struct ssh_string_s *hostname, struct ssh_string_s *luser, struct ssh_string_s *signature, unsigned int *seq);

#endif
