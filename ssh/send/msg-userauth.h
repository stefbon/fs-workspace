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

#ifndef _SSH_SEND_USERAUTH_H
#define _SSH_SEND_USERAUTH_H

/* prototypes */

void msg_write_userauth_pubkey_request(struct msg_buffer_s *mb, char *r_user, const char *service, struct ssh_key_s *pkey, struct ssh_pksign_s *sign, struct ssh_string_s *sig);
int send_userauth_pubkey_message(struct ssh_connection_s *c, char *ruser, const char *service, struct ssh_key_s *pkey, struct ssh_pksign_s *pksign, struct ssh_string_s *sig, unsigned int *seq);

void msg_write_userauth_none_message(struct msg_buffer_s *mb, char *r_user, char *service);
int send_userauth_none_message(struct ssh_connection_s *c, char *user, const char *service, unsigned int *seq);

void msg_write_userauth_hostbased_request(struct msg_buffer_s *mb, char *r_user, const char *service, struct ssh_key_s *pkey, char *l_hostname, char *l_user);
int send_userauth_hostbased_message(struct ssh_connection_s *c, char *ruser, const char *service, struct ssh_key_s *key, char *lhostname, char *luser, struct ssh_string_s *signature, unsigned int *seq);

int send_userauth_password_message(struct ssh_connection_s *c, char *user, char *pw, const char *service, unsigned int *seq);

#endif
