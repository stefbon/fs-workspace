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

#ifndef FS_WORKSPACE_SSH_PUBKEY_H
#define FS_WORKSPACE_SSH_PUBKEY_H

int read_parameters_pubkey(struct ssh_session_s *session, struct ssh_key_s *key, unsigned int *error);
int verify_sigH(struct ssh_session_s *session, struct ssh_key_s *key, struct common_buffer_s *hash, struct common_buffer_s *sigH);
int create_signature(struct ssh_session_s *session, struct ssh_key_s *key, struct common_buffer_s *data, struct ssh_string_s *signature, unsigned int *error);

void init_pubkey(struct ssh_session_s *session);
int set_pubkey(struct ssh_session_s *session, const char *name, unsigned int *error);
void free_pubkey(struct ssh_session_s *session);

unsigned int check_add_pubkeyname(const char *name, struct commalist_s *clist);
unsigned int ssh_get_pubkey_list(struct commalist_s *clist);

#endif
