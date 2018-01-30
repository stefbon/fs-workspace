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

#ifndef FS_WORKSPACE_SSH_DATA_H
#define FS_WORKSPACE_SSH_DATA_H

void init_ssh_algo(struct ssh_kexinit_algo *algo);

int store_kexinit_server(struct ssh_session_s *session, struct ssh_payload_s *payload, unsigned int *error);
int store_kexinit_client(struct ssh_session_s *session, struct ssh_payload_s *payload, unsigned int *error);

void free_kexinit_server(struct ssh_session_s *session);
void free_kexinit_client(struct ssh_session_s *session);

int store_ssh_session_id(struct ssh_session_s *session, unsigned char *id, unsigned int len);

void init_keydata(struct session_keydata_s *keydata);
void free_keydata(struct session_keydata_s *keydata);

void init_session_data(struct ssh_session_s *session);
void free_session_data(struct ssh_session_s *session);

#endif
