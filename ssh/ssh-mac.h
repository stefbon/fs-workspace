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

#ifndef FS_WORKSPACE_SSH_MAC_H
#define FS_WORKSPACE_SSH_MAC_H

void init_mac(struct ssh_session_s *session);

int set_hmac_s2c(struct ssh_session_s *session, const char *name, unsigned int *error);

void reset_s2c_mac(struct ssh_session_s *session);
int verify_mac_pre_decrypt(struct rawdata_s *data);
int verify_mac_post_decrypt(struct rawdata_s *data);
void free_s2c_mac(struct ssh_session_s *session);

int set_hmac_c2s(struct ssh_session_s *session, const char *name, unsigned int *error);

void reset_c2s_mac(struct ssh_session_s *session);
void write_mac_pre_encrypt(struct ssh_session_s *session, struct ssh_packet_s *packet);
void write_mac_post_encrypt(struct ssh_session_s *session, struct ssh_packet_s *packet);
ssize_t send_c2s(struct ssh_session_s *session, struct ssh_packet_s *packet);
void free_c2s_mac(struct ssh_session_s *session);

unsigned int get_maclen_c2s(struct ssh_session_s *session);
unsigned int get_maclen_s2c(struct ssh_session_s *session);

int set_mac_key_c2s(struct ssh_session_s *session, char *name, struct ssh_string_s *key);
int set_mac_key_s2c(struct ssh_session_s *session, char *name, struct ssh_string_s *key);

unsigned int get_mac_keylen(struct ssh_session_s *session, const char *name);

unsigned int ssh_get_mac_list(struct commalist_s *clist);

#endif
