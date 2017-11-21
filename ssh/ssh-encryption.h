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

#ifndef FS_WORKSPACE_SSH_ENCRYPTION_H
#define FS_WORKSPACE_SSH_ENCRYPTION_H

void init_encryption(struct ssh_session_s *session);

int set_encryption(struct ssh_session_s *session, const char *name, unsigned int *error);
int set_decryption(struct ssh_session_s *session, const char *name, unsigned int *error);

int ssh_encrypt(struct ssh_session_s *session, struct ssh_packet_s *packet);
int ssh_decrypt_length(struct rawdata_s *data, unsigned char *buffer, unsigned int len);
int ssh_decrypt_packet(struct rawdata_s *data);
void reset_encrypt(struct ssh_session_s *session);
void reset_decrypt(struct ssh_session_s *session);
void close_encrypt(struct ssh_session_s *session);
void close_decrypt(struct ssh_session_s *session);
void free_encrypt(struct ssh_session_s *session);
void free_decrypt(struct ssh_session_s *session);

unsigned int get_cipher_blocksize_c2s(struct ssh_session_s *session);
unsigned int get_cipher_blocksize_s2c(struct ssh_session_s *session);
unsigned int get_cipher_ivsize_c2s(struct ssh_session_s *session);
unsigned int get_cipher_ivsize_s2c(struct ssh_session_s *session);

unsigned int check_add_ciphername(const char *name, struct commalist_s *clist);
unsigned int ssh_get_cipher_list(struct commalist_s *clist);

unsigned int get_cipher_keysize(struct ssh_session_s *session, const char *name);
unsigned int get_cipher_blocksize(struct ssh_session_s *session, const char *name);
unsigned int get_cipher_ivsize(struct ssh_session_s *session, const char *name);

int set_cipher_key_c2s(struct ssh_session_s *session, char *name, struct ssh_string_s *key);
int set_cipher_key_s2c(struct ssh_session_s *session, char *name, struct ssh_string_s *key);

int set_cipher_iv_c2s(struct ssh_session_s *session, char *name, struct ssh_string_s *key);
int set_cipher_iv_s2c(struct ssh_session_s *session, char *name, struct ssh_string_s *key);

unsigned char get_message_padding(struct ssh_session_s *session, unsigned int len, unsigned int blocksize);
unsigned int get_size_firstbytes(struct ssh_session_s *session);

#endif
