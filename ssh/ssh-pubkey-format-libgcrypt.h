/*
  2010, 2011, 2012, 2013, 2014, 2015, 2016, 2017 Stef Bon <stefbon@gmail.com>

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

#ifndef FS_WORKSPACE_SSH_PUBKEY_FORMATS_LIBGCRYPT_H
#define FS_WORKSPACE_SSH_PUBKEY_FORMATS_LIBGCRYPT_H

int read_parameters_public_rsa_ssh_libgcrypt(struct ssh_key_s *key, unsigned int *error);
int read_parameters_public_dss_ssh_libgcrypt(struct ssh_key_s *key, unsigned int *error);
int read_parameters_public_ed25519_ssh_libgcrypt(struct ssh_key_s *key, unsigned int *error);

int read_private_rsa_ASN1_libgcrypt(struct ssh_key_s *key, unsigned int *error);
int read_private_dss_ASN1_libgcrypt(struct ssh_key_s *key, unsigned int *error);
int read_private_ed25519_openssh_libgcrypt(struct ssh_key_s *key, unsigned int *error);
int read_private_openssh_key(struct ssh_key_s *key, unsigned int *error);

int read_parameters_private_key(struct ssh_key_s *key, unsigned int *error);

#endif
