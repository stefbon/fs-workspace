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

#ifndef FS_WORKSPACE_SSH_ENCRYPTION_CHACHA20_POLY1305_LIBGCRYPT_H
#define FS_WORKSPACE_SSH_ENCRYPTION_CHACHA20_POLY1305_LIBGCRYPT_H

unsigned int _get_cipher_blocksize_chacha20_poly1305();
unsigned int _get_cipher_keysize_chacha20_poly1305();
unsigned int _get_cipher_ivsize_chacha20_poly1305();

int _set_encryption_c2s_chacha20_poly1305(struct ssh_encryption_s *encryption, unsigned int *error);
int _set_encryption_s2c_chacha20_poly1305(struct ssh_encryption_s *encryption, unsigned int *error);

signed char test_algo_chacha20_poly1305();

#endif
