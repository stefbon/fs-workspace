/*
  2018 Stef Bon <stefbon@gmail.com>

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

#ifndef _SSH_SEND_ENCRYPT_H
#define _SSH_SEND_ENCRYPT_H

struct encrypt_ops_s *get_encrypt_ops_container(struct list_element_s *list);
void add_encrypt_ops(struct encrypt_ops_s *ops);
struct encrypt_ops_s *get_next_encrypt_ops(struct encrypt_ops_s *ops);

void reset_encrypt(struct ssh_connection_s *c, struct algo_list_s *algo_cipher, struct algo_list_s *algo_hmac);

unsigned int build_cipher_list_c2s(struct ssh_connection_s *c, struct algo_list_s *alist, unsigned int start);
unsigned int build_hmac_list_c2s(struct ssh_connection_s *c, struct algo_list_s *alist, unsigned int start);

#endif
