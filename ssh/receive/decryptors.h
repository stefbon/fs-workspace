/*
  2017, 2018 Stef Bon <stefbon@gmail.com>

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

#ifndef FS_WORKSPACE_SSH_RECEIVE_DECRYPTORS_H
#define FS_WORKSPACE_SSH_RECEIVE_DECRYPTORS_H

struct ssh_decryptor_s *get_decryptor_container(struct list_element_s *list);
struct ssh_decryptor_s *get_decryptor_unlock(struct ssh_receive_s *r, unsigned int *error);
void queue_decryptor(struct ssh_decryptor_s *decryptor);
void remove_decryptors(struct ssh_decrypt_s *decrypt);

void init_decryptors_once();

#endif
