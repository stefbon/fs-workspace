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

#ifndef FS_WORKSPACE_SSH_RECEIVE_INIT_H
#define FS_WORKSPACE_SSH_RECEIVE_INIT_H

void register_msg_cb(unsigned char type, receive_msg_cb_t cb);
void process_cb_ssh_payload(struct ssh_session_s *session, struct ssh_payload_s *payload);

int init_receive(struct ssh_session_s *session, pthread_mutex_t *mutex, pthread_cond_t *cond, unsigned int *error);
void free_receive(struct ssh_session_s *session);

void set_receive_behaviour(struct ssh_receive_s *receive, const char *what);
void finish_receive_newkeys(struct ssh_receive_s *receive);
int wait_for_newkeys_to_complete(struct ssh_receive_s *receive);
void signal_receive_disconnect(struct ssh_receive_s *receive);
void start_receive_kexinit(struct ssh_receive_s *receive);

int init_once();

#endif
