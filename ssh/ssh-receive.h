/*
  2010, 2011, 2012, 2013, 2014, 2015 Stef Bon <stefbon@gmail.com>

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

#ifndef FS_WORKSPACE_SSH_RECEIVE_H
#define FS_WORKSPACE_SSH_RECEIVE_H

typedef void (* receive_msg_cb_t)(struct ssh_session_s *session, struct ssh_payload_s *payload);

int get_payload_ssh_data(struct rawdata_s *data, struct ssh_payload_s *payload);
void process_ssh_message(struct ssh_session_s *session, struct ssh_payload_s *payload);

int init_receive(struct ssh_session_s *session, pthread_mutex_t *mutex, pthread_cond_t *cond, unsigned int *error);
void free_receive(struct ssh_session_s *session);

void start_processing_queue(struct ssh_session_s *session);

void register_msg_cb(unsigned char type, receive_msg_cb_t cb);

void switch_receive_process(struct ssh_session_s *session, const char *phase);

int read_incoming_data(int fd, void *ptr, uint32_t events);

#endif
