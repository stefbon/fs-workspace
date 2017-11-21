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

#ifndef FS_WORKSPACE_SSH_QUEUE_PAYLOAD_H
#define FS_WORKSPACE_SSH_QUEUE_PAYLOAD_H

struct ssh_payload_s *get_ssh_payload(struct ssh_session_s *session, struct timespec *expire, unsigned int *sequence, unsigned int *error);
void queue_ssh_packet(struct ssh_session_s *session, struct ssh_packet_s *packet);

int init_receive_payload_queue(struct ssh_session_s *session, pthread_mutex_t *mutex, pthread_cond_t *cond);
void clean_receive_payload_queue(struct ssh_receive_s *receive);

void free_receive_payload_queue(struct ssh_receive_s *receive);

void switch_process_payload_queue(struct ssh_session_s *session, const char *phase);

#endif
