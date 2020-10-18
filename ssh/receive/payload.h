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

#ifndef _SSH_RECEIVE_PAYLOAD_H
#define _SSH_RECEIVE_PAYLOAD_H

struct ssh_payload_s *get_ssh_payload(struct ssh_connection_s *c, struct payload_queue_s *queue, struct timespec *expire, unsigned int *sequence, unsigned int *error);
void queue_ssh_payload_locked(struct payload_queue_s *queue, struct ssh_payload_s *payload);
void queue_ssh_payload(struct payload_queue_s *queue, struct ssh_payload_s *payload);
void init_payload_queue(struct ssh_connection_s *c, struct payload_queue_s *queue);
void clear_payload_queue(struct payload_queue_s *queue, unsigned char dolog);
struct ssh_payload_s *receive_message_common(struct ssh_connection_s *connection, int (* cb)(struct ssh_connection_s *connection, struct ssh_payload_s *payload), unsigned int *error);

#endif
