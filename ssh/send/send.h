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

#ifndef FS_WORKSPACE_SSH_SEND_SEND_H
#define FS_WORKSPACE_SSH_SEND_SEND_H

void set_send_behaviour(struct ssh_send_s *send, const char *what);
void signal_send_disconnect(struct ssh_send_s *send);
int write_ssh_packet(struct ssh_session_s *session, struct ssh_payload_s *payload, unsigned int *seq);
int write_ssh_packet_kexinit(struct ssh_session_s *session, struct ssh_payload_s *payload, unsigned int *seq);
int write_ssh_packet_newkeys(struct ssh_session_s *session, struct ssh_payload_s *payload, unsigned int *seq);
int write_ssh_packet_kexinit(struct ssh_session_s *session, struct ssh_payload_s *payload, unsigned int *seq);
int request_ssh_service(struct ssh_session_s *session, const char *service, struct payload_queue_s *queue);

#endif
