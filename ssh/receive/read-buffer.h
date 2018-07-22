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

#ifndef FS_WORKSPACE_SSH_RECEIVE_READ_BUFFER_H
#define FS_WORKSPACE_SSH_RECEIVE_READ_BUFFER_H

void process_ssh_packet_nodecompress(struct ssh_session_s *session, struct ssh_packet_s *packet);
void process_ssh_packet_decompress(struct ssh_session_s *session, struct ssh_packet_s *packet);

void read_ssh_buffer_packet(void *ptr);
void read_ssh_buffer_greeter(void *ptr);
void read_ssh_buffer_none(void *ptr);

void read_ssh_buffer(struct ssh_session_s *session);
void switch_read_ssh_buffer(struct ssh_session_s *session, const char *phase);

#endif