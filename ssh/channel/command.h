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

#ifndef _SSH_CHANNEL_COMMAND_H
#define _SSH_CHANNEL_COMMAND_H

/* prototypes */

unsigned int get_result_common(struct ssh_session_s *session, const char *command, struct common_buffer_s *buffer);

unsigned int get_timeinfo_server(struct ssh_session_s *session, struct common_buffer_s *buffer, struct timespec *send, struct timespec *recv);
unsigned int get_ssh_interface_info(struct context_interface_s *interface, const char *what, void *data, struct common_buffer_s *buffer);

unsigned int get_supported_services(struct ssh_session_s *session, struct common_buffer_s *b);

#endif
