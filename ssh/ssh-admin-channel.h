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

#ifndef FS_WORKSPACE_SSH_ADMIN_CHANNEL_H
#define FS_WORKSPACE_SSH_ADMIN_CHANNEL_H

/* prototypes */

int start_remote_shell_admin(struct ssh_channel_s *channel);
unsigned int start_shell_command_remote(struct ssh_channel_s *channel, char *command, struct server_reply_s *server_reply, struct timespec *send, struct timespec *received);
unsigned int run_command_remote(struct ssh_session_s *session, char *command, struct server_reply_s *server_reply, struct timespec *send, struct timespec *received);

unsigned int get_timeinfo_server(struct ssh_session_s *session, unsigned char *buffer, unsigned int len, struct timespec *send, struct timespec *recv, unsigned int *error);
unsigned int get_ssh_interface_info(struct context_interface_s *interface, const char *what, void *data, unsigned char *buffer, unsigned int size, unsigned int *error);

#endif
