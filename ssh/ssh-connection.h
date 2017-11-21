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

#ifndef FS_WORKSPACE_SSH_CONNECTION_H
#define FS_WORKSPACE_SSH_CONNECTION_H

void init_ssh_connection(struct ssh_session_s *session);

int connect_ssh_server(struct ssh_session_s *session, char *address, unsigned int port);
signed char compare_session_connection(struct ssh_session_s *session, char *address, unsigned int port);
void disconnect_ssh_server(struct ssh_session_s *session);

int add_session_eventloop(struct ssh_session_s *session, struct context_interface_s *interface, unsigned int *error);
void remove_session_eventloop(struct ssh_session_s *session);

char *get_ssh_ipv4(struct ssh_session_s *session, unsigned char what, unsigned int *error);
char *get_ssh_hostname(struct ssh_session_s *session, unsigned char what, unsigned int *error);

int check_serverkey(struct ssh_session_s *session, struct ssh_key_s *hostkey);

#endif
