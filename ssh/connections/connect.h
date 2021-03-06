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

#ifndef _SSH_CONNECTION_CONNECT_H
#define _SSH_CONNECTION_CONNECT_H

int create_ssh_networksocket(struct ssh_connection_s *connection, char *address, unsigned int port);
int connect_ssh_connection(struct ssh_connection_s *connection, char *address, unsigned int port);
void disconnect_ssh_connection(struct ssh_connection_s *connection);
int add_ssh_connection_eventloop(struct ssh_connection_s *connection, unsigned int fd, int (* read_incoming_data)(int fd, void *ptr, uint32_t events), unsigned int *error);
void remove_ssh_connection_eventloop(struct ssh_connection_s *connection);

#endif
