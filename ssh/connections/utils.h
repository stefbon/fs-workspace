/*
  2010, 2011, 2012, 2013, 2014, 2015, 2016, 2017, 2018, 2019, 2020 Stef Bon <stefbon@gmail.com>

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

#ifndef _SSH_CONNECTION_UTILS_H
#define _SSH_CONNECTION_UTILS_H

struct ssh_connection_s *get_next_ssh_connection(struct ssh_connections_s *connections, struct ssh_connection_s *connection, const char *how);
signed char compare_ssh_connection(struct ssh_connection_s *connection, char *address, unsigned int port);

void get_ssh_connection_expire_init(struct ssh_connection_s *c, struct timespec *expire);
void get_ssh_connection_expire_session(struct ssh_connection_s *c, struct timespec *expire);

unsigned int get_status_ssh_connection(struct ssh_connection_s *connection);
void signal_ssh_connections(struct ssh_session_s *session);

void increase_refcount_ssh_connection(struct ssh_connection_s *connection);
void decrease_refcount_ssh_connection(struct ssh_connection_s *connection);

struct ssh_session_s *get_ssh_connection_session(struct ssh_connection_s *connection);
struct ssh_connections_s *get_ssh_connection_connections(struct ssh_connection_s *connection);

#endif
