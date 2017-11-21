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

#ifndef FS_WORKSPACE_SSH_HOSTINFO_H
#define FS_WORKSPACE_SSH_HOSTINFO_H

void init_hostinfo(struct ssh_session_s *session);
void free_hostinfo(struct ssh_session_s *session);

void set_time_correction_server_behind(struct ssh_session_s *session, struct timespec *delta);
void set_time_correction_server_ahead(struct ssh_session_s *session, struct timespec *delta);

void correct_time_s2c(struct ssh_session_s *session, struct timespec *time);
void correct_time_c2s(struct ssh_session_s *session, struct timespec *time);

void set_time_delta(struct ssh_session_s *session, struct timespec *send, struct timespec *recv, struct timespec *output);

#endif
