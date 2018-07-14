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

#ifndef FS_WORKSPACE_SSH_COMMON_LIST_H
#define FS_WORKSPACE_SSH_COMMON_LIST_H

/* prototypes */

struct ssh_session_s *lookup_ssh_session(uint64_t unique);
void add_ssh_session_group(struct ssh_session_s *s);
void remove_ssh_session_group(struct ssh_session_s *s);

void lock_group_ssh_sessions(struct simple_lock_s *l);
void unlock_group_ssh_sessions(struct simple_lock_s *l);

struct ssh_session_s *get_next_ssh_session(void **index, unsigned int *hashvalue);
int initialize_group_ssh_sessions(unsigned int *error);
void free_group_ssh_sessions();

#endif
