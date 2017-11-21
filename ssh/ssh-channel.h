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

#ifndef FS_WORKSPACE_SSH_CHANNEL_H
#define FS_WORKSPACE_SSH_CHANNEL_H

/* prototypes */

struct ssh_channel_s *get_containing_channel(struct list_element_s *list);

void init_ssh_channel(struct ssh_channel_s *channel);
void add_admin_channel(struct ssh_session_s *session);

int start_new_channel(struct ssh_channel_s *channel);

struct ssh_channel_s *new_admin_channel(struct ssh_session_s *session);
void clear_ssh_channel(struct ssh_channel_s *channel);
void free_ssh_channel(struct ssh_channel_s *channel);
struct ssh_channel_s *remove_channel_table_locked(struct ssh_session_s *session, struct ssh_channel_s *channel, unsigned int local_channel);

void add_channel_table(struct ssh_channel_s *channel);
void remove_channel_table(struct ssh_channel_s *channel);
void clean_ssh_channel_queue(struct ssh_channel_s *channel);

void *create_ssh_connection(uid_t uid, struct context_interface_s *interface, struct context_address_s *address, unsigned int *error);

struct ssh_payload_s *get_ssh_payload_channel(struct ssh_channel_s *channel, struct timespec *expire, unsigned int *seq, unsigned int *error);
void queue_ssh_payload_channel(struct ssh_channel_s *channel, struct ssh_payload_s *payload);

#endif
