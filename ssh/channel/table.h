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

#ifndef FS_WORKSPACE_SSH_CHANNEL_TABLE_H
#define FS_WORKSPACE_SSH_CHANNEL_TABLE_H

/* prototypes */

struct ssh_channel_s *lookup_session_channel_for_flag(struct channel_table_s *table, unsigned int nr, unsigned int flag);
struct ssh_channel_s *lookup_session_channel_for_payload(struct channel_table_s *table, unsigned int nr, struct ssh_payload_s **p_payload);
struct ssh_channel_s *lookup_session_channel_for_data(struct channel_table_s *table, unsigned int nr, struct ssh_payload_s **p_payload);
struct ssh_channel_s *lookup_session_channel(struct channel_table_s *table, unsigned int nr);

void init_channels_table(struct ssh_session_s *session, unsigned int size);
void free_channels_table(struct ssh_session_s *session);

struct ssh_channel_s *find_channel(struct ssh_session_s *session, unsigned int type);
struct ssh_channel_s *get_next_channel(struct ssh_session_s *session, struct ssh_channel_s *channel);

void table_add_channel(struct ssh_channel_s *channel);
void table_remove_channel(struct ssh_channel_s *channel);

int add_channel(struct ssh_channel_s *channel, unsigned int flags);
void remove_channel(struct ssh_channel_s *channel, unsigned int flags);

int channeltable_readlock(struct channel_table_s *table, struct simple_lock_s *l);
int channeltable_upgrade_readlock(struct channel_table_s *table, struct simple_lock_s *l);
int channeltable_writelock(struct channel_table_s *table, struct simple_lock_s *l);
int channeltable_unlock(struct channel_table_s *table, struct simple_lock_s *l);

#endif
