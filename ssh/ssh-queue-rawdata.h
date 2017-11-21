/*
  2010, 2011, 2012, 2013, 2014, 2015 Stef Bon <stefbon@gmail.com>

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

#ifndef FS_WORKSPACE_SSH_QUEUE_RAWDATA_H
#define FS_WORKSPACE_SSH_QUEUE_RAWDATA_H

void queue_ssh_data(struct ssh_session_s *session, unsigned char *buffer, unsigned int len);

void stop_receive_data(struct ssh_session_s *session);
void init_receive_rawdata_queue(struct ssh_session_s *session);

void clean_receive_rawdata_queue(struct ssh_receive_s *receive);
void free_receive_rawdata_queue(struct ssh_receive_s *receive);

void switch_process_rawdata_queue(struct ssh_session_s *session, const char *phase);

#endif
