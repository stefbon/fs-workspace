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

#ifndef FS_WORKSPACE_SSH_SEND_H
#define FS_WORKSPACE_SSH_SEND_H


/* prototypes */

int init_send(struct ssh_session_s *session);
void free_send(struct ssh_session_s *session);

int send_ssh_message(struct ssh_session_s *session, int (*fill_raw_message)(struct ssh_session_s *ssh_session, struct ssh_payload_s *payload, void *ptr), void *ptr, unsigned int *seq);
int sendproc_ssh_message(struct ssh_session_s *session, struct ssh_sendproc_s *sendproc, void *ptr, unsigned int *seq);
void switch_send_process(struct ssh_session_s *session, const char *phase);

#endif
