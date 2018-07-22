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

#ifndef FS_WORKSPACE_SFTP_REQUEST_H
#define FS_WORKSPACE_SFTP_REQUEST_H

void *create_sftp_request_ctx(void *ptr, struct sftp_request_s *sftp_r, unsigned int *error);
void *get_sftp_request(struct sftp_subsystem_s *sftp_subsystem, unsigned int id, struct sftp_request_s **sftp_r, unsigned int *error);
int signal_sftp_received_id(struct sftp_subsystem_s *sftp_subsystem, void *r);

unsigned char wait_sftp_response_ctx(struct context_interface_s *interface, void *r, struct timespec *timeout, unsigned int *error);
unsigned char wait_sftp_response_simpe_ctx(void *ptr, void *r, struct timespec *timeout, unsigned int *error);

void remove_orphan_requests(struct sftp_subsystem_s *sftp_subsystem, struct timespec *expire);

int init_send_hash(struct sftp_send_hash_s *send_hash, unsigned int *error);
void free_send_hash(struct sftp_send_hash_s *send_hash);

#endif
