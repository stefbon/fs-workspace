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

#ifndef FS_WORKSPACE_SSH_SEND_SFTP_V04_H
#define FS_WORKSPACE_SSH_SEND_SFTP_V04_H

/* prototypes */

int send_sftp_init_v04(struct sftp_subsystem_s *sftp, unsigned int *seq);
int send_sftp_stat_v04_generic(struct sftp_subsystem_s *sftp, struct sftp_request_s *sftp_r, unsigned int flags);
int send_sftp_lstat_v04_generic(struct sftp_subsystem_s *sftp, struct sftp_request_s *sftp_r, unsigned int flags);
int send_sftp_fstat_v04_generic(struct sftp_subsystem_s *sftp, struct sftp_request_s *sftp_r, unsigned int flags);

void use_sftp_send_v04(struct sftp_subsystem_s *sftp);

#endif

