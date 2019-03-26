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

#ifndef FS_WORKSPACE_SFTP_TIME_H
#define FS_WORKSPACE_SFTP_TIME_H

/* prototypes */

int init_time_correction(struct context_interface_s *interface, struct sftp_subsystem_s *sftp);
void correct_time_s2c_ctx(void *ptr, struct timespec *time);
void correct_time_c2s_ctx(void *ptr, struct timespec *time);

#endif
