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

#ifndef FS_WORKSPACE_SFTP_ATTR_COMMON_H
#define FS_WORKSPACE_SFTP_ATTR_COMMON_H

/* prototypes */

unsigned int read_attributes_ctx(void *ptr, char *buffer, unsigned int size, struct fuse_sftp_attr_s *fuse_attr);
unsigned int write_attributes_ctx(void *ptr, char *buffer, unsigned int size, struct fuse_sftp_attr_s *fuse_attr);

void read_name_response_ctx(void *ptr, struct name_response_s *response, char **name, unsigned int *len);
unsigned int read_attr_response_ctx(void *ptr, struct name_response_s *response, struct fuse_sftp_attr_s *fuse_attr);

int get_attribute_info_ctx(void *ptr, unsigned int valid, const char *what);

#endif
