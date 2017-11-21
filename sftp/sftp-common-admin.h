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

#ifndef FS_WORKSPACE_SFTP_COMMON_ADMIN_H
#define FS_WORKSPACE_SFTP_COMMON_ADMIN_H

#define SFTP_USERINFO_REMOTE_GROUP		1
#define SFTP_USERINFO_REMOTE_UID		2
#define SFTP_USERINFO_REMOTE_GID		4

struct sftp_userinfo_s {
    struct ssh_string_s				*remote_group;
    uid_t					*remote_uid;
    gid_t					*remote_gid;
    unsigned int				wanted;
    unsigned int				received;
};

/* prototypes */

unsigned int get_sftp_interface_info(struct context_interface_s *interface, const char *what, void *data, unsigned char *buffer, unsigned int size, unsigned int *error);
unsigned int get_sftp_sharedmap(struct ssh_session_s *session, char *name, unsigned char *buffer, unsigned int len, unsigned int *error);

void get_timeinfo_sftp_server(struct sftp_subsystem_s *sftp);

#endif
