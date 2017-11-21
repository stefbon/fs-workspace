/*
  2010, 2011, 2012, 2013, 2014 Stef Bon <stefbon@gmail.com>

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
#ifndef FS_WORKSPACE_OPTIONS_H
#define FS_WORKSPACE_OPTIONS_H

#define FS_WORKSPACE_CONFIGFILE 	"/etc/fs-workspace/options"
#define FS_WORKSPACE_BASEMAP 		"/etc/fs-workspace/base"
#define FS_WORKSPACE_SOCKET 		"/run/fs-workspace/sock"
#define FS_WORKSPACE_DISCOVERMAP 	"/etc/fs-workspace/discover"

#define FS_WORKSPACE_SSH_USERMAPPING_NONE		1
#define FS_WORKSPACE_SSH_USERMAPPING_MAP		2
#define FS_WORKSPACE_SSH_USERMAPPING_DEFAULT		FS_WORKSPACE_SSH_USERMAPPING_MAP

struct fs_options_struct {
    struct pathinfo_s configfile;
    struct pathinfo_s socket;
    struct pathinfo_s basemap;
    struct pathinfo_s discovermap;
    char *ssh_ciphers;
    char *ssh_pubkeys;
    char *ssh_compression;
    char *ssh_keyx;
    char *ssh_mac;
    unsigned char ssh_init_timeout;
    unsigned char ssh_session_timeout;
    unsigned char ssh_exec_timeout;
    char *user_unknown;
    char *user_nobody;
    double attr_timeout;
    double entry_timeout;
    double negative_timeout;
    unsigned int maxsize;
    unsigned char ssh_usermapping;
};

// Prototypes

int parse_arguments(int argc, char *argv[], unsigned int *error);
void free_options();

#endif
