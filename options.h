/*
  2010, 2011, 2012, 2013, 2014, 2015, 2016, 2017  Stef Bon <stefbon@gmail.com>

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

#include "pathinfo.h"

#define _OPTIONS_MAIN_CONFIGFILE 			"/etc/fs-workspace/options"
#define _OPTIONS_MAIN_BASEMAP 				"/etc/fs-workspace/base"
#define _OPTIONS_MAIN_SOCKET 				"/run/fs-workspace/sock"

/* FUSE */

#define _OPTIONS_FUSE_ATTR_TIMEOUT			1.0
#define _OPTIONS_FUSE_ENTRY_TIMEOUT			1.0
#define _OPTIONS_FUSE_NEGATIVE_TIMEOUT			1.0

/* NETWORK */

#define _OPTIONS_NETWORK_DISCOVER_METHOD_AVAHI		1
#define _OPTIONS_NETWORK_DISCOVER_METHOD_FILE		2
#define _OPTIONS_NETWORK_DISCOVER_STATIC_FILE_DEFAULT	"/etc/fs-workspace/network.services"

#define _OPTIONS_NETWORK_ICON_HIDE			0
#define _OPTIONS_NETWORK_ICON_SHOW			1
#define _OPTIONS_NETWORK_ICON_OVERRULE			2

/* SSH */

#define _OPTIONS_SSH_FLAG_SUPPORT_EXT_INFO		1

#define _OPTIONS_SSH_EXTENSION_SERVER_SIG_ALGS		1
#define _OPTIONS_SSH_EXTENSION_DELAY_COMPRESSION	2
#define _OPTIONS_SSH_EXTENSION_NO_FLOW_CONTROL		3
#define _OPTIONS_SSH_EXTENSION_ELEVATION		4

#define _OPTIONS_SSH_INIT_TIMEOUT_DEFAULT		2
#define _OPTIONS_SSH_SESSION_TIMEOUT_DEFAULT		2
#define _OPTIONS_SSH_EXEC_TIMEOUT_DEFAULT		2

#define _OPTIONS_SSH_BACKEND_OPENSSH			1

/* other TODO :
    _OPTIONS_SSH_BACKEND_GPGME
*/

/* the db/file on this machine with trusted host keys
    like /etc/ssh/known_hosts and ~/.ssh/known_hosts for openssh */

#define _OPTIONS_SSH_TRUSTDB_NONE			0
#define _OPTIONS_SSH_TRUSTDB_OPENSSH			1

/* other sources of trusted hostkeys? */

/* SFTP */

#define _OPTIONS_SFTP_PACKET_MAXSIZE			8192
#define _OPTIONS_SFTP_USERMAPPING_NONE			1
#define _OPTIONS_SFTP_USERMAPPING_MAP			2
#define _OPTIONS_SFTP_USERMAPPING_FILE			3
#define _OPTIONS_SFTP_USERMAPPING_DEFAULT		_OPTIONS_SFTP_USERMAPPING_MAP

#define _OPTIONS_SFTP_NETWORK_NAME_DEFAULT		"SFTP"

#define _OPTIONS_SFTP_FLAG_SHOW_DOMAINNAME		1
#define _OPTIONS_SFTP_FLAG_HOME_USE_REMOTENAME		2

struct ssh_options_s {
    unsigned int			flags;
    unsigned int			extensions;
    char 				*crypto_cipher_algos;
    char 				*pubkey_algos;
    char 				*compression_algos;
    char 				*keyx_algos;
    char 				*crypto_mac_algos;
    unsigned char 			init_timeout;
    unsigned char 			session_timeout;
    unsigned char 			exec_timeout;
    unsigned int 			backend;
    unsigned int 			trustdb;
};

struct sftp_options_s {
    unsigned int 			flags;
    char 				*usermapping_user_unknown;
    char 				*usermapping_user_nobody;
    unsigned int			packet_maxsize;
    unsigned char			usermapping_type;
    char				*usermapping_file;
    char				*network_name;
};

struct network_options_s {
    unsigned int 			flags;
    char 				*discover_static_file;
    unsigned int			domain_icon;
    unsigned int			server_icon;
    unsigned int			share_icon;
};

struct fuse_options_s {
    struct timespec			attr_timeout;
    struct timespec			entry_timeout;
    struct timespec			negative_timeout;
};

struct fs_options_s {
    struct pathinfo_s			configfile;
    struct pathinfo_s			socket;
    struct pathinfo_s			basemap;
    struct pathinfo_s			discovermap;
    struct fuse_options_s		fuse;
    struct network_options_s		network;
    struct ssh_options_s		ssh;
    struct sftp_options_s		sftp;
};

// Prototypes

int parse_arguments(int argc, char *argv[], unsigned int *error);
void free_options();

#endif
