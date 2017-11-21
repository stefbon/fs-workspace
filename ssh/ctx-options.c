/*
  2010, 2011, 2012, 2103, 2014, 2015, 2016 Stef Bon <stefbon@gmail.com>

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

#include "global-defines.h"

#include <stdio.h>
#include <stdlib.h>
#include <stddef.h>
#include <stdbool.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <dirent.h>
#include <errno.h>
#include <err.h>
#include <sys/time.h>
#include <time.h>
#include <pthread.h>
#include <ctype.h>
#include <inttypes.h>

#include <sys/param.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/syscall.h>

#include "logging.h"
#include "main.h"
#include "pathinfo.h"
#include "entry-management.h"
#include "fuse-fs.h"
#include "workspaces.h"
#include "workspace-context.h"

#include "utils.h"
#include "options.h"

#include "ctx-options.h"

extern struct fs_options_struct fs_options;

static const char *_usermapping_none = "none";
static const char *_usermapping_map = "map";

char *get_ssh_options(const char *name)
{
    if (strcmp(name, "ciphers")==0) {

	return fs_options.ssh_ciphers;

    } else if (strcmp(name, "hmac")==0) {

	return fs_options.ssh_mac;

    } else if (strcmp(name, "compression")==0) {

	return fs_options.ssh_compression;

    } else if (strcmp(name, "keyx")==0) {

	return fs_options.ssh_keyx;

    } else if (strcmp(name, "pubkey")==0) {

	return fs_options.ssh_pubkeys;

    } else if (strcmp(name, "user-unknown")==0) {

	return fs_options.user_unknown;

    } else if (strcmp(name, "user-nobody")==0) {

	return fs_options.user_nobody;

    } else {

	return NULL;

    }

    return NULL;
}

unsigned int get_max_data_size(uid_t uid)
{
    return 8192; /* 2K */
}

const char *get_mapping_user_context_ssh(uid_t uid)
{

    /* the same for every user for now: ignore the user */

    if (fs_options.ssh_usermapping==FS_WORKSPACE_SSH_USERMAPPING_NONE) {

	return _usermapping_none;

    } else if (fs_options.ssh_usermapping==FS_WORKSPACE_SSH_USERMAPPING_MAP) {

	return _usermapping_map;

    }

    return "";

}
