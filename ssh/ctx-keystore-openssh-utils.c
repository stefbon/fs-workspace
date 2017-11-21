/*
  2010, 2011, 2012, 2103, 2014, 2015, 2016, 2017 Stef Bon <stefbon@gmail.com>

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
#include <sys/fsuid.h>

#include <sys/socket.h>
#include <netdb.h>
#include <arpa/inet.h>

#include <glib.h>

#include "logging.h"
#include "main.h"
#include "pathinfo.h"
#include "simple-list.h"

#include "utils.h"
#include "options.h"

#include "ctx-keystore.h"
#include "ctx-keystore-openssh.h"

unsigned int get_path_openssh_user(struct passwd *pwd, char *path, char *buffer, unsigned int len)
{

    if (buffer) {

	if (path==NULL) {

	    return snprintf(buffer, len, "%s/.ssh/", pwd->pw_dir);

	} else if (*path=='/') {

	    /* path already absolute */
	    return snprintf(buffer, len, "%s", path);

	} else {
	    char *sep=strchr(path, '/');

	    if (sep) {

		/* when there is a slash (but not starting with it) relative to $HOME */

		if (*path=='~') {

		    return snprintf(buffer, len, "%s%s", pwd->pw_dir, &path[1]);

		} else {

		    return snprintf(buffer, len, "%s/%s", pwd->pw_dir, path);

		}

	    } else {

		/* no slash: relative to $HOME/.ssh/ */

		return snprintf(buffer, len, "%s/.ssh/%s", pwd->pw_dir, path);

	    }

	}

    } else {

	if (path==NULL) {

	    return strlen(pwd->pw_dir) + strlen("/.ssh/") + 1;

	} else if (*path=='/') {

	    /* path already absolute */
	    return strlen(path) + 1;

	} else {
	    char *sep=strchr(path, '/');

	    if (sep) {

		return strlen(pwd->pw_dir) + strlen(path) + 2;

	    } else {

		return strlen(pwd->pw_dir) + strlen("/.ssh/") + strlen(path) + 1;

	    }

	}

    }

    return 0;

}

unsigned int get_path_openssh_system(char *path, char *buffer, unsigned int len)
{

    if (buffer) {

	if (path==NULL) {

	    return snprintf(buffer, len, "/etc/ssh/");

	} else if (*path=='/') {

	    return snprintf(buffer, len, "%s", path);

	} else {

	    return snprintf(buffer, len, "/etc/ssh/%s", path);

	}

    } else {

	if (path==NULL) {

	    return strlen("/etc/ssh/") + 1;

	} else if (*path=='/') {

	    return strlen(path) + 1;

	} else {

	    return strlen("/etc/ssh/") + strlen(path) + 1;

	}

    }

    return 0;

}

static int _open_file_ssh(char *path, struct stat *st, unsigned int *error)
{
    struct stat test;
    int fd=0;

    /* path already absolute */

    if (lstat(path, &test)==-1) {

	*error=errno;
	goto out;

    }

    if (st) memcpy(st, &test, sizeof(struct stat));

    if (! S_ISREG(test.st_mode)) {

	*error=EINVAL;
	goto out;

    }

    if (access(path, F_OK | R_OK)==-1) {

	*error=errno;
	goto out;

    }

    fd=open(path, O_RDONLY);
    if (fd==-1) {

	*error=errno;
	fd=0; /* zero is never a valid fd --here-- */

    }

    out:

    return fd;

}

/* open a file while checking access
    path can be:
    - absolute, starting with a slash
    - only a name, relative to $HOME/.ssh directory */

unsigned int open_file_ssh_user(struct passwd *pwd, char *path, struct stat *st, unsigned int *error)
{
    int fd=0;
    uid_t uid_keep=setfsuid(pwd->pw_uid);
    gid_t gid_keep=setfsgid(pwd->pw_gid);
    unsigned int len=get_path_openssh_user(pwd, path, NULL, 0);
    char fullpath[len];

    if (get_path_openssh_user(pwd, path, fullpath, len)>0) {

	fd=_open_file_ssh(fullpath, st, error);

    }

    out:

    uid_keep=setfsuid(uid_keep);
    gid_keep=setfsgid(gid_keep);

    return (unsigned int) fd;

}

int stat_file_ssh_user(struct passwd *pwd, char *path, struct stat *st, unsigned int *error)
{
    int result=-1;
    uid_t uid_keep=setfsuid(pwd->pw_uid);
    gid_t gid_keep=setfsgid(pwd->pw_gid);
    unsigned int len=get_path_openssh_user(pwd, path, NULL, 0);
    char fullpath[len];

    if (get_path_openssh_user(pwd, path, fullpath, len)>0) {

	result=lstat(fullpath, st);
	if (result==-1) *error=errno;

    }

    out:

    uid_keep=setfsuid(uid_keep);
    gid_keep=setfsgid(gid_keep);

    return result;

}

int stat_file_ssh_system(struct passwd *pwd, char *path, struct stat *st, unsigned int *error)
{
    int result=-1;
    uid_t uid_keep=setfsuid(pwd->pw_uid);
    gid_t gid_keep=setfsgid(pwd->pw_gid);
    unsigned int len=get_path_openssh_system(path, NULL, 0);
    char fullpath[len];

    if (get_path_openssh_system(path, fullpath, len)>0) {

	result=lstat(fullpath, st);
	if (result==-1) *error=errno;

    }

    out:

    uid_keep=setfsuid(uid_keep);
    gid_keep=setfsgid(gid_keep);

    return result;

}
/* read system files
    don't drop privileges */

unsigned int open_file_ssh_system(struct passwd *pwd, char *path, struct stat *st, unsigned int *error)
{
    int fd=0;
    // uid_t uid_keep=setfsuid(pwd->pw_uid);
    // gid_t gid_keep=setfsgid(pwd->pw_gid);
    unsigned int len=get_path_openssh_system(path, NULL, 0);
    char fullpath[len];

    if (get_path_openssh_system(path, fullpath, len)>0) {

	fd=_open_file_ssh(fullpath, st, error);

    }

    out:

    // uid_keep=setfsuid(uid_keep);
    // gid_keep=setfsgid(gid_keep);
    return (unsigned int) fd;

}

unsigned int openat_file_ssh(struct passwd *pwd, unsigned int dfd, char *name, unsigned char user, struct stat *st, unsigned int *error)
{
    struct stat test;
    uid_t uid_keep=0;
    gid_t gid_keep=0;
    int fd=0;

    if (user>0) {
	uid_keep=setfsuid(pwd->pw_uid);
	gid_keep=setfsgid(pwd->pw_gid);
    }

    if (fstatat(dfd, name, &test, 0)==-1) {

	*error=errno;
	goto out;

    }

    if (st) memcpy(st, &test, sizeof(struct stat));

    if (! S_ISREG(test.st_mode)) {

	*error=EINVAL;
	goto out;

    }

    if (faccessat(dfd, name, F_OK | R_OK, 0)==-1) {

	*error=errno;
	goto out;

    }

    fd=openat(dfd, name, O_RDONLY);

    if (fd==-1) {

	*error=errno;
	fd=0;

    }

    out:

    if (user>0) {
	uid_keep=setfsuid(uid_keep);
	gid_keep=setfsgid(gid_keep);

    }

    return (unsigned int) fd;

}
