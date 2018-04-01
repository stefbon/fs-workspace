/*
  2016, 2017, 2018 Stef Bon <stefbon@gmail.com>

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

#include "logging.h"
#include "utils.h"
#include "simple-list.h"

#include "pk-keys.h"
#include "pk-keystore.h"
#include "openssh-utils.h"

#define _OPENSSH_PUBLIC_FILE_EXTENSION		".pub"

static int check_pk_file_extension(char *name, unsigned int len, char **pos)
{
    unsigned int size=strlen(_OPENSSH_PUBLIC_FILE_EXTENSION);
    if (size>=len) return -1;
    if (pos) *pos=&name[len - size];
    return (strncmp(&name[len - size], _OPENSSH_PUBLIC_FILE_EXTENSION, size) == 0) ? 0 : -1;
}

static int check_pk_file_name(char *name, unsigned int len)
{
    if (len<=9) return -1;
    return (strncmp(name, "ssh_host_", 9) == 0) ? 0 : -1;
}

static int check_pk_file_private(char *path, unsigned int size, char *name, unsigned int len)
{
    char tmp[size + len + 2];

    if (snprintf(tmp, size + len + 2, "%s/%s", path, name)>0) {
	struct stat st;
	char *pos=NULL;

	/* check the public file does exist */

	if (lstat(tmp, &st)==-1) return -1;
	if (! S_ISREG(st.st_mode)) return -1;

	/* private file is minus the extension must exist */

	if (check_pk_file_extension(tmp, strlen(tmp), &pos)==-1) return -1;
	*pos='\0';

	if (lstat(tmp, &st)==-1) return -1;
	if (S_ISREG(st.st_mode)) return 0;

    }

    return -1;

}

/* add a public key identity for an openssh local file */

static unsigned char add_pk_identity(struct pk_list_s *pk_list, char *filename, unsigned int len, const char *what)
{
    struct pk_identity_s *identity=NULL;
    unsigned char scope = 0;

    scope = (strcmp(what, "user")==0) ? PK_IDENTITY_SCOPE_USER : PK_IDENTITY_SCOPE_HOST;

    identity = create_pk_identity(pk_list, PK_IDENTITY_SOURCE_OPENSSH_LOCAL, scope, len + 1);

    if (identity) {

	memcpy(identity->buffer, filename, len+1); /* including the trailing zero */
	identity->size=len+1;

	identity->pk.openssh_local.file = identity->buffer;
	identity->pk.openssh_local.user = NULL; /* no remote user when file is found on standard location */
	identity->pk.openssh_local.flags = PK_IDENTITY_FLAG_OPENSSH_STANDARD; /* found on standard location */

	return 1;

    }

    return 0;

}

/* look for files ending with ".pub"
    for user look in $HOME/.ssh/
    for host look in /etc/ssh/
*/

int get_identity_records_openssh(struct pk_list_s *pkeys, const char *what, unsigned int *error)
{
    struct passwd *pwd=pkeys->pwd;
    unsigned int size=get_directory_openssh_common(pwd, what, NULL, 0);
    char path[size];
    int result=0;
    uid_t uid_keep=0;
    gid_t gid_keep=0;
    DIR *dp=NULL;
    struct dirent *de=NULL;

    if (get_directory_openssh_common(pwd, what, path, size)<=0) return 0;
    logoutput_info("get_identity_records_openssh: look in %s", path);

    uid_keep=setfsuid(pwd->pw_uid);
    gid_keep=setfsgid(pwd->pw_gid);

    dp=opendir(path);

    if (dp==NULL) {

	*error=errno;
	logoutput_info("get_identity_records_openssh: unable to open %s error %i (%s)", path, *error, strerror(*error));
	goto out;

    }

    de=readdir(dp);

    while (de) {
	unsigned int len=strlen(de->d_name);

	/* check for extension (.pub), presence of the private file (without extension) and the name when looking for host keys */

	if (check_pk_file_extension(de->d_name, len, NULL) == -1) goto next;

	if (strcmp(what, "host")==0) {

	    if (check_pk_file_name(de->d_name, len) == -1) goto next;

	}

	if (check_pk_file_private(path, size, de->d_name, len) == -1) goto next;

	logoutput_info("get_identity_records_openssh: found %s", de->d_name);

	result += add_pk_identity(pkeys, de->d_name, len, what);

	next:
	de=readdir(dp);

    }

    closedir(dp);

    out:
    setfsuid(uid_keep);
    setfsgid(gid_keep);

    return result;

}

static int open_file_helper(struct passwd *pwd, char *file, unsigned char scope, char *buffer, unsigned int len, unsigned int *error)
{
    unsigned int fd=0;
    int result=0;
    struct stat st;

    if (scope == PK_IDENTITY_SCOPE_USER) {

	fd=open_file_ssh_user(pwd, file, &st, error);

    } else {

	fd=open_file_ssh_system(pwd, file, &st, error);

    }

    if (fd>0) {

	if (len<st.st_size) {

	    logoutput_warning("open_file_helper: file is %i bytes but buffer is %i bytes", (int) st.st_size, len);
	    *error=EINVAL;

	}

	ssize_t bytes=read(fd, buffer, len);

	if (bytes==-1) {

	    *error=errno;

	} else {

	    if (bytes<len) {

		logoutput_warning("open_file_helper: %i bytes read (buffer size is %i)", (int) bytes, len);

	    } else {

		logoutput_debug("open_file_helper: %i bytes read", (int) bytes);

	    }
	    result=(int) bytes;

	}

	close(fd);

    }

    return result;

}

/* read a public or private key in buffer; if buffer is NULL, return the required size of buffer
*/

int get_key_file_openssh(struct pk_identity_s *identity, char *buffer, unsigned int size, unsigned char secret)
{
    struct pk_list_s *pk_list=identity->pk_list;
    unsigned int error=0;
    unsigned int len=strlen(identity->pk.openssh_local.file);
    char file[len+1];

    memcpy(file, identity->pk.openssh_local.file, len+1);

    if (secret>0) {
	char *pos = NULL;

	/* the private key file is minus extension */

	if (check_pk_file_extension(file, len, &pos) == -1) return 0;
	*pos = '\0';

    }

    if (buffer==NULL) {
	struct stat st;
	int result=0;

	if (identity->scope == PK_IDENTITY_SCOPE_USER) {

	    result=stat_file_ssh_user(pk_list->pwd, file, &st, &error);

	} else {

	    result=stat_file_ssh_system(pk_list->pwd, file, &st, &error);

	}

	return (result==0) ? (int) st.st_size : 0;

    }

    return open_file_helper(pk_list->pwd, file, identity->scope, buffer, size, &error);

}
