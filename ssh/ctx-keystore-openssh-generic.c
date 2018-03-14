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
#include "utils.h"
#include "simple-list.h"

#include "ctx-keystore.h"
#include "ctx-keystore-openssh.h"

#include "pk/openssh-utils.h"

/* look for files ending with ".pub"
    for user look in $HOME/.ssh/
    for host look in /etc/ssh/
*/

int get_identity_records_openssh_generic(struct public_keys_s *keys, const char *what, unsigned int *error)
{
    struct passwd *pwd=keys->pwd;
    unsigned int len=get_directory_openssh_common(pwd, what, NULL, 0);
    char path[len];
    int result=0;

    if (get_directory_openssh_common(pwd, what, path, len)>0) {
	uid_t uid_keep=setfsuid(pwd->pw_uid);
	gid_t gid_keep=setfsgid(pwd->pw_gid);
	DIR *dp=NULL;

	logoutput_debug("get_identity_records_openssh_generic: look in %s", path);

	dp=opendir(path);

	if (dp==NULL) {

	    *error=errno;
	    logoutput_debug("init_public_keys_openssh_generic: unable to open %s error %i (%s)", path, *error, strerror(*error));

	} else {
	    struct dirent *de=NULL;

	    de=readdir(dp);

	    while(de) {
		unsigned int len=strlen(de->d_name);

		if (len>4 && strncmp(de->d_name + len - 4, ".pub", 4)==0) {
		    struct common_identity_s *identity=NULL;
		    char *name=NULL;

		    identity=malloc(sizeof(struct common_identity_s));
		    name=malloc(len + 1);

		    if (identity && name) {

			memcpy(name, de->d_name, len);
			name[len]='\0';

			identity->ptr=(void *) keys;
			identity->flags=_IDENTITY_FLAG_GENERIC | _IDENTITY_FLAG_OPENSSH;
			identity->file=name;
			identity->user=NULL; /* no remote user with generic */
			identity->list.next=NULL;
			identity->list.prev=NULL;

			if (strcmp(what, "user")==0) identity->flags|=_IDENTITY_FLAG_USER;

			add_list_element_last(&keys->head, &keys->tail, &identity->list);
			result++;

		    } else {

			if (identity) {

			    free(identity);
			    identity=NULL;

			}

			if (name) {

			    free(name);
			    name=NULL;

			}

			/* what to do here? break with error? */

		    }

		}

		de=readdir(dp);

	    }

	    closedir(dp);

	}

	setfsuid(uid_keep);
	setfsgid(gid_keep);

    }

    return result;
}
