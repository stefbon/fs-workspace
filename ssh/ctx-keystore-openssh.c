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
#include "ctx-keystore-openssh-generic.h"
#include "ctx-keystore-openssh-config.h"

#include "pk/openssh-utils.h"

extern unsigned int get_uint32(unsigned char *buff);

static struct common_identity_s *get_containing_identity_list(struct list_element_s *list)
{
    return (struct common_identity_s *) ( ((char *) list) - offsetof(struct common_identity_s, list));
}

static void free_identity(struct common_identity_s *identity)
{
    if (identity->user) free(identity->user);
    if (identity->file) free(identity->file);
    free(identity);
}

struct common_identity_s *get_next_identity_openssh(void *ptr)
{
    struct public_keys_s *keys=(struct public_keys_s *) ptr;
    struct list_element_s *list=NULL;
    struct common_identity_s *identity=NULL;
    struct stat st;
    unsigned int error=0;
    int result=0;

    if (! keys) return NULL;

    getkey:

    list=get_list_head(&keys->head, &keys->tail);
    if (list==NULL) return NULL;
    identity=get_containing_identity_list(list);

    if (identity->flags & _IDENTITY_FLAG_USER ) {

	result=stat_file_ssh_user(keys->pwd, identity->file, &st, &error);

    } else {

	result=stat_file_ssh_system(keys->pwd, identity->file, &st, &error);

    }

    if (result==-1) {

	logoutput("get_next_identity_openssh: error %i stat file %s (%s)", error, identity->file, strerror(error));
	free_identity(identity);
	identity=NULL;

	goto getkey;

    }

    return identity;

}

static int open_file_helper(struct passwd *pwd, char *file, unsigned int flags, char *buffer, unsigned int len, unsigned int *error)
{
    unsigned int fd=0;
    int result=0;
    struct stat st;

    if (flags & _IDENTITY_FLAG_USER) {

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

int get_public_key_openssh(struct common_identity_s *identity, char *buffer, unsigned int len)
{
    struct public_keys_s *keys=(struct public_keys_s *) identity->ptr;
    unsigned int error=0;

    if (buffer==NULL) {
	struct stat st;
	int result=0;

	if (identity->flags & _IDENTITY_FLAG_USER) {

	    result=stat_file_ssh_user(keys->pwd, identity->file, &st, &error);

	} else {

	    result=stat_file_ssh_system(keys->pwd, identity->file, &st, &error);

	}

	if (result==0) {

	    error=0;
	    logoutput_debug("get_public_key_openssh: size %i", (int) st.st_size);
	    return (int) st.st_size;

	} else {

	    error=errno;
	    return 0;

	}

    }

    return open_file_helper(keys->pwd, identity->file, identity->flags, buffer, len, &error);

}

int get_private_key_openssh(struct common_identity_s *identity, char *buffer, unsigned int size)
{
    struct public_keys_s *keys=(struct public_keys_s *) identity->ptr;
    unsigned int error=0;
    int result=0;

    if (identity->file) {
	unsigned int len=strlen(identity->file);

	if (len > 4 && strncmp(identity->file + len - 4, ".pub", 4)==0) {
	    char file[len];

	    memcpy(file, identity->file, len - 4);
	    file[len - 4]='\0';

	    if (buffer==NULL) {
		struct stat st;

		if (identity->flags & _IDENTITY_FLAG_USER) {

		    result=stat_file_ssh_user(keys->pwd, file, &st, &error);

		} else {

		    result=stat_file_ssh_system(keys->pwd, file, &st, &error);

		}

		if (result==0) {

		    logoutput_debug("get_private_key_openssh: size %i", (int) st.st_size);
		    error=0;
		    return (int) st.st_size;

		} else {

		    error=errno;
		    result=0;

		}

	    } else {

		result=open_file_helper(keys->pwd, file, identity->flags, buffer, size, &error);

	    }

	}

    }

    return result;
}

void free_identity_record_openssh(struct common_identity_s *identity)
{
    free_identity(identity);
}

void finish_identity_records_openssh(void *ptr)
{
    struct public_keys_s *keys=(struct public_keys_s *) ptr;

    if (keys) {
	struct list_element_s *list=NULL;

	list=get_list_head(&keys->head, &keys->tail);

	while (list) {
	    struct common_identity_s *i=get_containing_identity_list(list);

	    free_identity(i);
	    i=NULL;
	    list=get_list_head(&keys->head, &keys->tail);

	}

	free(keys);

    }

}

void *init_identity_records_openssh(struct passwd *pwd, struct hostaddress_s *hostaddress, const char *what, unsigned int *error)
{
    struct public_keys_s *keys=NULL;
    int result=0;

    keys=malloc(sizeof(struct public_keys_s));

    if (! keys) {

	*error=ENOMEM;
	goto error;

    }

    memset(keys, 0, sizeof(struct public_keys_s));
    keys->flags=0;
    keys->pwd=pwd;
    keys->head=NULL;
    keys->tail=NULL;

    result=get_identity_records_openssh_config(keys, hostaddress, what, error);

    if (result>0) {

	logoutput_debug("init_identity_records_openssh: found %i records from config", result);
	return (void *) keys;

    } else if (result==-1) {

	logoutput("init_identity_records_openssh: error %i (%s)", *error, strerror(*error));

    } else {

	logoutput_debug("init_identity_records_openssh: no records from config, trying generic");

    }

    result=get_identity_records_openssh_generic(keys, what, error);

    if (result>0) {

	logoutput_debug("init_identity_records_openssh: found %i record%s from generic", result, (result>1) ? "s" : "");

    } else if (result==-1) {

	logoutput("init_identity_records_openssh: error %i (%s)", *error, strerror(*error));

    } else {

	logoutput_debug("init_identity_records_openssh: no records from generic");

    }

    return (void *) keys;

    error:

    if (keys) free(keys);
    return NULL;

}
