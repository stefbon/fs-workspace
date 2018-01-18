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
#include "ctx-keystore-openssh-knownhosts.h"

static FILE *get_openssh_known_hosts_file(struct passwd *pwd, unsigned int *error)
{
    FILE *fp=NULL;
    unsigned int len=strlen(pwd->pw_dir) + strlen("/.ssh/known_hosts") + 1;
    char fullpath[len];

    if (snprintf(fullpath, len, "%s/.ssh/known_hosts", pwd->pw_dir)>0) {
	uid_t uid_keep=setfsuid(pwd->pw_uid);
	gid_t gid_keep=setfsgid(pwd->pw_gid);

	fp=fopen(fullpath, "r");
	if (! fp) *error=errno;

	setfsuid(uid_keep);
	setfsgid(gid_keep);

    }

    return fp;

}

struct known_hosts_s {
    FILE				*fp;
    char				*line;
    unsigned int			filter;
    char				*host;
    char				*type;
    char				*key;
};

void *init_known_hosts_openssh(struct passwd *pwd, unsigned int filter, unsigned int *error)
{
    struct known_hosts_s *known_hosts=NULL;
    FILE *fp=NULL;

    if ((filter & _KNOWN_HOST_FILTER_CA) && (filter & _KNOWN_HOST_FILTER_KEYS)) {

	*error=EINVAL;
	return NULL;

    }

    known_hosts=malloc(sizeof(struct known_hosts_s));

    if (known_hosts==NULL) {

	*error=ENOMEM;
	return NULL;

    }

    fp=get_openssh_known_hosts_file(pwd, error);

    if (fp==NULL) {

	free(known_hosts);
	return NULL;

    }

    known_hosts->fp=fp;
    known_hosts->line=NULL;
    known_hosts->filter=filter;
    known_hosts->host=NULL;
    known_hosts->type=NULL;
    known_hosts->key=NULL;

    return (void *) known_hosts;
}

int get_next_known_host_openssh(void *ptr, unsigned int *error)
{
    struct known_hosts_s *known_hosts=NULL;
    ssize_t size=0;
    size_t len=0;

    if (! ptr) return -1;

    known_hosts=(struct known_hosts_s *) ptr;

    nextline:

    if (known_hosts->line) {

	free(known_hosts->line);
	known_hosts->line=NULL;

    }

    known_hosts->host=NULL;
    known_hosts->type=NULL;
    known_hosts->key=NULL;

    size=getline(&known_hosts->line, &len, known_hosts->fp);

    if (size==-1 || known_hosts->line==NULL) {

	if (errno==ENOMEM) *error=errno;
	if (known_hosts->line) {

	    free(known_hosts->line);
	    known_hosts->line=NULL;

	}

	return -1;

    } else {
	char *sep=NULL;
	char *start=NULL;

	/* make sure the newline will not interfere */

	sep=strchr(known_hosts->line, '\n');
	if (sep) *sep='\0';

	len=strlen(known_hosts->line);

	start=known_hosts->line;
	while (start < known_hosts->line + len && isspace(*start)) start++;
	len=strlen(start);
	if (len==0) goto nextline;

	/* skip lines starting with a # (=comment) */

	if (strncmp(start, "#", 1)==0) goto nextline;

	/* skip lines starting with a | (=hashed hostnames) */

	if (strncmp(start, "|", 1)==0) goto nextline;

	if (strncmp(start, "@", 1)==0) {

	    if (len > 15) {

		if (strncmp(start, "@revoked ", 9)==0) goto nextline;

		if (strncmp(start, "@cert-authority ", 16)==0) {

		    if (!(known_hosts->filter & _KNOWN_HOST_FILTER_CA)) goto nextline;

		    start+=strlen("@cert-authority");
		    while ((start < known_hosts->line + len) && isspace(*start)) start++;
		    len=strlen(start);
		    if (len==0) goto nextline;

		} else {

		    goto nextline;

		}

	    } else {

		goto nextline;

	    }

	} else {

	    if (!(known_hosts->filter & _KNOWN_HOST_FILTER_KEYS)) goto nextline;

	}

	/* first field is host(s) */

	known_hosts->host=start;
	sep=strchr(start, ' ');
	if (sep==NULL) goto nextline;
	*sep='\0';

	/* second field is the type */

	start=sep+1;
	while (start < known_hosts->line + len && isspace(*start)) start++;
	len=strlen(start);
	if (len==0) goto nextline;
	known_hosts->type=start;
	sep=strchr(start, ' ');
	if (sep==NULL) goto nextline;
	*sep='\0';

	/* third field is the key (encoded) */

	start=sep+1;
	while (start < known_hosts->line + len && isspace(*start)) start++;
	len=strlen(start);
	if (len==0) goto nextline;
	known_hosts->key=start;
	sep=strchr(start, ' ');
	if (sep) *sep='\0';

	return 0;

    }

    return -1;

}

void *finish_known_hosts_openssh(void *ptr)
{
    struct known_hosts_s *known_hosts=(struct known_hosts_s *) ptr;

    if (known_hosts) {

	if (known_hosts->line) free(known_hosts->line);
	if (known_hosts->fp) fclose(known_hosts->fp);
	memset(known_hosts, 0, sizeof(struct known_hosts_s));
	free(known_hosts);

    }

}

static int is_host_pattern(char *host)
{
    return (strchr(host, '?') || strchr(host, '*'));
}

int compare_host_known_host_openssh(void *ptr, char *host)
{
    struct known_hosts_s *known_hosts=(struct known_hosts_s *) ptr;
    char *sep=NULL;
    char *start=NULL;
    int match=-1;

    if (! known_hosts) return -1;
    start=known_hosts->host;

    findhost:

    sep=strchr(start, ',');
    if (sep) *sep='\0';

    if (is_host_pattern(start)) {

	match=_match_pattern_host(host, start, 0);

    } else {

	if (strcmp(start, host)==0) match=0;

    }

    if (sep) {

	*sep=',';
	if (match==0) goto out;
	start=sep+1;
	goto findhost;

    }

    out:

    return match;

}

char *get_algo_known_host_openssh(void *ptr)
{
    struct known_hosts_s *known_hosts=(struct known_hosts_s *) ptr;
    return known_hosts->type;
}

int match_key_known_host_openssh(void *ptr, char *key, unsigned int len)
{
    struct known_hosts_s *known_hosts=(struct known_hosts_s *) ptr;
    gsize size=0;

    if (known_hosts==NULL || known_hosts->key==NULL) return -1;

    if (g_base64_decode_inplace((gchar *)known_hosts->key, &size)) {

	if (size==len && strcmp(key, (char *) known_hosts->key)==0) return 0;

    }

    return -1;
}
