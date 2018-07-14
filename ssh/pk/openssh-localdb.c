/*
  2010, 2011, 2012, 2103, 2014, 2015, 2016, 2017, 2018 Stef Bon <stefbon@gmail.com>

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
#include <errno.h>
#include <err.h>
#include <sys/time.h>
#include <time.h>
#include <ctype.h>
#include <inttypes.h>

#include <sys/param.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/fsuid.h>

#include "logging.h"
#include "main.h"
#include "utils.h"
#include "network-utils.h"

#include "ssh-datatypes.h"
#include "ssh-utils.h"

#include "pk-types.h"
#include "pk-keys.h"
#include "pk-utils.h"

#include "openssh-utils.h"

static int get_openssh_known_hosts_path(char *path, size_t size, struct passwd *pwd, const char *what)
{

    if (strcmp(what, "user")==0) {

	/* user */

	if (path) {

	    return snprintf(path, size, "%s/.ssh/known_hosts", pwd->pw_dir);

	} else {

	    return strlen(pwd->pw_dir) + strlen("/.ssh/known_hosts") + 1;

	}

    } else if (strcmp(what, "system")==0) {

	/* system */

	if (path) {

	    return snprintf(path, size, "/etc/ssh/ssh_known_hosts");

	} else {

	    return strlen("/etc/ssh/ssh_known_hosts") + 1;

	}

    }

    return 0;

}

static FILE *get_openssh_known_hosts_file(struct passwd *pwd, const char *what, unsigned int *error)
{
    int len = get_openssh_known_hosts_path(NULL, 0, pwd, what);
    char path[len];
    FILE *fp=NULL;

    if (get_openssh_known_hosts_path(path, len, pwd, what)>0) {
	uid_t uid_keep=setfsuid(pwd->pw_uid);
	gid_t gid_keep=setfsgid(pwd->pw_gid);

	logoutput("get_openssh_known_hosts_file: %s", path);

	fp=fopen(path, "r");
	if (! fp) *error=errno;

	setfsuid(uid_keep);
	setfsgid(gid_keep);

    }

    return fp;

}

static void clear_cntrl_char(char *line, size_t len)
{
    char *pos=line;

    while (pos < (char *)(line + len)) {

	if (iscntrl(*pos)) *pos=' ';
	pos++;

    }

}

static int is_host_pattern(char *host)
{
    return (strchr(host, '?') || strchr(host, '*'));
}

/*	check the specification of the host matches the ipv4 or the hostname
	note host can be more than one specification, seperated by a comma
*/

static int compare_host_openssh(char *host, char *ipv4, char *hostname)
{
    char *sep=NULL;
    char *start=host;
    int match=-1;

    findhost:

    sep=strchr(start, ',');
    if (sep) *sep='\0';

    if (is_host_pattern(start)) {

	match=_match_pattern_host(ipv4, start, 0);
	if (match==-1) match=_match_pattern_host(hostname, start, 0);

    } else {

	if (strcmp(start, ipv4)==0) {

	    match=0;

	} else if (strcmp(start, hostname)==0) {

	    match=0;

	}

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

/* look in the file fp for a hostkey */

static int _check_serverkey_pk(FILE *fp, char *remotehost, char *remoteipv4, struct ssh_key_s *key, const char *what, unsigned int *error)
{
    int result=-1;
    char *line=NULL;
    size_t size=0;
    char *start=NULL;
    char *sep=NULL;
    unsigned int len=0;

    while (getline(&line, &size, fp)>0) {

	len=(unsigned int) size;
	sep=memchr(line, '\n', size);
	if (sep) {

	    *sep='\0';
	    len=strlen(line); /* equal (unsigned int) (sep - line) */

	}

	if (len==0) continue;
	clear_cntrl_char(line, len);
	if ( line[0] == '#' || line[0] == '|' ) continue;

	if (strcmp(what, "ca")==0) {
	    unsigned int tmp=strlen("@cert-authority");

	    /* look for lines starting with @cert-authority */

	    if (line[0] != '@') continue;
	    if (len <= tmp + 1) continue;
	    if (memcmp(line, "@cert-authority ", tmp+1)!=0) continue;

	    start = line + tmp + 1;
	    len=(unsigned int) strlen(start);

	} else {

	    if (line[0] == '@') continue;
	    start=line;

	}

	sep=memchr(start, ' ', len);

	if (sep) {

	    /* host (pattern) */

	    *sep='\0';

	    if (compare_host_openssh(start, remoteipv4, remotehost)==-1) {

		*sep=' ';
		continue;

	    }

	    *sep=' ';
	    while (sep < (char *) (start + len) && isspace(*sep)) sep++;
	    start=sep;
	    len=(unsigned int) strlen(start);

	} else {

	    continue;

	}

	sep=memchr(start, ' ', len);

	if (sep) {
	    struct ssh_pkalgo_s *algo=NULL;

	    /* algo */

	    *sep='\0';

	    algo=get_pkalgo(start, strlen(start), NULL);

	    if (algo == NULL) {

		*sep=' ';
		continue;

	    } else if (algo != key->algo) {

		*sep=' ';
		continue;

	    }

	    *sep=' ';

	    while (sep < (char *) (start + len) && isspace(*sep)) sep++;
	    start=sep;
	    len=(unsigned int) strlen(start);

	} else {

	    continue;

	}

	sep=memchr(start, ' ', len);
	if (sep) *sep='\0';
	len=(unsigned int) strlen(start);

	if (len>0) {
	    struct ssh_string_s decoded;

	    init_ssh_string(&decoded);

	    /* key field is base64 encoded */

	    len=decode_buffer_base64(start, len, &decoded);

	    if (decoded.len > 0) {

		/* decoded data is in SSH format */

		result=(* key->compare_key_data)(key, decoded.ptr, decoded.len, PK_DATA_FORMAT_SSH);
		free_ssh_string(&decoded);
		if (result==0) break;

	    }

	    free_ssh_string(&decoded);

	}

    }

    out:

    if (line) free(line);
    return result;

}

/* check the server hostkey against the personal known_hosts file */

int check_serverkey_openssh(unsigned int fd, struct passwd *pwd, struct ssh_key_s *pkey, const char *what)
{
    FILE *fp = NULL;
    unsigned int error=0;
    char *remotehost=NULL;
    char *remoteipv4=NULL;
    int result=-1;

    remotehost=get_connection_hostname(fd, 1, &error);

    if (remotehost==NULL) {

	logoutput("check_serverkey: error %i getting remote hostname (%s)", error, strerror(error));
	goto finish;

    }

    remoteipv4=get_connection_ipv4(fd, 1, &error);

    if (remoteipv4==NULL) {

	logoutput("check_serverkey: error %i getting remote ipv4 (%s)", error, strerror(error));
	goto finish;

    }

    /* try user's known hosts */

    fp = get_openssh_known_hosts_file(pwd, "user", &error);

    if (fp) {

	result=_check_serverkey_pk(fp, remotehost, remoteipv4, pkey, what, &error);
	fclose(fp);
	if (result==0) goto finish;

    } else {

	if (error!=ENOENT) {

	    logoutput("check_serverkey: error %i looking for users known hosts file (%s)", error, strerror(error));

	}

    }

    /* try system's known hosts */

    fp = get_openssh_known_hosts_file(pwd, "system", &error);

    if (fp) {

	result=_check_serverkey_pk(fp, remotehost, remoteipv4, pkey, what, &error);
	fclose(fp);

    } else {

	if (error!=ENOENT) {

	    logoutput("check_serverkey: error %i looking for systems known hosts file (%s)", error, strerror(error));

	}

    }

    finish:

    if (remotehost) free(remotehost);
    if (remoteipv4) free(remoteipv4);

    return result;

}
