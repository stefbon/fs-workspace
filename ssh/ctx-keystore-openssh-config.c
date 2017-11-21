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
#include <sys/fsuid.h>

#include "logging.h"
#include "main.h"
#include "pathinfo.h"
#include "simple-list.h"

#include "utils.h"
#include "options.h"

#include "ctx-keystore.h"
#include "ctx-keystore-openssh.h"
#include "ctx-keystore-openssh-utils.h"

static void str_tolower(char *string, unsigned int len)
{
    for (unsigned int i=0; i<len; i++) string[i]=tolower(string[i]);
}

static int _match_pattern_host(char *host, char *hostpattern, unsigned int level, unsigned int *flags)
{
    char *start=hostpattern;
    unsigned int len_h=strlen(hostpattern);
    char *pos_q=NULL;
    char *pos_s=NULL;
    char *pos=host;
    unsigned int len=strlen(host);

    if (level>20) return -1; /* not too deep recursion */

    pos_q=strchr(start, '?');
    pos_s=strchr(start, '*');

    while ((pos_q || pos_s) && pos < host + len) {

	*flags|=_IDENTITY_FLAG_WILDCARD;

	if (pos_q && (pos_s==NULL || (pos_s && pos_s>pos_q))) {

	    /* questionmark */

	    if (pos_q>start) {
		unsigned int bytes=(unsigned int) (pos_q - start);

		/* do the in between bytes match? */

		if (strncmp(pos, start, bytes)!=0) return -1;
		pos+=bytes;

	    }

	    pos++;
	    start=pos_q+1;

	    if (start==hostpattern+len_h) {

		if (pos==host+len) return 0;
		return -1;

	    }

	    pos_q=strchr(start, '?');
	    pos_s=strchr(start, '*');
	    continue;

	}

	if (pos_s && (pos_q==NULL || (pos_q && pos_q>pos_s))) {
	    char *help=NULL;

	    /* asterix */

	    if (pos_s>start) {
		unsigned int bytes=(unsigned int) (pos_s - start);

		/* do the in between bytes match? */

		if (strncmp(pos, start, bytes)!=0) return -1;
		pos+=bytes;

	    }

	    start=pos_s+1;

	    nextstring:

	    /* when nothing more in pattern then ready */

	    if (start>=hostpattern+len_h) return 0;

	    pos_q=strchr(start, '?');
	    pos_s=strchr(start, '*');
	    help=NULL;

	    /* look for the following string after the "*" : it must be in host
		a pattern like a*bcd matches aabcd but also aabcbcd
	    */

	    if (pos_s && (pos_q==NULL || (pos_q && pos_q>pos_s))) {

		help=pos_s;

	    } else if (pos_q && (pos_s==NULL || (pos_s && pos_s>pos_q))) {

		help=pos_q;

	    }

	    if (help==start) {

		start++;
		goto nextstring;

	    }

	    if (help) {
		unsigned int tmp=(unsigned int) (help-start);
		char string[tmp+1];
		char *sep=NULL;

		/* the string between "*" and next pattern character must be present in host */

		memcpy(string, start, tmp);
		string[tmp]='\0';

		/* this string may be more than once in host and the "*" can expand to anything so try every occurence */

		findstring:

		sep=strstr(pos, string);
		if (sep==NULL) return -1;

		pos=sep+tmp;
		start=help;

		if (_match_pattern_host(pos, start, level+1, flags)==0) return 0;
		goto findstring;

	    } else {
		unsigned int tmp=strlen(start);

		/* no more patterns in the rest, this rest must be the last part of host */

		if (strlen(pos)>=tmp && strcmp(host+len-tmp, start)==0) {

		    return 0;

		} else {

		    return -1;

		}

	    }

	}

    }

    if ((pos < host + len) && (start < hostpattern + len_h)) {

	if (strcmp(pos, start)==0) return 0;

    }

    return -1;

}

static int match_pattern_host(char *host, char *hostpattern, unsigned int *flags)
{

    if (strcmp(hostpattern, "*")==0) {

	*flags|=_IDENTITY_FLAG_DEFAULT;
	return 0;

    }

    return _match_pattern_host(host, hostpattern, 0, flags);

}

static int match_patterns_hostaddress(struct hostaddress_s *hostaddress, char *hostpattern, unsigned int *flags)
{
    int result=-1;
    char *address[2];

    address[0]=hostaddress->hostname;
    address[1]=hostaddress->ip;

    for (unsigned int i=0; i<2; i++) {

	/* test the hostpattern matches the hostname, and if not try the ip address */

	if (address[i]) {
	    char *sep=NULL;
	    char *pos=hostpattern;

	    /* proccess any pattern found (seperated by comma's) */

	    nextpattern:

	    sep=strchr(pos, ',');
	    if (sep) *sep='\0';

	    *flags=0;
	    result=match_pattern_host(address[i], pos, flags);

	    if (sep) *sep=',';

	    if (result==0) {

		logoutput("match_patterns_hostaddress: match with pattern %s", hostpattern);
		break;

	    }

	    if (sep) goto nextpattern;

	}

    }

    return result;

}

static unsigned char check_add_host_section(struct public_keys_s *keys, const char *what, struct hostaddress_s *hostaddress, char *hostpattern, char *hostname, char **pidentityfile, char **puser)
{
    struct common_identity_s *identity=NULL;
    unsigned int flags=0;

    if (hostpattern==NULL) return 0;

    if (match_patterns_hostaddress(hostaddress, hostpattern, &flags)==-1) return 0; /* zero means no identity */

    /* section applies to the host */

    if (hostname) {

	if (hostaddress->hostname && hostaddress->ip) {

	    if (strcmp(hostname, hostaddress->hostname)!=0 && strcmp(hostname, hostaddress->ip)!=0) {

		logoutput("check_add_host_section: hostname found in openssh config %s does not match name and ip connected host %s/%s", hostname, hostaddress->hostname, hostaddress->ip);

	    }

	} else if (hostaddress->hostname) {

	    if (strcmp(hostname, hostaddress->hostname)!=0) {

		logoutput("check_add_host_section: hostname found in openssh config %s does not match name connected host %s", hostname, hostaddress->hostname);

	    }

	} else if (hostaddress->ip) {

	    if (strcmp(hostname, hostaddress->ip)!=0) {

		logoutput("check_add_host_section: hostname found in openssh config %s does not match ip connected host %s", hostname, hostaddress->ip);

	    }

	}

    }

    identity=malloc(sizeof(struct common_identity_s));
    if (identity==NULL) return 0;

    identity->ptr=(void *) keys;
    identity->flags=_IDENTITY_FLAG_OPENSSH | flags;

    if (*pidentityfile) {

	identity->file=*pidentityfile;
	*pidentityfile=NULL;

    } else {

	identity->file=NULL;

    }

    if (*puser) {

	identity->user=*puser;
	*puser=NULL;

    }

    identity->list.next=NULL;
    identity->list.prev=NULL;

    if (strcmp(what, "user")==0) identity->flags|=_IDENTITY_FLAG_USER;
    add_list_element_last(&keys->head, &keys->tail, &identity->list);

    return 1;

}

static int get_size_FILE(FILE *fp)
{
    int fd=fileno(fp);
    struct stat st;

    if (fstat(fd, &st)==0) return st.st_size;
    return 0;

}

/* read the remote user (and possibly a public key) from the openssh configuration for this user and host
    TODO: enable processing of escape characters:
    - %d local user home directory
    - %u local user name
    - %l local host name
    - %h remote host name
    - %r remote user name
    and enable more identity files
*/

static int _get_openssh_config(struct public_keys_s *keys, char *file, const char *what, struct hostaddress_s *hostaddress, unsigned int *error)
{
    FILE *fp=NULL;
    unsigned int size=0;
    int result=0;

    fp=fopen(file, "r");

    if (! fp) {

	*error=errno;
	logoutput("_get_openssh_config: unable to open file %s error %i (%s)", file, *error, strerror(*error));
	return -1;

    }

    logoutput("_get_openssh_config: open file %s", file);
    size=get_size_FILE(fp);

    /* TODO: some checking on sane maximum size */

    if (size>0) {
	char buffer[size];
	char *sep=NULL;
	char *start=NULL;
	unsigned int len=0;

	memset(buffer, '\0', size);

	/* outer loop: look for a host section */

	while (fgets(buffer, size, fp)) {

	    sep=strchr(buffer, '\n');
	    if (sep) *sep='\0';
	    start=buffer;
	    len=strlen(start);

	    while ((start < buffer + len) && isspace(*start)) start++;
	    if (start>buffer) len=strlen(start);
	    if (len==0) continue;

	    readsection:

	    /* skip lines starting with a # (=comment) */
	    if (strncmp(start, "#", 1)==0) continue;

	    /* keyword /first field to lower */

	    sep=strchr(start, ' ');
	    if (sep==NULL) continue;
	    str_tolower(start, (unsigned int) (sep - start));

	    /* look for the "host" keyword */

	    if (len>5 && strncmp(start, "host ", 5)==0) {
		char *hostpattern=NULL;
		char *hostname=NULL;
		char *user=NULL;
		char *identityfile=NULL;

		logoutput("_get_openssh_config: host section %s found", start);

		start+=5;
		while ((start < buffer + len) && isspace(*start)) start++;
		len=strlen(start);
		if (len==0) continue;

		/* hostpattern can be a nickname or a pattern to test the hostname */

		hostpattern=malloc(len+1);
		if (hostpattern==NULL) continue;
		strcpy(hostpattern, start);

		/* read lines starting with a space */

		while (fgets(buffer, size, fp)) {

		    sep=strchr(buffer, '\n');
		    if (sep) *sep='\0';
		    start=buffer;
		    len=strlen(start);
		    if (len==0) continue;

		    /* skip the starting spaces but ther must be at least one */

		    if (strncmp(start, " ", 1)!=0) break;
		    while ((start < buffer + len) && isspace(*start)) start++;
		    len=strlen(start);
		    if (len==0) continue;

		    /* keyword / first field to lower */

		    sep=strchr(start, ' ');
		    if (sep==NULL) continue;
		    str_tolower(start, (unsigned int) (sep - start));

		    if (len>9 && strncmp(start, "hostname ", 9)==0) {

			start+=9;
			len=strlen(start);
			if (len==0) continue;

			logoutput("_get_openssh_config: hostname %s found", start);

			if (hostname==NULL) {

			    hostname=malloc(len+1);
			    if (hostname) {

				strcpy(hostname, start);

			    } else {

				logoutput("_get_openssh_config: error allocating memory for %s", start);

			    }

			} else {

			    logoutput("_get_openssh_config: error hostname already found %s - %s", hostname, start);

			}

		    }

		    if (len>13 && strncmp(start, "identityfile ", 13)==0) {

			start+=13;
			len=strlen(start);
			if (len==0) continue;

			logoutput("_get_openssh_config: identityfile %s found", start);

			if (identityfile==NULL) {

			    identityfile=malloc(len+1);
			    if (identityfile) {

				strcpy(identityfile, start);

			    } else {

				logoutput("_get_openssh_config: error allocating memory for %s", start);

			    }

			} else {

			    logoutput("_get_openssh_config: error identityfile already found %s - %s", identityfile, start);

			}

		    }

		    if (len>5 && strncmp(start, "user ", 5)==0) {

			start+=5;
			len=strlen(start);
			if (len==0) continue;

			logoutput("_get_openssh_config: user %s found", start);

			if (user==NULL) {

			    user=malloc(len+1);
			    if (user) {

				strcpy(user, start);

			    } else {

				logoutput("_get_openssh_config: error allocating memory for %s", start);

			    }

			} else {

			    logoutput("_get_openssh_config: error user already found %s - %s", user, start);

			}

		    }

		}

		/* process the values found */

		if (identityfile) result+=check_add_host_section(keys, what, hostaddress, hostpattern, hostname, &identityfile, &user);

		if (hostname) free(hostname);
		if (hostpattern) free(hostpattern);
		if (identityfile) free(identityfile);
		if (user) free(user);

		if (feof(fp)) break;
		goto readsection;

	    }

	}

    } else {

	logoutput("get_openssh_host_config: error %i getting stat (%s)", errno, strerror(errno));

    }

    close:
    fclose(fp);

    return result;

}

static unsigned int get_configpath_openssh_common(struct passwd *pwd, const char *what, char *buffer, unsigned int len)
{

    if (strcmp(what, "user")==0) {

	return get_path_openssh_user(pwd, "ssh_config", buffer, len);

    } else if (strcmp(what, "host")==0) {

	return get_path_openssh_system("ssh_config", buffer, len);

    }

    return 0;

}

/* get identity records for hostaddress from configuration
    this function searches the openssh configuration for the user and identity file to use to use to login
    on the host "hostaddress"
*/

int get_identity_records_openssh_config(struct public_keys_s *keys, struct hostaddress_s *hostaddress, const char *what, unsigned int *error)
{
    int result=0;

    /* keys for user or host */

    if (strcmp(what, "user")==0) {
	unsigned int len=get_path_openssh_user(keys->pwd, "ssh_config", NULL, 0);

	/* try first the personal .ssh_config */

	if (len>0) {
	    char fullpath[len];

	    if (get_path_openssh_user(keys->pwd, "ssh_config", fullpath, len)>0) {

		result+=_get_openssh_config(keys, fullpath, what, hostaddress, error);

	    }

	}

	/* second try the host wide ssh_config */

	len=get_path_openssh_system("ssh_config", NULL, 0);

	if (len>0) {
	    char fullpath[len];

	    if (get_path_openssh_system("ssh_config", fullpath, len)>0) {

		result+=_get_openssh_config(keys, fullpath, what, hostaddress, error);

	    }

	}

    } else if (strcmp(what, "host")==0) {

	logoutput("get_identity_records_openssh_config: no support for host keys");

    } else {

	logoutput("get_identity_records_openssh_config: %s not reckognized");

    }

    return result;

}
