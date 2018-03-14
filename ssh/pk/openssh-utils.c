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

#include <stdio.h>
#include <stdlib.h>
#include <stddef.h>
#include <stdbool.h>
#include <string.h>
#include <unistd.h>
#include <sys/time.h>
#include <time.h>
#include <ctype.h>
#include <inttypes.h>

#include <sys/param.h>
#include <sys/types.h>
#include <sys/stat.h>

#include <logging.h>
#include <utils.h>

/* test the host is matched by hostpattern
    hostpattern can contain a '?' and a '*' */

int _match_pattern_host(char *host, char *hostpattern, unsigned int level)
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

		if (_match_pattern_host(pos, start, level+1)==0) return 0;
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

/*	get the path of user related openssh files on standard locations */

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

/* get the path of system related openssh files on standard locations */

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

unsigned int get_directory_openssh_common(struct passwd *pwd, const char *what, char *buffer, unsigned int len)
{

    if (strcmp(what, "user")==0) {

	return get_path_openssh_user(pwd, NULL, buffer, len);

    } else if (strcmp(what, "system")==0) {

	return get_path_openssh_system(NULL, buffer, len);

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
