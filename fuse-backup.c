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
#include <sys/vfs.h>

#include "logging.h"
#include "main.h"
#include "pathinfo.h"
#include "utils.h"
#include "options.h"
#include "fuse-dentry.h"
#include "fuse-directory.h"
#include "fuse-utils.h"

#include "fuse-interface.h"
#include "fuse-fs.h"
#include "workspaces.h"
#include "path-caching.h"
#include "workerthreads.h"
#include "simple-hash.h"

#include "sftp/common-protocol.h"
#include "sftp/send-common.h"
#include "backup/backup-common.h"
#include "sftp/fuse-sftp-common.h"
#include "sftp/attr-common.h"
#include "ssh/datatypes/ssh-uint.h"
#include "ssh/ssh-utils.h"

#include "handlemime.h"
#include "backup/send.h"

extern unsigned char wait_sftp_service_complete_ctx(struct context_interface_s *interface, struct timespec *timeout, unsigned int *error);
extern struct fs_options_s fs_options;

static void process_backupscripts(void *ptr)
{
    logoutput_info("process_backupscripts");
}

static unsigned int get_mimetype_common(char *path, char *name, char *buffer, unsigned int size)
{
    unsigned int len=strlen(path) + strlen(name) + 2;
    char fullpath[len];

    if (snprintf(fullpath, len, "%s/%s", path, name)>0) return get_mimetype(fullpath, buffer, size);
    return 0;
}

static int get_stat(char *path, char *name, struct stat *st)
{
    unsigned int len=strlen(path) + strlen(name) + 2;
    char fullpath[len];

    if (snprintf(fullpath, len, "%s/%s", path, name)>0) return stat(fullpath, st);
    return -1;

}

/* synchronize the local file with the version on the server
    - interface				reference to sftp subsystem
    - backup				reference to backup on server
    - name				name of file relative to the backup directory
    - st				stat attributes
    - what				bits to synchronize (FATTR_MTIME, FATTR_UID, FATTR_SIZE etc from linux/fuse.h)
    */

static void sync_localfile_remote(struct context_interface_s *interface, struct backup_s *backup, char *name, int fd, struct stat *st, int what)
{
    struct backuphandle_s handle;
    struct fuse_sftp_attr_s fuse_attr;
    unsigned int size=get_attr_buffer_size(interface->ptr, st, what, &fuse_attr, 1); 
    char attrbuffer[size]; /* buffer for sending and receiving sftp attributes */
    int result=0;

    memset(handle.buffer, '\0', BACKUPHANDLE_SIZE);
    handle.flags=0;
    handle.len=0;
    handle.fd=fd;
    handle.valid=0;
    handle.set=0;
    handle.error=0;

    size=write_attributes_ctx(interface->ptr, attrbuffer, size, &fuse_attr);
    if (size>=4) handle.valid=get_uint32(attrbuffer); /* first four bytes are the valid parameter */

    result=send_createfile_backup(interface, backup, name, &handle, attrbuffer, size);

    if (result==-1) {

	logoutput_info("sync_localfile_remote: send createfile failed");
	return;

    } else if (result==0) {

	logoutput_info("sync_localfile_remote: ready");
	return;

    }

    /* check the mtime is requested and differs:
	only then the backup file differs and sync of the file contents is required */

    /* TODO:
	use librsync to use a method using less io
	- create and keep signature every file on server
	- clients get signature (eventually keep) and make delta with current version
	- client copies delta to server (if there is a signaficant difference) and server patches the backup */

    if (get_attribute_info_ctx(interface->ptr, handle.valid, "mtime")>0 && get_attribute_info_ctx(interface->ptr, handle.set, "mtime")>0) {
	unsigned int blocksize=4096; /* default, get it from somewhere, a statvfs call to remote server */
	off_t offset=0;
	char bytes[blocksize];
	ssize_t read=0;

	logoutput_warning("sync_localfile_remote: send whole file (%i bytes)", st->st_size);

	while (offset < st->st_size) {
	    unsigned char eof=0;

	    read=pread(handle.fd, bytes, blocksize, offset); /* pread will automatically read less bytes then requested when offset + blocksize exceeds the file size */
	    if (offset + blocksize >= size) eof=1;

	    if (read>0) {
		int written=send_writefile_backup(interface, &handle, offset, bytes, read, &eof);

		if (written==-1) {

		    break;

		} else if (read != written) {

		    if (eof==0) logoutput_warning("sync_localfile_remote: bytes written on server %i differs from bytes read %i", write, read);

		}

	    }

	    offset+=read;

	}

    }

    send_releasefile_backup(interface, &handle, name);

}

static void backup_directory(struct backup_s *backup)
{
}

static int match_backup_mimetype(struct list_element_s *list, void *ptr)
{
    struct backupmime_s *nmime=(struct backupmime_s *) (((char *) list) - offsetof(struct backupmime_s, list));
    struct backupmime_s *mime=(struct backupmime_s *) ptr;

    if (nmime->len==mime->len && memcmp(nmime->name, mime->name, mime->len)==0) return 0;
    return -1;
}

static void read_user_backups(uid_t uid, struct list_header_s *header)
{
    struct passwd *pw=getpwuid(uid);
    unsigned int len=(pw) ? (strlen(pw->pw_dir) + 64) : 0;
    char path[len];

    if (pw && snprintf(path, len, "%s/.config/backup", pw->pw_dir)>0) {
	FILE *fp=fopen(path, "r");

	if (fp) {
	    char *line=NULL;
	    size_t size=0;
	    struct backup_s *backup=NULL;

	    while (getline(&line, &size, fp)!=-1) {
		char *sep=memchr(line, '\n', size);

		if (sep) {

		    *sep='\0';
		    size=(unsigned int)(sep - line);

		}

		if (size>7 && strncmp(line, "backup=", 7)==0) {
		    char *value=memchr(line, '=', size);

		    if (backup) {

			if ((backup->flags & BACKUP_FLAG_MIMETYPES)==0) free(backup);
			backup=NULL;

		    }

		    /* value is the path to backup */

		    if (value) {
			struct stat st;

			value++;

			if (stat(value, &st)==0 && S_ISDIR(st.st_mode)) {

			    backup=create_backup(0, value);

			    if (backup==NULL) {

				logoutput("process_backups: error creating backup");
				goto readyout;

			    }

			}

		    }

		} else if (size>5 && strncmp(line, "mime=", 5)==0) {

		    /* the mimetypes belonging to this backup */

		    if (backup) {
			char *value=memchr(line, '=', size);

			if (value) {
			    char *name=NULL;
			    char *sep=NULL;
			    unsigned int left=0;

			    value++;
			    name=value;

			    searchmime:

			    if (line + size > name) {

				left=(unsigned int)(line + size - name);
				sep=memchr(name, ';', left);

			    } else {

				sep=NULL;

			    }

			    if (sep) {

				*sep='\0';

				if (add_backupmime(backup, name)) backup->flags |= BACKUP_FLAG_MIMETYPES;
				name=sep+1;
				goto searchmime;

			    }

			    if (backup->flags & BACKUP_FLAG_MIMETYPES) {

				logoutput("read_user_backups: add backup %s", backup->path);
				add_list_element_last(header, &backup->list);

			    } else {

				free(backup);

			    }

			    backup=NULL;

			}

		    }

		}

	    }

	    readyout:

	    if (line) free(line);
	    if (backup && (backup->flags & BACKUP_FLAG_MIMETYPES)==0) free(backup);
	    fclose(fp);

	}

	if (header->count>1) {
	    struct list_element_s *list=get_list_head(header, 0);

	    /* remove any doubles */

	    while (list) {
		struct backup_s *backup=(struct backup_s *) ( ((char *) list) - offsetof(struct backup_s, list));
		struct list_element_s *nlist=get_next_element(list);

		while (nlist) {
		    struct backup_s *nbackup=(struct backup_s *) ( ((char *) nlist) - offsetof(struct backup_s, list));
		    struct list_element_s *next=get_next_element(nlist);

		    if (strcmp(backup->path, nbackup->path)==0) {
			struct list_element_s *mlist=NULL;

			logoutput_warning("read_user_backups: directory %s mas multiple entries: change that in %s", backup->path, path);
			mlist=get_list_head(&nbackup->mime, SIMPLE_LIST_FLAG_REMOVE);

			while (mlist) {

			    /* doubles are possible and harmless */
			    add_list_element_last(&backup->mime, mlist);
			    mlist=get_list_head(&nbackup->mime, SIMPLE_LIST_FLAG_REMOVE);

			}

			remove_list_element(&nbackup->list);
			free(nbackup);

		    }

		    nlist=next;

		}

		list=get_next_element(list);

	    }

	}

    }

}

/* get the mimetype of an entry in backup directory and match it to an mimetype belonging to this backup */

static struct backupmime_s *match_backup_mime(struct backup_s *backup, char *name)
{
    char buffer[256];
    unsigned int len=0;
    struct backupmime_s *mime=NULL;

    /* get the mimetype of file */

    memset(buffer, '\0', 256);
    len=get_mimetype_common(backup->path, name, buffer, 256);

    if (len>0) {
	struct list_element_s *list=NULL;

	/* check the mimetype is one of the mimetypes to backup */

	list=get_list_head(&backup->mime, 0);

	while (list) {

	    mime=(struct backupmime_s *) (((char *) list) - offsetof(struct backupmime_s, list));
	    if (mime->len==len && strncmp(mime->name, buffer, len)==0) break;
	    list=get_next_element(list);
	    mime=NULL;

	}

    }

    return mime;

}

static void process_backups(void *ptr)
{
    struct service_context_s *context=(struct service_context_s *) ptr;
    struct context_interface_s *interface=&context->interface;
    unsigned int error=0;
    struct list_header_s tmp=INIT_LIST_HEADER;
    struct list_element_s *list=NULL;
    struct timespec timeout;

    /* create a temporary list header to store the backups found */

    init_list_header(&tmp, SIMPLE_LIST_TYPE_EMPTY, NULL);

    logoutput("process_backups");

    /* wait for context/interface/connection is complete/online and up */

    timeout.tv_sec=5;
    timeout.tv_nsec=0;

    if (wait_sftp_service_complete_ctx(interface, &timeout, &error)==0) {

	logoutput("process_backups: sftp service not completed, error %i:%s", error, strerror(error));
	goto out;

    }

    open_mimedb();
    read_user_backups(context->workspace->user->uid, &tmp);

    /* walk every backup, get the rules per backup, and compare every entry in backup which is of the mimetype */

    list=get_list_head(&tmp, SIMPLE_LIST_FLAG_REMOVE);

    while (list) {
	struct backup_s *backup=(struct backup_s *) ( ((char *) list) - offsetof(struct backup_s, list));
	struct stat st;

	if (stat(backup->path, &st)==-1) goto nextbackup;

	if (send_create_backup(context, backup, &st)==0) {
	    DIR *dp=NULL;
	    struct dirent *de=NULL;
	    int dfd=0;

	    logoutput("process_backups: received id %lli for backup path=%.*s", backup->id, backup->len, backup->path);

	    add_backup_backuphash(backup);
	    backup->flags|=BACKUP_FLAG_HASHED;

	    dp=opendir(backup->path);
	    if (dp==NULL) continue;
	    dfd=dirfd(dp);
	    de=readdir(dp);

	    while (de) {
		char buffer[256];
		unsigned int len=0;
		struct list_element_s *list=NULL;
		struct backupmime_s *mime=NULL;

		if (strcmp(de->d_name, ".")==0 || strcmp(de->d_name, "..")==0 || de->d_type != DT_REG) goto nextfile;

		/* get the mimetype of file and test it's a mime to backup */

		mime=match_backup_mime(backup, de->d_name);

		if (mime) {
		    int fd=0;

		    fd=openat(dfd, de->d_name, O_RDONLY);

		    if (fd>0) {

			if (fstat(fd, &st)==0) sync_localfile_remote(interface, backup, de->d_name, fd, &st, FATTR_SIZE | FATTR_MTIME | FATTR_MODE | FATTR_UID | FATTR_GID);
			close(fd);

		    }

		}

		nextfile:
		de=readdir(dp);

	    }

	    closedir(dp);

	}

	nextbackup:
	list=get_list_head(&tmp, SIMPLE_LIST_FLAG_REMOVE);

    }

    out:
    close_mimedb();

}

/* start a baskup service for user
    context/workspace is the mountpoint
*/

void start_backup_service(struct service_context_s *context)
{
    unsigned int error=0;

    logoutput("start_backup_service");
    work_workerthread(NULL, 0, process_backups, (void *) context, &error);

}

void start_backupscript_service(struct service_context_s *context)
{
    unsigned int error=0;

    logoutput("start_backupscript_service");
    work_workerthread(NULL, 0, process_backupscripts, (void *) context, &error);

}
