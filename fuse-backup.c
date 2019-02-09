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

#include "sftp/sftp-common-protocol.h"
#include "sftp/sftp-send-common.h"
#include "backup/backup-common.h"
#include "sftp/fuse-sftp-common.h"
#include "sftp/sftp-attr-common.h"
#include "ssh/datatypes/ssh-uint.h"
#include "ssh/datatypes/ssh-namelist.h"
#include "ssh/ssh-utils.h"

#include "handlemime.h"

extern void *create_sftp_request_ctx(void *ptr, struct sftp_request_s *sftp_r, unsigned int *error);
extern unsigned char wait_sftp_response_ctx(struct context_interface_s *i, void *r, struct timespec *timeout, unsigned int *error);
extern void get_sftp_request_timeout(struct timespec *timeout);
extern unsigned int get_sftp_interface_info(struct context_interface_s *interface, const char *what, void *data, struct common_buffer_s *buffer);
extern unsigned char wait_sftp_service_complete_ctx(struct context_interface_s *interface, struct timespec *timeout, unsigned int *error);
extern unsigned char name_found_commalist(char *, char *);

extern struct fs_options_s fs_options;

static void process_backupscripts(void *ptr)
{
    logoutput_info("process_backupscripts");
}

static unsigned int get_mimetype_common(char *path, char *name, char *buffer, unsigned int size)
{
    unsigned int len=strlen(path) + strlen(name) + 2;
    char fullpath[len];

    if (snprintf(fullpath, len, "%s/%s", path, name)>0) {

	logoutput_info("get_mimetype: path %s", fullpath);
	return get_mimetype(fullpath, buffer, size);

    }

    return 0;
}

static int get_stat(char *path, char *name, struct stat *st)
{
    unsigned int len=strlen(path) + strlen(name) + 2;
    char fullpath[len];

    if (snprintf(fullpath, len, "%s/%s", path, name)>0) {

	logoutput_info("get_stat: %s", fullpath);
	return stat(fullpath, st);

    }

    return -1;
}

static void copy_localfile_remote(struct context_interface_s *interface, struct backup_s *backup, char *name, struct stat *st)
{
    /* copy local file to server, how?
	- create file in remote directory
	- write/copy contents
	- compare result and release
    */

    /*
	createfile@backup.bononline.nl
	writefile@backup.bononline.nl
	releasefile@backup.bononline.nl
    */

    /* TODO: for existing files only copy the region which is relevant: which has been changed */

    struct sftp_request_s sftp_r;
    char handle[128]; /* 128 must be enough */
    unsigned int lenhandle=0;
    char connectionstatus[4];
    struct common_buffer_s bufferstatus;
    struct fuse_sftp_attr_s fuse_attr;
    unsigned int size=get_attr_buffer_size(interface->ptr, st, FATTR_UID | FATTR_GID | FATTR_MODE | FATTR_SIZE | FATTR_MTIM, &fuse_attr, 1);
    char attrbuffer[size];
    char path[backup->len + strlen(name) + 2];

    snprintf(path, backup->len + strlen(name) + 2, "%.*s/%s", backup->len, backup->path, name);

    logoutput("copy_localfile_remote: copy %s to server", path);

    bufferstatus.ptr=connectionstatus;
    bufferstatus.size=4;
    bufferstatus.len=bufferstatus.size;
    bufferstatus.pos=bufferstatus.ptr;

    if (get_sftp_interface_info(interface, "status", NULL, &bufferstatus)==4) {
	unsigned int error=get_uint32(connectionstatus);

	logoutput_info("copy_localfile_remote: error %i (%s)", error, strerror(error));
	return;

    }

    size=write_attributes_ctx(interface->ptr, attrbuffer, size, &fuse_attr);

    memset(handle, '\0', 128);
    memset(&sftp_r, 0, sizeof(struct sftp_request_s));

    sftp_r.id=0;
    sftp_r.call.createfile.id=backup->id;
    sftp_r.call.createfile.name=name;
    sftp_r.call.createfile.len=strlen(name);
    sftp_r.call.createfile.buffer=(unsigned char *) attrbuffer;
    sftp_r.call.createfile.size=size;
    sftp_r.fuse_request=NULL;

    if (send_sftp_createfile_ctx(interface->ptr, &sftp_r)>=0) {
	unsigned int error=0;
	void *request=create_sftp_request_ctx(interface->ptr, &sftp_r, &error);

	if (request) {
	    struct timespec timeout;

	    get_sftp_request_timeout(&timeout);
	    error=0;

	    if (wait_sftp_response_ctx(interface, request, &timeout, &error)==1) {

		if (sftp_r.type==SSH_FXP_HANDLE) {
		    unsigned long long id=get_uint64(sftp_r.response.handle.name);

		    memcpy(handle, sftp_r.response.handle.name, sftp_r.response.handle.len);
		    logoutput("copy_localfile_remote: received handle %lli", id);
		    lenhandle=sftp_r.response.handle.len;

		} else if (sftp_r.type==SSH_FXP_STATUS) {

		    if (sftp_r.response.status.code==0) {

			logoutput("copy_localfile_remote: %s created on server", name);

		    } else {

			logoutput("copy_localfile_remote: received status %i", sftp_r.response.status.code);

		    }

		}

	    }

	}

    }

    unsigned int blocksize=4096;
    uint64_t offset=0;
    char bytes[blocksize];
    ssize_t read=0;
    unsigned int fd=open(path, O_RDONLY);

    logoutput("copy_localfile_remote: path %s fd %i", path, fd);

    while (fd>0 && offset + blocksize < st->st_size) {

	if (get_sftp_interface_info(interface, "status", NULL, &bufferstatus)==4) {
	    unsigned int error=get_uint32(connectionstatus);

	    logoutput_warning("copy_localfile_remote: error %i (%s)", error, strerror(error));
	    if (fd>0) close(fd);
	    return;

	}

	read=pread(fd, bytes, blocksize, offset);

	logoutput_warning("copy_localfile_remote: read %i", read);

	if (read>0) {

	    memset(&sftp_r, 0, sizeof(struct sftp_request_s));

	    sftp_r.id=0;
	    sftp_r.call.writefile.len=lenhandle;
	    sftp_r.call.writefile.handle=(unsigned char *)handle;
	    sftp_r.call.writefile.offset=offset;
	    sftp_r.call.writefile.size=read;
	    sftp_r.call.writefile.bytes=bytes;
	    sftp_r.fuse_request=NULL;

	    logoutput_warning("copy_localfile_remote: offset %lli size %lli", offset, read);

	    if (send_sftp_writefile_ctx(interface->ptr, &sftp_r)>=0) {
		unsigned int error=0;
		void *request=create_sftp_request_ctx(interface->ptr, &sftp_r, &error);

		if (request) {
		    struct timespec timeout;

		    get_sftp_request_timeout(&timeout);
		    error=0;

		    if (wait_sftp_response_ctx(interface, request, &timeout, &error)==1) {

			if (sftp_r.type==SSH_FXP_STATUS) {

			    if (sftp_r.response.status.code==0) {

				logoutput_info("copy_localfile_remote: %s created on server", name);

			    } else {

				logoutput_info("copy_localfile_remote: received status %i", sftp_r.response.status.code);

			    }

			}

		    }

		}

		if (read < blocksize) break;
		offset+=read;

	    }

	}

    }

    memset(&sftp_r, 0, sizeof(struct sftp_request_s));

    sftp_r.id=0;
    sftp_r.call.releasefile.size=lenhandle;
    sftp_r.call.releasefile.handle=(unsigned char *)handle;
    sftp_r.fuse_request=NULL;
    if (fd>0) close(fd);

    if (send_sftp_releasefile_ctx(interface->ptr, &sftp_r)>=0) {
	unsigned int error=0;
	void *request=create_sftp_request_ctx(interface->ptr, &sftp_r, &error);

	if (request) {
	    struct timespec timeout;

	    get_sftp_request_timeout(&timeout);
	    error=0;

	    if (wait_sftp_response_ctx(interface, request, &timeout, &error)==1) {

		if (sftp_r.type==SSH_FXP_STATUS) {

		    if (sftp_r.response.status.code==0) {

			logoutput_info("copy_localfile_remote: %s released on server", name);

		    } else {

			logoutput_info("copy_localfile_remote: received status %i while releasing %s", sftp_r.response.status.code, name);

		    }

		}

	    }

	}

    }

}

static void backup_directory(struct backup_s *backup)
{
}

static int send_create_backup(struct service_context_s *context, struct backup_s *backup)
{
    struct context_interface_s *interface=&context->interface;
    struct sftp_request_s sftp_r;
    int result=-1;

    replace_cntrl_char(backup->path, backup->len, REPLACE_CNTRL_FLAG_TEXT);

    logoutput("send_create_backup: %.*s", backup->len, backup->path);

    memset(&sftp_r, 0, sizeof(struct sftp_request_s));

    sftp_r.id=0;
    sftp_r.call.createbackup.path=(unsigned char *) backup->path;
    sftp_r.call.createbackup.len=backup->len;
    sftp_r.fuse_request=NULL; /* not initiated by fuse/VFS */

    if (send_sftp_createbackup_ctx(interface->ptr, &sftp_r)>=0) {
	unsigned int error=0;
	void *request=create_sftp_request_ctx(interface->ptr, &sftp_r, &error);

	if (request) {
	    struct timespec timeout;

	    get_sftp_request_timeout(&timeout);
	    error=0;

	    if (wait_sftp_response_ctx(interface, request, &timeout, &error)==1) {

		if (sftp_r.type==SSH_FXP_DATA) {

		    if (sftp_r.response.data.size>=9) {

			backup->id=get_uint64(sftp_r.response.data.data);
			if (sftp_r.response.data.data[8] > 0) backup->flags |= BACKUP_FLAG_CREATED;
			if (sftp_r.response.data.size>9) logoutput_warning("send_create_backup: strange reply data response (size=%i)", sftp_r.response.data.size);
			result=0;

		    } else {

			logoutput_warning("send_create_backup: invalid reply data response (size=%i)", sftp_r.response.data.size);

		    }

		    free(sftp_r.response.data.data);
		    sftp_r.response.data.data=NULL;

		} else if (sftp_r.type==SSH_FXP_STATUS) {

		    logoutput("send_create_backup: received status %i while creating %s", sftp_r.response.status.code, backup->path);

		} else {

		    logoutput("send_create_backup: received type %i while creating %s", sftp_r.type, backup->path);

		}

	    }

	}

    }

    return result;

}

static int send_compare_file(struct service_context_s *context, struct backup_s *backup, struct stat *st, char *name)
{
    struct context_interface_s *interface=&context->interface;
    struct sftp_request_s sftp_r;
    struct fuse_sftp_attr_s fuse_attr;
    unsigned int size=get_attr_buffer_size(context->interface.ptr, st, FATTR_SIZE | FATTR_MTIME, &fuse_attr, 1);
    char attrbuffer[size];
    char buffer[8 + 4 + strlen(name) + size];
    unsigned int pos=0;
    unsigned int len=strlen(backup->path) + 2 + strlen(name);
    char path[len];
    int result=-1;

    snprintf(path, len, "%s/%s", backup->path, name);

    logoutput("send_compare_file: file %s", path);

    size=write_attributes_ctx(interface->ptr, attrbuffer, size, &fuse_attr);
    store_uint64(&buffer[pos], backup->id);
    pos+=8;
    store_uint32(&buffer[pos], strlen(name));
    pos+=4;
    memcpy(&buffer[pos], name, strlen(name));
    pos+=strlen(name);
    memcpy(&buffer[pos], attrbuffer, size);
    pos+=size;

    memset(&sftp_r, 0, sizeof(struct sftp_request_s));

    sftp_r.id=0;
    sftp_r.call.comparebackup.data=(unsigned char *) buffer;
    sftp_r.call.comparebackup.len=pos;
    sftp_r.fuse_request=NULL; /* not initiated by fuse/VFS */

    /* compare the local stat with the remote one, only if there is a difference send the file to the remote server to backup (and create a new version) */

    if (send_sftp_comparebackup_ctx(interface->ptr, &sftp_r)==0) {
	unsigned int error=0;
	void *request=create_sftp_request_ctx(interface->ptr, &sftp_r, &error);

	if (request) {
	    struct timespec timeout;

	    get_sftp_request_timeout(&timeout);
	    error=0;

	    if (wait_sftp_response_ctx(interface, request, &timeout, &error)==1) {

		if (sftp_r.type==SSH_FXP_DATA) {
		    unsigned int copyresult=get_uint32((char *)sftp_r.response.data.data);

		    if (copyresult==1 || copyresult==2) {

			/* copy file to server TODO*/

			logoutput("send_compare_file: result %i", copyresult);
			result=0;

		    }

		    free(sftp_r.response.data.data);
		    sftp_r.response.data.data=NULL;

		} else if (sftp_r.type==SSH_FXP_STATUS) {

		    logoutput("send_compare_file: received status %i while creating %s", sftp_r.response.status.code, backup->path);

		} else {

		    logoutput("send_compare_file: received type %i while creating %s", sftp_r.type, backup->path);

		}

	    }

	}

    }

    return result;

}

static unsigned int dummy_hashfunction(void *data)
{
    return 0;
}

static void process_backups(void *ptr)
{
    struct service_context_s *context=(struct service_context_s *) ptr;
    struct context_interface_s *interface=&context->interface;
    uid_t uid=context->workspace->user->uid;
    struct passwd *pw=getpwuid(uid);
    unsigned int len=strlen(pw->pw_dir) + 64;
    char path[len];
    struct timespec timeout;
    unsigned int error=0;
    struct backup_s *backup=NULL;
    unsigned int hashvalue=0;
    char connectionstatus[4];
    void *index=NULL;
    struct common_buffer_s bufferstatus;
    struct simple_hash_s new_backups;
    struct list_header_s nb_list_header=INIT_LIST_HEADER;
    struct list_element_s *list=NULL;

    memset(&new_backups, 0, sizeof(struct simple_hash_s));
    init_simple_locking(&new_backups.locking);
    new_backups.len=1;
    new_backups.hash=&nb_list_header;
    new_backups.hashfunction=dummy_hashfunction;

    bufferstatus.ptr=connectionstatus;
    bufferstatus.size=4;
    bufferstatus.len=bufferstatus.size;
    bufferstatus.pos=bufferstatus.ptr;

    /* look in $HOME/.config/backup */

    logoutput("process_backups");

    open_mimedb();

    /* wait for context/interface/connection is complete/online and up */

    timeout.tv_sec=5;
    timeout.tv_nsec=0;

    if (wait_sftp_service_complete_ctx(interface, &timeout, &error)==0) {

	logoutput("process_backups: sftp service not completed, error %i:%s", error, strerror(error));
	goto out;

    }

    if (snprintf(path, len, "%s/.config/backup", pw->pw_dir)>0) {

	FILE *fp=fopen(path, "r");

	if (fp) {
	    char *line=NULL;
	    size_t size=0;

	    logoutput("process_backups: found file %s", path);

	    while (getline(&line, &size, fp)!=-1) {

		logoutput("process_backups: found %s", line);
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

			value++;
			backup=create_backup(0, value);

			if (backup==NULL) {

			    logoutput("process_backups: error creating backup");
			    free(line);
			    fclose(fp);
			    goto out;

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

				if (add_backupmime(backup, name)) {

				    logoutput("process_backups: added mime %s", name);
				    backup->flags |= BACKUP_FLAG_MIMETYPES;

				}

				name=sep+1;
				goto searchmime;

			    }

			    if (backup->flags & BACKUP_FLAG_MIMETYPES) {

				add_data_to_hash(&new_backups, backup);

			    } else {

				free(backup);

			    }

			    backup=NULL;

			}

		    }

		} else {

		    logoutput("process_backups: found line %s", line);

		}

	    }

	    fclose(fp);

	    if (backup) {

		if ((backup->flags & BACKUP_FLAG_MIMETYPES)==0) free(backup);
		backup=NULL;

	    }

	}

    }

    /* walk every backup, get the rules per backup, and compare every entry in backup which is of the mimetype */


    backup=(struct backup_s *) get_next_hashed_value(&new_backups, &index, 0);
    if (backup) {

	index=NULL;
	remove_data_from_hash(&new_backups, (void *) backup);

    }

    while (backup) {

	if (get_sftp_interface_info(interface, "status", NULL, &bufferstatus)==4) {
	    unsigned int error=get_uint32(connectionstatus);

	    logoutput("process_backups: error %i (%s)", error, strerror(error));
	    goto out;

	}

	logoutput("process_backups: get_next_backup %.*s", backup->len, backup->path);

	if (send_create_backup(context, backup)==0) {
	    DIR *dp=NULL;
	    struct dirent *de=NULL;
	    struct stat st;
	    char buffer[256];
	    unsigned int len=0;
	    struct list_element_s *list=NULL;
	    struct backupmime_s *mime=NULL;

	    logoutput("process_backups: found id %lli (path=%.*s)", backup->id, backup->len, backup->path);

	    add_backup_backuphash(backup);
	    backup->flags|=BACKUP_FLAG_HASHED;

	    dp=opendir(backup->path);
	    if (dp==NULL) goto out;
	    de=readdir(dp);

	    while (de) {

		if (strcmp(de->d_name, ".")==0 || strcmp(de->d_name, ".")==0) goto nextfile;

		/* get the mimetype of file */

		memset(buffer, '\0', 256);
		len=get_mimetype_common(backup->path, de->d_name, buffer, 256);
		if (de->d_type != DT_REG || len==0) goto nextfile;

		/* check the mimetype is one of the mimetypes to backup */

		logoutput("process_backups: test file %s/%s (mime=%s len=%i)", backup->path, de->d_name, buffer, len);

		list=get_list_head(&backup->mime, 0);

		while (list) {

		    mime=(struct backupmime_s *) (((char *) list) - offsetof(struct backupmime_s, list));
		    if (mime->len==len && strncmp(mime->name, buffer, len)==0) break;
		    list=get_next_element(list);
		    mime=NULL;

		}

		if (mime && get_stat(backup->path, de->d_name, &st)==0) {

		    if (send_compare_file(context, backup, &st, de->d_name)==0) copy_localfile_remote(interface, backup, de->d_name, &st);


		}

		nextfile:
		de=readdir(dp);

	    }

	    closedir(dp);

	}

	nextbackup:

	backup=(struct backup_s *) get_next_hashed_value(&new_backups, &index, 0);
	if (backup) {

	    index=NULL;
	    remove_data_from_hash(&new_backups, (void *) backup);

	}

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
