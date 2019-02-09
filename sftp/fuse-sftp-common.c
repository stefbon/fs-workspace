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

#include "logging.h"
#include "main.h"
#include "pathinfo.h"
#include "utils.h"

#include "fuse-fs.h"

#include "workspace-interface.h"
#include "workspaces.h"
#include "workspace-context.h"

#include "fuse-fs-common.h"

#include "sftp-common-protocol.h"
#include "fuse-sftp-common.h"
#include "sftp-attr-common.h"

extern void correct_time_s2c_ctx(void *ptr, struct timespec *time);
extern void correct_time_c2s_ctx(void *ptr, struct timespec *time);
extern unsigned char get_sftp_features(void *ptr);

typedef void (* copy_attr_cb)(void *ptr, struct stat *st, struct fuse_sftp_attr_s *fuse_attr);

static void copy_attr_size(void *ptr, struct stat *st, struct fuse_sftp_attr_s *fuse_attr)
{
    st->st_size=fuse_attr->size;
}

static void copy_attr_mode(void *ptr, struct stat *st, struct fuse_sftp_attr_s *fuse_attr)
{
    mode_t mode_keep=(st->st_mode & S_IFMT);
    mode_t perm_keep=st->st_mode - mode_keep;
    st->st_mode=perm_keep | fuse_attr->type;
}

static void copy_attr_permissions(void *ptr, struct stat *st, struct fuse_sftp_attr_s *fuse_attr)
{
    unsigned int keep=st->st_mode;

    if (fuse_attr->valid[FUSE_SFTP_INDEX_TYPE]==1) {

	st->st_mode=fuse_attr->permissions | fuse_attr->type;

    } else {
	mode_t mode_keep=(st->st_mode & S_IFMT);

	st->st_mode=fuse_attr->permissions | mode_keep;

    }

    logoutput("copy_attr_permissions: pre %i post %i", keep, st->st_mode);

}

static void copy_attr_uid(void *ptr, struct stat *st, struct fuse_sftp_attr_s *fuse_attr)
{
    st->st_uid=fuse_attr->user.uid;
}

static void copy_attr_gid(void *ptr, struct stat *st, struct fuse_sftp_attr_s *fuse_attr)
{
    st->st_gid=fuse_attr->group.gid;
}

static void copy_attr_atim(void *ptr, struct stat *st, struct fuse_sftp_attr_s *fuse_attr)
{
    st->st_atim.tv_sec=fuse_attr->atime;
    st->st_atim.tv_nsec=fuse_attr->atime_n;
    correct_time_s2c_ctx(ptr, &st->st_atim);
}

static void copy_attr_mtim(void *ptr, struct stat *st, struct fuse_sftp_attr_s *fuse_attr)
{
    st->st_mtim.tv_sec=fuse_attr->mtime;
    st->st_mtim.tv_nsec=fuse_attr->mtime_n;
    correct_time_s2c_ctx(ptr, &st->st_mtim);
}

static void copy_attr_ctim(void *ptr, struct stat *st, struct fuse_sftp_attr_s *fuse_attr)
{
    st->st_ctim.tv_sec=fuse_attr->ctime;
    st->st_ctim.tv_nsec=fuse_attr->ctime_n;
    correct_time_s2c_ctx(ptr, &st->st_ctim);
}

static void copy_attr_nothing(void *ptr, struct stat *st, struct fuse_sftp_attr_s *fuse_attr)
{
}

static copy_attr_cb copy_attr_acb[][2] = {
	{copy_attr_nothing, copy_attr_size},
	{copy_attr_nothing, copy_attr_uid},
	{copy_attr_nothing, copy_attr_gid},
	{copy_attr_mode, copy_attr_permissions},
	{copy_attr_nothing, copy_attr_atim},
	{copy_attr_nothing, copy_attr_mtim},
	{copy_attr_nothing, copy_attr_ctim}};

/*
    fill the inode values (size,mode,uid,gid,c/m/atime) with the attributes from sftp
    this is not straightforward since it's possible that the server did not provide all values
    param:
    - ptr				pointer to sftp context
    - inode				inode to fill
    - fuse_sftp_attr_s			values received from server
*/

void fill_inode_attr_sftp(void *ptr, struct stat *st, struct fuse_sftp_attr_s *fuse_attr)
{

    /* size */

    (* copy_attr_acb[0][fuse_attr->valid[FUSE_SFTP_INDEX_SIZE]])(ptr, st, fuse_attr);

    /* owner */

    (* copy_attr_acb[1][fuse_attr->valid[FUSE_SFTP_INDEX_USER]])(ptr, st, fuse_attr);

    /* group */

    (* copy_attr_acb[2][fuse_attr->valid[FUSE_SFTP_INDEX_GROUP]])(ptr, st, fuse_attr);

    /* permissions */

    (* copy_attr_acb[3][fuse_attr->valid[FUSE_SFTP_INDEX_PERMISSIONS]])(ptr, st, fuse_attr);

    /* atime */

    (* copy_attr_acb[4][fuse_attr->valid[FUSE_SFTP_INDEX_ATIME]])(ptr, st, fuse_attr);

    /* mtime */

    (* copy_attr_acb[5][fuse_attr->valid[FUSE_SFTP_INDEX_MTIME]])(ptr, st, fuse_attr);

    /* ctime */

    (* copy_attr_acb[6][fuse_attr->valid[FUSE_SFTP_INDEX_CTIME]])(ptr, st, fuse_attr);

}

/*
    translate the attributes to set from fuse to a buffer sftp understands

    FUSE (20161123) :

    FATTR_MODE
    FATTR_UID
    FATTR_GID
    FATTR_SIZE
    FATTR_ATIME
    FATTR_MTIME
    FATTR_FH
    FATTR_ATIME_NOW
    FATTR_MTIME_NOW
    FATTR_LOCKOWNER
    FATTR_CTIME

    to

    SFTP:

    - size
    - owner
    - group
    - permissions
    - access time
    - modify time
    - change time

    (there are more attributes in sftp, but those are not relevant)

    TODO:
    find out about lock owner

*/

unsigned int get_attr_buffer_size(void *ptr, struct stat *st, unsigned int fuse_set, struct fuse_sftp_attr_s *fuse_attr, unsigned char raw)
{
    unsigned int fuse_supported=get_sftp_features(ptr);
    unsigned int set=0;

    memset(fuse_attr, 0, sizeof(struct fuse_sftp_attr_s));

    if (raw==0) {

	set=fuse_set & fuse_supported;

    } else {

	set=fuse_set;

    }

    if (set & FATTR_SIZE) {

	logoutput("get_attr_buffer_size: set size: %lu", st->st_size);

	fuse_attr->valid[FUSE_SFTP_INDEX_SIZE]=1;
	fuse_attr->asked |= FUSE_SFTP_ATTR_SIZE;
	fuse_attr->size=st->st_size;

    }

    if (set & FATTR_UID) {

	logoutput("get_attr_buffer_size: set owner: %i", (unsigned int) st->st_uid);

	fuse_attr->valid[FUSE_SFTP_INDEX_USER]=1;
	fuse_attr->asked |= FUSE_SFTP_ATTR_USER;
	fuse_attr->user.uid=st->st_uid;

    }

    if (set & FATTR_GID) {

	logoutput("get_attr_buffer_size: set group: %i", (unsigned int) st->st_gid);

	fuse_attr->valid[FUSE_SFTP_INDEX_GROUP]=1;
	fuse_attr->asked |= FUSE_SFTP_ATTR_GROUP;
	fuse_attr->group.gid=st->st_gid;

    }

    if (set & FATTR_MODE) {

	fuse_attr->valid[FUSE_SFTP_INDEX_PERMISSIONS]=1;
	fuse_attr->asked |= FUSE_SFTP_ATTR_PERMISSIONS;
	fuse_attr->permissions=(st->st_mode & (S_IRWXU | S_IRWXG | S_IRWXO));

	logoutput("get_attr_buffer_size: set permissions: %i", (unsigned int) fuse_attr->permissions);

    }

    if (set & FATTR_ATIME) {
	struct timespec time;

	logoutput("get_attr_buffer_size: set atime");

	fuse_attr->valid[FUSE_SFTP_INDEX_ATIME]=1;
	if (set & FATTR_ATIME_NOW) get_current_time(&st->st_atim);

	time.tv_sec=st->st_atim.tv_sec;
	time.tv_nsec=st->st_atim.tv_nsec;

	correct_time_c2s_ctx(ptr, &time);

	fuse_attr->atime=time.tv_sec;
	fuse_attr->atime_n=time.tv_nsec;
	fuse_attr->asked |= FUSE_SFTP_ATTR_ATIME;

    }

    if (set & FATTR_MTIME) {
	struct timespec time;

	logoutput("get_attr_buffer_size: set mtime");

	fuse_attr->valid[FUSE_SFTP_INDEX_MTIME]=1;
	if (set & FATTR_MTIME_NOW) get_current_time(&st->st_mtim);

	time.tv_sec=st->st_mtim.tv_sec;
	time.tv_nsec=st->st_mtim.tv_nsec;

	correct_time_c2s_ctx(ptr, &time);

	fuse_attr->mtime=time.tv_sec;
	fuse_attr->mtime_n=time.tv_nsec;
	fuse_attr->asked |= FUSE_SFTP_ATTR_MTIME;

    }

    if (set & FATTR_CTIME) {
	struct timespec time;

	logoutput("get_attr_buffer_size: set ctime");

	fuse_attr->valid[FUSE_SFTP_INDEX_CTIME]=1;

	time.tv_sec=st->st_ctim.tv_sec;
	time.tv_nsec=st->st_ctim.tv_nsec;

	correct_time_c2s_ctx(ptr, &time);

	fuse_attr->ctime=time.tv_sec;
	fuse_attr->ctime_n=time.tv_nsec;
	fuse_attr->asked |= FUSE_SFTP_ATTR_CTIME;

    }

    if (set & FATTR_ATIME) {
	struct timespec time;

	logoutput("get_attr_buffer_size: set atime");

	fuse_attr->valid[FUSE_SFTP_INDEX_ATIME]=1;

	time.tv_sec=st->st_atim.tv_sec;
	time.tv_nsec=st->st_atim.tv_nsec;

	correct_time_c2s_ctx(ptr, &time);

	fuse_attr->atime=time.tv_sec;
	fuse_attr->atime_n=time.tv_nsec;
	fuse_attr->asked |= FUSE_SFTP_ATTR_ATIME;

    }

    fuse_attr->type=(st->st_mode & S_IFMT);

    /* call the write_attributes with NULL buffer: get the required length */

    return write_attributes_ctx(ptr, NULL, 0, fuse_attr);

}

void init_sftp_request(struct sftp_request_s *r)
{
    memset(r, 0, sizeof(struct sftp_request_s));
}
