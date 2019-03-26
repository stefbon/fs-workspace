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
#include "utils.h"
#include "fuse-dentry.h"

#include "workspace-interface.h"
#include "ssh-common.h"
#include "ssh-channel.h"
#include "ssh-utils.h"
#include "ssh-hostinfo.h"

#include "common-protocol.h"
#include "common.h"
#include "attr-common.h"
#include "protocol-v05.h"

static unsigned int type_mapping[10]={0, S_IFREG, S_IFDIR, S_IFLNK, 0, 0, S_IFSOCK, S_IFCHR, S_IFBLK, S_IFIFO};
static unsigned int type_reverse[13]={SSH_FILEXFER_TYPE_UNKNOWN, SSH_FILEXFER_TYPE_FIFO, SSH_FILEXFER_TYPE_CHAR_DEVICE, SSH_FILEXFER_TYPE_UNKNOWN, SSH_FILEXFER_TYPE_DIRECTORY, SSH_FILEXFER_TYPE_UNKNOWN, SSH_FILEXFER_TYPE_BLOCK_DEVICE, SSH_FILEXFER_TYPE_UNKNOWN, SSH_FILEXFER_TYPE_REGULAR, SSH_FILEXFER_TYPE_UNKNOWN, SSH_FILEXFER_TYPE_SYMLINK, SSH_FILEXFER_TYPE_UNKNOWN, SSH_FILEXFER_TYPE_SOCKET};

struct sftp_string_s {
    char				*name;
    unsigned int			len;
};

struct sftp_acl_s {
    uint32_t				flags;
    uint32_t				count;
};

struct sftp_attr_s {
    uint32_t				valid;
    unsigned char			type;
    uint64_t				size;
    struct sftp_string_s		owner;
    struct sftp_string_s		group;
    uint32_t				permissions;
    int64_t				accesstime;
    uint64_t				accesstime_n;
    int64_t				createtime;
    uint64_t				createtime_n;
    int64_t				modifytime;
    uint64_t				modifytime_n;
    struct sftp_string_s		acl;
    uint32_t				bits;
    uint32_t				extended_count;
    char				*extensions;
};

typedef unsigned int (* read_attr_cb)(struct sftp_subsystem_s *sftp, char *buffer, unsigned int size, struct sftp_attr_s *attr, struct fuse_sftp_attr_s *fuse_attr);

static unsigned int read_attr_zero(struct sftp_subsystem_s *sftp, char *buffer, unsigned int size, struct sftp_attr_s *attr, struct fuse_sftp_attr_s *fuse_attr)
{
    /* does nothing*/
    return 0;
}

static unsigned int read_attr_size(struct sftp_subsystem_s *sftp, char *buffer, unsigned int size, struct sftp_attr_s *attr, struct fuse_sftp_attr_s *fuse_attr)
{

    attr->size=get_uint32(buffer);
    fuse_attr->size=attr->size;
    fuse_attr->valid[FUSE_SFTP_INDEX_SIZE]=1;
    fuse_attr->received|=FUSE_SFTP_ATTR_SIZE;

    return 8; /* 64 bits takes 8 bytes */
}

static unsigned int read_attr_ownergroup(struct sftp_subsystem_s *sftp, char *buffer, unsigned int size, struct sftp_attr_s *attr, struct fuse_sftp_attr_s *fuse_attr)
{
    struct sftp_usermapping_s *usermapping=&sftp->usermapping;
    char *pos=buffer;

    attr->owner.len=get_uint32(pos);
    pos+=4;

    if (attr->owner.len>0) {
	struct sftp_user_s user;

	attr->owner.name=pos;
	pos+=attr->owner.len;

	user.remote.name.ptr=attr->owner.name;
	user.remote.name.len=attr->owner.len;

	(* usermapping->get_local_uid)(sftp, &user);

	fuse_attr->user.uid=user.local_uid;

	fuse_attr->valid[FUSE_SFTP_INDEX_USER]=1;
	fuse_attr->received|=FUSE_SFTP_ATTR_USER;

    }

    attr->group.len=get_uint32(pos);
    pos+=4;

    if (attr->group.len>0) {
	struct sftp_group_s group;

	attr->group.name=pos;
	pos+=attr->group.len;

	group.remote.name.ptr=attr->group.name;
	group.remote.name.len=attr->group.len;

	(* usermapping->get_local_gid)(sftp, &group);

	fuse_attr->group.gid=group.local_gid;

	fuse_attr->valid[FUSE_SFTP_INDEX_GROUP]=1;
	fuse_attr->received|=FUSE_SFTP_ATTR_GROUP;

    }

    return 8 + attr->owner.len + attr->group.len;
}

static unsigned int read_attr_permissions(struct sftp_subsystem_s *sftp, char *buffer, unsigned int size, struct sftp_attr_s *attr, struct fuse_sftp_attr_s *fuse_attr)
{
    attr->permissions=get_uint32(buffer);
    fuse_attr->permissions=(S_IRWXU | S_IRWXG | S_IRWXO) & attr->permissions; /* sftp uses the same permission bits as Linux */
    fuse_attr->valid[FUSE_SFTP_INDEX_PERMISSIONS]=1;
    fuse_attr->received|=FUSE_SFTP_ATTR_PERMISSIONS;
    return 4;
}

static unsigned int read_attr_accesstime(struct sftp_subsystem_s *sftp, char *buffer, unsigned int size, struct sftp_attr_s *attr, struct fuse_sftp_attr_s *fuse_attr)
{
    attr->accesstime=get_uint64(buffer);
    fuse_attr->atime=attr->accesstime;
    fuse_attr->valid[FUSE_SFTP_INDEX_ATIME]=1;
    fuse_attr->received|=FUSE_SFTP_ATTR_ATIME;
    return 8;
}

static unsigned int read_attr_accesstime_n(struct sftp_subsystem_s *sftp, char *buffer, unsigned int size, struct sftp_attr_s *attr, struct fuse_sftp_attr_s *fuse_attr)
{
    attr->accesstime_n=get_uint32(buffer);
    fuse_attr->atime_n=attr->accesstime_n;
    return 4;
}

static unsigned int read_attr_createtime(struct sftp_subsystem_s *sftp, char *buffer, unsigned int size, struct sftp_attr_s *attr, struct fuse_sftp_attr_s *fuse_attr)
{

    attr->createtime=get_uint64(buffer);
    return 8;
}

static unsigned int read_attr_createtime_n(struct sftp_subsystem_s *sftp, char *buffer, unsigned int size, struct sftp_attr_s *attr, struct fuse_sftp_attr_s *fuse_attr)
{
    attr->createtime_n=get_uint32(buffer);
    return 4;
}

static unsigned int read_attr_modifytime(struct sftp_subsystem_s *sftp, char *buffer, unsigned int size, struct sftp_attr_s *attr, struct fuse_sftp_attr_s *fuse_attr)
{
    attr->modifytime=get_uint64(buffer);
    fuse_attr->mtime=attr->modifytime;
    fuse_attr->valid[FUSE_SFTP_INDEX_MTIME]=1;
    fuse_attr->received|=FUSE_SFTP_ATTR_MTIME;
    return 8;
}

static unsigned int read_attr_modifytime_n(struct sftp_subsystem_s *sftp, char *buffer, unsigned int size, struct sftp_attr_s *attr, struct fuse_sftp_attr_s *fuse_attr)
{
    attr->modifytime_n=get_uint32(buffer);
    fuse_attr->mtime_n=attr->modifytime_n;
    return 4;
}

static unsigned int read_attr_acl(struct sftp_subsystem_s *sftp, char *buffer, unsigned int size, struct sftp_attr_s *attr, struct fuse_sftp_attr_s *fuse_attr)
{
    char *pos=buffer;

    /*
	acl's have the form:
	- uint32			acl-flags
	- uint32			ace-count
	- ACE				ace[ace-count]

	one ace looks like:
	- uint32			ace-type (like ALLOW, DENY, AUDIT and ALARM)
	- uint32			ace-flag
	- uint32			ace-mask (what)
	- string			who
    */

    unsigned int acl_flags=0;
    unsigned int ace_count=0;

    unsigned int ace_type=0;
    unsigned int ace_flag=0;
    unsigned int ace_mask=0;
    unsigned int len=0;

    acl_flags=get_uint32(pos);
    pos+=4;

    ace_count=get_uint32(pos);
    pos+=4;

    for (unsigned int i=0; i<ace_count; i++) {

	ace_type=get_uint32(pos);
	pos+=4;

	ace_flag=get_uint32(pos);
	pos+=4;

	ace_mask=get_uint32(pos);
	pos+=4;

	len=get_uint32(pos);
	pos+=4;

	/* do nothing now ... */

	pos+=len;

    }

    return (unsigned int)(pos - buffer);

}

static unsigned int read_attr_bits(struct sftp_subsystem_s *sftp, char *buffer, unsigned int size, struct sftp_attr_s *attr, struct fuse_sftp_attr_s *fuse_attr)
{
    attr->bits=get_uint32(buffer);
    return 4;
}

static unsigned int read_attr_extensions(struct sftp_subsystem_s *sftp, char *buffer, unsigned int size, struct sftp_attr_s *attr, struct fuse_sftp_attr_s *fuse_attr)
{
    /* what to do here ? */
    return 0;
}

static read_attr_cb read_attr_acb[][2] = {
	{read_attr_zero, read_attr_size},
	{read_attr_zero, read_attr_ownergroup},
	{read_attr_zero, read_attr_permissions},
	{read_attr_zero, read_attr_accesstime},
	{read_attr_zero, read_attr_accesstime_n},
	{read_attr_zero, read_attr_createtime},
	{read_attr_zero, read_attr_createtime_n},
	{read_attr_zero, read_attr_modifytime},
	{read_attr_zero, read_attr_modifytime_n},
	{read_attr_zero, read_attr_acl},
	{read_attr_zero, read_attr_bits},
	{read_attr_zero, read_attr_extensions}};

static unsigned int read_sftp_attributes(struct sftp_subsystem_s *sftp, unsigned int valid, char *buffer, unsigned int size, struct sftp_attr_s *sftp_attr, struct fuse_sftp_attr_s *fuse_attr)
{
    unsigned char vb[12];
    char *pos=buffer;
    unsigned char type=0;

    vb[0]=(valid & SSH_FILEXFER_ATTR_SIZE) >> SSH_FILEXFER_INDEX_SIZE;
    vb[1]=(valid & SSH_FILEXFER_ATTR_OWNERGROUP) >> SSH_FILEXFER_INDEX_OWNERGROUP;
    vb[2]=(valid & SSH_FILEXFER_ATTR_PERMISSIONS) >> SSH_FILEXFER_INDEX_PERMISSIONS;
    vb[3]=(valid & SSH_FILEXFER_ATTR_ACCESSTIME) >> SSH_FILEXFER_INDEX_ACCESSTIME;

    vb[5]=(valid & SSH_FILEXFER_ATTR_CREATETIME) >> SSH_FILEXFER_INDEX_CREATETIME;

    vb[7]=(valid & SSH_FILEXFER_ATTR_MODIFYTIME) >> SSH_FILEXFER_INDEX_MODIFYTIME;

    vb[8]=(valid & SSH_FILEXFER_ATTR_SUBSECOND_TIMES) >> SSH_FILEXFER_INDEX_SUBSECOND_TIMES;
    vb[9]=(valid & SSH_FILEXFER_ATTR_ACL) >> SSH_FILEXFER_INDEX_ACL;
    vb[10]=(valid & SSH_FILEXFER_ATTR_BITS) >> SSH_FILEXFER_INDEX_BITS;
    vb[11]=(valid & SSH_FILEXFER_ATTR_EXTENDED) >> SSH_FILEXFER_INDEX_EXTENDED;

    /* read nseconds only if time and subseconds_times bits both are set */

    vb[4]=vb[3] & vb[8];
    vb[6]=vb[5] & vb[8];
    vb[8]=vb[7] & vb[8];

    /*
	read type (always present)
	- byte			type
    */

    type=(unsigned char) *pos;

    if (type<10) {

	fuse_attr->type=type_mapping[type];

    } else {

	fuse_attr->type=0;

    }

    pos++;
    fuse_attr->valid[FUSE_SFTP_INDEX_TYPE]=1;
    fuse_attr->received|=FUSE_SFTP_ATTR_TYPE;

    /*
	size
    */

    pos += (* read_attr_acb[0][vb[0]])(sftp, pos, (unsigned int)(buffer + size - pos + 1), sftp_attr, fuse_attr);

    /*
	owner and group
    */

    pos += (* read_attr_acb[1][vb[1]])(sftp, pos, (unsigned int)(buffer + size - pos + 1), sftp_attr, fuse_attr);

    /*
	permissions
    */

    pos += (* read_attr_acb[2][vb[2]])(sftp, pos, (unsigned int)(buffer + size - pos + 1), sftp_attr, fuse_attr);

    /*
	accesstime
    */

    pos += (* read_attr_acb[3][vb[3]])(sftp, pos, (unsigned int)(buffer + size - pos + 1), sftp_attr, fuse_attr);

    /*
	accesstime_n
    */

    pos += (* read_attr_acb[4][vb[4]])(sftp, pos, (unsigned int)(buffer + size - pos + 1), sftp_attr, fuse_attr);

    /*
	createtime
    */

    pos += (* read_attr_acb[5][vb[5]])(sftp, pos, (unsigned int)(buffer + size - pos + 1), sftp_attr, fuse_attr);

    /*
	createtime_n
    */

    pos += (* read_attr_acb[6][vb[6]])(sftp, pos, (unsigned int)(buffer + size - pos + 1), sftp_attr, fuse_attr);

    /*
	modifytime
    */

    pos += (* read_attr_acb[7][vb[7]])(sftp, pos, (unsigned int)(buffer + size - pos + 1), sftp_attr, fuse_attr);

    /*
	modifytime_n
    */

    pos += (* read_attr_acb[8][vb[8]])(sftp, pos, (unsigned int)(buffer + size - pos + 1), sftp_attr, fuse_attr);

    /*
	acl
    */

    pos += (* read_attr_acb[9][vb[9]])(sftp, pos, (unsigned int)(buffer + size - pos + 1), sftp_attr, fuse_attr);

    /*
	attrib_bits and attrib_bits_valid
    */

    pos += (* read_attr_acb[10][vb[10]])(sftp, pos, (unsigned int)(buffer + size - pos + 1), sftp_attr, fuse_attr);

    /*
	extensions
    */

    pos += (* read_attr_acb[11][vb[11]])(sftp, pos, (unsigned int)(buffer + size - pos + 1), sftp_attr, fuse_attr);

    return (unsigned int) (pos - buffer);

}

static unsigned int read_attributes_v05(struct sftp_subsystem_s *sftp, char *buffer, unsigned int size, struct fuse_sftp_attr_s *fuse_attr)
{
    struct sftp_attr_s sftp_attr;
    char *pos=buffer;
    unsigned int valid=0;

    memset(&sftp_attr, 0, sizeof(struct sftp_attr_s));

    valid=get_uint32(pos);
    pos+=4;

    pos+=read_sftp_attributes(sftp, valid, pos, size-4, &sftp_attr, fuse_attr);

    return (unsigned int) (pos - buffer);

}

typedef unsigned int (* write_attr_cb)(struct sftp_subsystem_s *sftp, char *pos, unsigned int size, struct fuse_sftp_attr_s *fuse_attr, unsigned int *valid);

static unsigned int write_attr_zero(struct sftp_subsystem_s *sftp, char *pos, unsigned int size, struct fuse_sftp_attr_s *fuse_attr, unsigned int *valid)
{
    return 0;
}

static unsigned int write_attr_size(struct sftp_subsystem_s *sftp, char *pos, unsigned int size, struct fuse_sftp_attr_s *fuse_attr, unsigned int *valid)
{
    store_uint64(pos, fuse_attr->size);
    *valid|=SSH_FILEXFER_ATTR_SIZE;
    return 8;
}

static unsigned int write_attr_ownergroup(struct sftp_subsystem_s *sftp, char *buffer, unsigned int size, struct fuse_sftp_attr_s *fuse_attr, unsigned int *valid)
{
    struct sftp_usermapping_s *usermapping=&sftp->usermapping;
    char *pos=buffer;

    if (fuse_attr->valid[FUSE_SFTP_INDEX_USER]==1) {
	struct sftp_user_s user;

	user.remote.name.ptr=pos+4;
	user.local_uid=fuse_attr->user.uid;

	(* usermapping->get_remote_user)(sftp, &user);

	store_uint32(pos, user.remote.name.len);
	pos+=4+user.remote.name.len;

    } else {

	store_uint32(pos, 0);
	pos+=4;

    }

    if (fuse_attr->valid[FUSE_SFTP_INDEX_GROUP]==1) {
	struct sftp_group_s group;

	group.remote.name.ptr=pos+4;
	group.local_gid=fuse_attr->group.gid;

	(* usermapping->get_remote_group)(sftp, &group);

	store_uint32(pos, group.remote.name.len);
	pos+=4+group.remote.name.len;

    } else {

	store_uint32(pos, 0);
	pos+=4;

    }

    *valid|=SSH_FILEXFER_ATTR_OWNERGROUP;

    return (unsigned int) (pos-buffer);

}

static unsigned int write_attr_permissions(struct sftp_subsystem_s *sftp, char *pos, unsigned int size, struct fuse_sftp_attr_s *fuse_attr, unsigned int *valid)
{
    store_uint32(pos, fuse_attr->permissions & ( S_IRWXU | S_IRWXG | S_IRWXO ));
    *valid|=SSH_FILEXFER_ATTR_PERMISSIONS;
    return 4;
}

static unsigned int write_attr_accesstime(struct sftp_subsystem_s *sftp, char *pos, unsigned int size, struct fuse_sftp_attr_s *fuse_attr, unsigned int *valid)
{
    store_uint64(pos, fuse_attr->atime);
    *valid|=SSH_FILEXFER_ATTR_ACCESSTIME;
    store_uint32(pos+8, fuse_attr->atime_n);
    *valid|=SSH_FILEXFER_ATTR_SUBSECOND_TIMES;
    return 12;
}

static unsigned int write_attr_modifytime(struct sftp_subsystem_s *sftp, char *pos, unsigned int size, struct fuse_sftp_attr_s *fuse_attr, unsigned int *valid)
{
    store_uint64(pos, fuse_attr->mtime);
    *valid|=SSH_FILEXFER_ATTR_MODIFYTIME;
    store_uint32(pos+8, fuse_attr->mtime_n);
    *valid|=SSH_FILEXFER_ATTR_SUBSECOND_TIMES;
    return 12;
}

static write_attr_cb write_attr_acb[][2] = {
	{write_attr_zero, write_attr_size},
	{write_attr_zero, write_attr_ownergroup},
	{write_attr_zero, write_attr_permissions},
	{write_attr_zero, write_attr_accesstime},
	{write_attr_zero, write_attr_modifytime}};

static unsigned int write_attributes_v05(struct sftp_subsystem_s *sftp, char *buffer, unsigned int size, struct fuse_sftp_attr_s *fuse_attr)
{

    if (buffer==NULL) {
	unsigned int len=0;

	len = 5; /* valid flag + type byte */
	len += fuse_attr->valid[FUSE_SFTP_INDEX_SIZE] * 8; /* size */

	if (fuse_attr->valid[FUSE_SFTP_INDEX_USER] | fuse_attr->valid[FUSE_SFTP_INDEX_GROUP]) {
	    struct sftp_usermapping_s *usermapping=&sftp->usermapping;

	    len+=8; /* both len fields have to be filled (and may be filled with 0) */
	    if (fuse_attr->valid[FUSE_SFTP_INDEX_USER]) {
		struct sftp_user_s user;

		user.remote.name.ptr=NULL;
		user.remote.name.len=0;
		user.local_uid=fuse_attr->user.uid;

		(* usermapping->get_remote_user)(sftp, &user);

		len+=user.remote.name.len;

	    }

	    if (fuse_attr->valid[FUSE_SFTP_INDEX_GROUP]) {
		struct sftp_group_s group;

		group.remote.name.ptr=NULL;
		group.remote.name.len=0;
		group.local_gid=fuse_attr->group.gid;

		(* usermapping->get_remote_group)(sftp, &group);

		len+=group.remote.name.len;

	    }

	}

	len += fuse_attr->valid[FUSE_SFTP_INDEX_PERMISSIONS] * 4; /* permissions */
	len += fuse_attr->valid[FUSE_SFTP_INDEX_ATIME] * 12; /* access time (8+4)*/
	len += fuse_attr->valid[FUSE_SFTP_INDEX_MTIME] * 12; /* modify time (8+4)*/

	return len;

    } else {
	unsigned int valid=0;
	unsigned int type=IFTODT(fuse_attr->type);
	char *pos=buffer;

	store_uint32(pos, valid); /* correct this later */
	pos+=4;

	if (type > 13) {

	    *pos=(unsigned char) SSH_FILEXFER_TYPE_UNKNOWN;

	} else {

	    *pos=type_reverse[type];

	}

	pos++;

	/* size */

	pos+= (* write_attr_acb[0][fuse_attr->valid[FUSE_SFTP_INDEX_SIZE]]) (sftp, pos, (unsigned int)(buffer + size - pos + 1), fuse_attr, &valid);

	/* owner and/or group */

	pos+= (* write_attr_acb[1][fuse_attr->valid[FUSE_SFTP_INDEX_USER] | fuse_attr->valid[FUSE_SFTP_INDEX_GROUP]]) (sftp, pos, (unsigned int)(buffer + size - pos + 1), fuse_attr, &valid);

	/* permissions */

	pos+= (* write_attr_acb[2][fuse_attr->valid[FUSE_SFTP_INDEX_PERMISSIONS]]) (sftp, pos, (unsigned int)(buffer + size - pos + 1), fuse_attr, &valid);

	/* access time */

	pos+= (* write_attr_acb[3][fuse_attr->valid[FUSE_SFTP_INDEX_ATIME]]) (sftp, pos, (unsigned int)(buffer + size - pos + 1), fuse_attr, &valid);

	/* modify time */

	pos+= (* write_attr_acb[4][fuse_attr->valid[FUSE_SFTP_INDEX_MTIME]]) (sftp, pos, (unsigned int)(buffer + size - pos + 1), fuse_attr, &valid);

	/* valid is set: write it at begin */

	store_uint32(buffer, valid);

	return (unsigned int) (pos - buffer);

    }

    return 0;

}

/*
    read a name and attributes from a name response
    since version 4 a name response looks like:

    uint32				id
    uint32				count
    repeats count times:
	string				filename [UTF-8]
	ATTRS				attr

*/

static void read_name_response_v05(struct sftp_subsystem_s *sftp, struct name_response_s *response, char **name, unsigned int *len)
{
    logoutput_debug("read_name_response_v05: pos %i", (unsigned int)(response->pos - response->buff));
    *len=get_uint32(response->pos);
    response->pos+=4;

    *name=(char *) response->pos; /* name without trailing zero */
    response->pos+=*len;
}

static unsigned int read_attr_response_v05(struct sftp_subsystem_s *sftp, struct name_response_s *response, struct fuse_sftp_attr_s *sftp_attr)
{
    char *keep=response->pos;

    memset(sftp_attr, 0, sizeof(struct fuse_sftp_attr_s));

    logoutput_debug("read_name_response_v05: pos %i", (unsigned int)(response->pos - response->buff));
    response->pos+=read_attributes_v05(sftp, response->pos, (unsigned int) (response->buff + response->size - response->pos), sftp_attr);
    response->count--;

    logoutput_debug("read_attr_response_v05: m %i p %i", sftp_attr->type, sftp_attr->permissions);

    return (unsigned int)(response->pos - keep);
}

static void read_sftp_features_v05(struct sftp_subsystem_s *sftp)
{
    struct sftp_supported_s *supported=&sftp->supported;
    unsigned int attribute_mask=supported->version.v05.attribute_mask;

    if (attribute_mask==0) return;

    supported->fuse_attr_supported=FUSE_SFTP_ATTR_TYPE;
    supported->version.v05.init=1;

    if (attribute_mask & SSH_FILEXFER_ATTR_SIZE) {

	logoutput_debug("read_sftp_features_v05: sftp attr size supported");
	supported->fuse_attr_supported|=FUSE_SFTP_ATTR_SIZE;

    } else {

	logoutput_debug("read_sftp_features_v05: sftp attr size not supported");

    }

    if (attribute_mask & SSH_FILEXFER_ATTR_PERMISSIONS) {

	supported->fuse_attr_supported|=FUSE_SFTP_ATTR_PERMISSIONS;
	logoutput_debug("read_sftp_features_v05: sftp attr permissions supported");

    } else {

	logoutput_debug("read_sftp_features_v05: sftp attr permissions not supported");

    }

    if (attribute_mask & SSH_FILEXFER_ATTR_OWNERGROUP) {

	supported->fuse_attr_supported|=FUSE_SFTP_ATTR_USER | FUSE_SFTP_ATTR_GROUP;
	logoutput_debug("read_sftp_features_v05: sftp attr ownergroup supported");

    } else {

	logoutput_debug("read_sftp_features_v05: sftp attr ownergroup not supported");

    }

    if (attribute_mask & SSH_FILEXFER_ATTR_ACCESSTIME) {

	supported->fuse_attr_supported|=FUSE_SFTP_ATTR_ATIME;
	logoutput_debug("read_sftp_features_v05: sftp attr atime supported");

    } else {

	logoutput_debug("read_sftp_features_v05: sftp attr mtime not supported");

    }

    if (attribute_mask & SSH_FILEXFER_ATTR_MODIFYTIME) {

	supported->fuse_attr_supported|=FUSE_SFTP_ATTR_MTIME;
	logoutput_debug("read_sftp_features_v05: sftp attr mtime supported");

    } else {

	logoutput_debug("read_sftp_features_v05: sftp attr mtime not supported");

    }

}

static unsigned int get_attribute_mask_v05(struct sftp_subsystem_s *sftp)
{
    struct sftp_supported_s *supported=&sftp->supported;
    return (supported->version.v05.attribute_mask);
}

static int get_attribute_info_v05(struct sftp_subsystem_s *sftp, unsigned int valid, const char *what)
{
    if (strcmp(what, "size")==0) return (valid & SSH_FILEXFER_ATTR_SIZE);
    if (strcmp(what, "uid")==0) return -1;
    if (strcmp(what, "gid")==0) return -1;
    if (strcmp(what, "user@")==0) return (valid & SSH_FILEXFER_ATTR_OWNERGROUP);
    if (strcmp(what, "group@")==0) return (valid & SSH_FILEXFER_ATTR_OWNERGROUP);
    if (strcmp(what, "perm")==0) return (valid & SSH_FILEXFER_ATTR_PERMISSIONS);
    if (strcmp(what, "acl")==0) return (valid & SSH_FILEXFER_ATTR_ACL);
    if (strcmp(what, "btime")==0) return (valid & SSH_FILEXFER_ATTR_CREATETIME);
    if (strcmp(what, "atime")==0) return (valid & SSH_FILEXFER_ATTR_ACCESSTIME);
    if (strcmp(what, "ctime")==0) return -1;
    if (strcmp(what, "mtime")==0) return (valid & SSH_FILEXFER_ATTR_MODIFYTIME);
    if (strcmp(what, "subseconds")==0) return (valid & SSH_FILEXFER_ATTR_SUBSECOND_TIMES);
    return -2;
}

static struct sftp_attr_ops_s attr_ops_v05 = {
    .read_attributes			= read_attributes_v05,
    .write_attributes			= write_attributes_v05,
    .read_name_response			= read_name_response_v05,
    .read_attr_response			= read_attr_response_v05,
    .read_sftp_features			= read_sftp_features_v05,
    .get_attribute_mask			= get_attribute_mask_v05,
};

void use_sftp_attr_v05(struct sftp_subsystem_s *sftp_subsystem)
{
    sftp_subsystem->attr_ops=&attr_ops_v05;
}
