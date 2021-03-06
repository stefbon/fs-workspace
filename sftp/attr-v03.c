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

#include "logging.h"
#include "main.h"

#include "utils.h"
#include "fuse-dentry.h"

#include "workspace-interface.h"
#include "ssh-common.h"
#include "ssh-channel.h"
#include "ssh-hostinfo.h"
#include "ssh-utils.h"

#include "common-protocol.h"
#include "common.h"
#include "protocol-v03.h"
#include "attr-common.h"

static unsigned int type_mapping[5]={0, S_IFREG, S_IFDIR, S_IFLNK, 0};

struct sftp_string_s {
    char				*name;
    unsigned int			len;
};

struct sftp_attr_s {
    uint32_t				valid;
    uint64_t				size;
    uint32_t				uid;
    uint32_t				gid;
    struct sftp_string_s		owner;
    struct sftp_string_s		group;
    uint32_t				permissions;
    uint32_t				accesstime;
    uint32_t				modifytime;
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

    attr->size=get_uint64(buffer);
    fuse_attr->size=attr->size;
    fuse_attr->valid[FUSE_SFTP_INDEX_SIZE]=1;
    fuse_attr->received|=FUSE_SFTP_ATTR_SIZE;

    logoutput_debug("read_attr_size: size %i", attr->size);

    return 8; /* 64 bits takes 8 bytes */
}

static unsigned int read_attr_ownergroup(struct sftp_subsystem_s *sftp, char *buffer, unsigned int size, struct sftp_attr_s *attr, struct fuse_sftp_attr_s *fuse_attr)
{
    struct sftp_usermapping_s *usermapping=&sftp->usermapping;
    char *pos=buffer;

    logoutput_debug("read_attr_ownergroup: uid %i gid %i", fuse_attr->user.uid, fuse_attr->group.gid);

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

    logoutput_debug("read_attr_ownergroup: uid %i gid %i", fuse_attr->user.uid, fuse_attr->group.gid);

    return 8 + attr->owner.len + attr->group.len;
}

static unsigned int read_attr_uidgid(struct sftp_subsystem_s *sftp, char *buffer, unsigned int size, struct sftp_attr_s *attr, struct fuse_sftp_attr_s *fuse_attr)
{
    struct sftp_usermapping_s *usermapping=&sftp->usermapping;
    char *pos=buffer;
    struct sftp_user_s user;
    struct sftp_group_s group;

    attr->uid=get_uint32(pos);
    pos+=4;

    user.remote.id=attr->uid;
    (* usermapping->get_local_uid)(sftp, &user);

    fuse_attr->user.uid=user.local_uid;

    fuse_attr->valid[FUSE_SFTP_INDEX_USER]=1;
    fuse_attr->received|=FUSE_SFTP_ATTR_USER;

    attr->gid=get_uint32(pos);
    pos+=4;

    group.remote.id=attr->gid;
    (* usermapping->get_local_gid)(sftp, &group);

    fuse_attr->group.gid=group.local_gid;

    fuse_attr->valid[FUSE_SFTP_INDEX_GROUP]=1;
    fuse_attr->received|=FUSE_SFTP_ATTR_GROUP;

    logoutput_debug("read_attr_uidgid: uid %i gid %i", user.local_uid, group.local_gid);

    return 8;
}

static unsigned int read_attr_permissions(struct sftp_subsystem_s *sftp, char *buffer, unsigned int size, struct sftp_attr_s *attr, struct fuse_sftp_attr_s *fuse_attr)
{
    attr->permissions=get_uint32(buffer);
    fuse_attr->permissions=(S_IRWXU | S_IRWXG | S_IRWXO) & attr->permissions; /* sftp uses the same permission bits as Linux */
    fuse_attr->valid[FUSE_SFTP_INDEX_PERMISSIONS]=1;
    fuse_attr->received|=FUSE_SFTP_ATTR_PERMISSIONS;
    logoutput_debug("read_attr_permissions: fattr %i attr %i", attr->permissions, fuse_attr->permissions);
    return 4;
}

static unsigned int read_attr_acmodtime(struct sftp_subsystem_s *sftp, char *buffer, unsigned int size, struct sftp_attr_s *attr, struct fuse_sftp_attr_s *fuse_attr)
{
    attr->accesstime=get_uint32(buffer);
    fuse_attr->atime=attr->accesstime;
    fuse_attr->valid[FUSE_SFTP_INDEX_ATIME]=1;
    fuse_attr->received|=FUSE_SFTP_ATTR_ATIME;

    attr->modifytime=get_uint32(buffer+4);
    fuse_attr->mtime=attr->modifytime;
    fuse_attr->valid[FUSE_SFTP_INDEX_MTIME]=1;
    fuse_attr->received|=FUSE_SFTP_ATTR_MTIME;

    return 8;
}

static unsigned int read_attr_extensions(struct sftp_subsystem_s *sftp, char *buffer, unsigned int size, struct sftp_attr_s *attr, struct fuse_sftp_attr_s *fuse_attr)
{
    /* what to do here ? */
    return 0;
}

static read_attr_cb read_attr_acb[][2] = {
	{read_attr_zero, read_attr_size},
	{read_attr_zero, read_attr_uidgid},
	{read_attr_zero, read_attr_permissions},
	{read_attr_zero, read_attr_acmodtime},
	{read_attr_zero, read_attr_extensions},
	{read_attr_zero, read_attr_ownergroup}};

static unsigned int read_sftp_attributes(struct sftp_subsystem_s *sftp, unsigned int valid, char *buffer, unsigned int size, struct fuse_sftp_attr_s *fuse_attr)
{
    unsigned char vb[6];
    char *pos=buffer;
    unsigned char type=0;
    struct sftp_attr_s sftp_attr;

    memset(&sftp_attr, 0, sizeof(struct sftp_attr_s));

    vb[0]=(valid & SSH_FILEXFER_ATTR_SIZE) >> SSH_FILEXFER_INDEX_SIZE;
    vb[1]=(valid & SSH_FILEXFER_ATTR_UIDGID) >> SSH_FILEXFER_INDEX_UIDGID;
    vb[2]=(valid & SSH_FILEXFER_ATTR_PERMISSIONS) >> SSH_FILEXFER_INDEX_PERMISSIONS;
    vb[3]=(valid & SSH_FILEXFER_ATTR_ACMODTIME) >> SSH_FILEXFER_INDEX_ACMODTIME;
    vb[4]=(valid & SSH_FILEXFER_ATTR_EXTENDED) >> SSH_FILEXFER_INDEX_EXTENDED;
    vb[5]=(valid & SSH_FILEXFER_ATTR_OWNERGROUP) >> SSH_FILEXFER_INDEX_OWNERGROUP;

    /* type field is not present */

    /* size */

    pos += (* read_attr_acb[0][vb[0]])(sftp, pos, (unsigned int)(buffer + size - pos + 1), &sftp_attr, fuse_attr);

    /* uid and gid */

    pos += (* read_attr_acb[1][vb[1]])(sftp, pos, (unsigned int)(buffer + size - pos + 1), &sftp_attr, fuse_attr);

    /* owner and group */

    pos += (* read_attr_acb[5][vb[5]])(sftp, pos, (unsigned int)(buffer + size - pos + 1), &sftp_attr, fuse_attr);

    /* permissions */

    pos += (* read_attr_acb[2][vb[2]])(sftp, pos, (unsigned int)(buffer + size - pos + 1), &sftp_attr, fuse_attr);

    /* acmodtime */

    pos += (* read_attr_acb[3][vb[3]])(sftp, pos, (unsigned int)(buffer + size - pos + 1), &sftp_attr, fuse_attr);

    /* extensions */

    pos += (* read_attr_acb[4][vb[4]])(sftp, pos, (unsigned int)(buffer + size - pos + 1), &sftp_attr, fuse_attr);

    return (unsigned int) (pos - buffer);

}

static unsigned int read_attributes_v03(struct sftp_subsystem_s *sftp, char *buffer, unsigned int size, struct fuse_sftp_attr_s *fuse_attr)
{
    char *pos=buffer;
    unsigned int valid=0;

    // logoutput_base64encoded("read_attributes_v03", buffer, size);
    logoutput_debug("read_attributes_v03");

    valid=get_uint32(pos);
    pos+=4;

    logoutput_debug("read_attributes_v03: valid %i", valid);

    pos+=read_sftp_attributes(sftp, valid, pos, size-4, fuse_attr);
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

static unsigned int write_attr_uidgid(struct sftp_subsystem_s *sftp, char *buffer, unsigned int size, struct fuse_sftp_attr_s *fuse_attr, unsigned int *valid)
{
    struct sftp_usermapping_s *usermapping=&sftp->usermapping;
    char *pos=buffer;
    struct sftp_user_s user;
    struct sftp_group_s group;

    user.local_uid=fuse_attr->user.uid;

    (* usermapping->get_remote_user)(sftp, &user);

    store_uint32(pos, user.remote.id);
    pos+=4;

    group.local_gid=fuse_attr->group.gid;

    (* usermapping->get_remote_group)(sftp, &group);

    store_uint32(pos, group.remote.id);
    pos+=4;

    *valid|=SSH_FILEXFER_ATTR_UIDGID;

    return (unsigned int) (pos-buffer);

}

static unsigned int write_attr_permissions(struct sftp_subsystem_s *sftp, char *pos, unsigned int size, struct fuse_sftp_attr_s *fuse_attr, unsigned int *valid)
{
    store_uint32(pos, fuse_attr->permissions & ( S_IRWXU | S_IRWXG | S_IRWXO ));
    *valid|=SSH_FILEXFER_ATTR_PERMISSIONS;
    return 4;
}

static unsigned int write_attr_acmodtime(struct sftp_subsystem_s *sftp, char *pos, unsigned int size, struct fuse_sftp_attr_s *fuse_attr, unsigned int *valid)
{
    store_uint32(pos, fuse_attr->atime);
    store_uint32(pos+4, fuse_attr->mtime);
    *valid|=SSH_FILEXFER_ATTR_ACMODTIME;
    return 8;
}

static write_attr_cb write_attr_acb[][2] = {
	{write_attr_zero, write_attr_size},
	{write_attr_zero, write_attr_uidgid},
	{write_attr_zero, write_attr_permissions},
	{write_attr_zero, write_attr_acmodtime}};

static unsigned int write_attributes_v03(struct sftp_subsystem_s *sftp, char *buffer, unsigned int size, struct fuse_sftp_attr_s *fuse_attr)
{

    if (buffer==NULL) {
	unsigned int len=0;

	len = 4; /* valid flag */
	len += fuse_attr->valid[FUSE_SFTP_INDEX_SIZE] * 8; /* size */
	if (fuse_attr->valid[FUSE_SFTP_INDEX_USER] | fuse_attr->valid[FUSE_SFTP_INDEX_GROUP]) len+=8;
	len += fuse_attr->valid[FUSE_SFTP_INDEX_PERMISSIONS] * 4; /* permissions */
	if (fuse_attr->valid[FUSE_SFTP_INDEX_ATIME] | fuse_attr->valid[FUSE_SFTP_INDEX_MTIME]) len+=8;

	return len;

    } else {
	unsigned int valid=0;
	char *pos=buffer;

	store_uint32(pos, valid); /* correct this later */
	pos+=4;

	/* size */

	pos+= (* write_attr_acb[0][fuse_attr->valid[FUSE_SFTP_INDEX_SIZE]]) (sftp, pos, (unsigned int)(buffer + size - pos + 1), fuse_attr, &valid);

	/* owner and/or group */

	pos+= (* write_attr_acb[1][fuse_attr->valid[FUSE_SFTP_INDEX_USER] | fuse_attr->valid[FUSE_SFTP_INDEX_GROUP]]) (sftp, pos, (unsigned int)(buffer + size - pos + 1), fuse_attr, &valid);

	/* permissions */

	pos+= (* write_attr_acb[2][fuse_attr->valid[FUSE_SFTP_INDEX_PERMISSIONS]]) (sftp, pos, (unsigned int)(buffer + size - pos + 1), fuse_attr, &valid);

	/* acmod time */

	pos+= (* write_attr_acb[3][fuse_attr->valid[FUSE_SFTP_INDEX_ATIME] | fuse_attr->valid[FUSE_SFTP_INDEX_MTIME]]) (sftp, pos, (unsigned int)(buffer + size - pos + 1), fuse_attr, &valid);

	/* valid is set: write it at begin */

	store_uint32(buffer, valid);

	return (unsigned int) (pos - buffer);

    }

    return 0;

}

/*
    read a name and attributes from a name response
    for version 4 a name response looks like:

    uint32				id
    uint32				count
    repeats count times:
	string				filename
	string				longname
	ATTRS				attr


    longname is output of ls -l command like:

    -rwxr-xr-x   1 mjos     staff      348911 Mar 25 14:29 t-filexfer
    1234567890 123 12345678 12345678 12345678 123456789012
    01234567890123456789012345678901234567890123456789012345
    0         1         2         3         4         5

    example:

    -rw-------    1 sbon     sbon         1799 Nov 26 15:22 .bash_history


*/

static unsigned int read_name_response_v03(struct sftp_subsystem_s *sftp, char *buffer, unsigned int size, char **name, unsigned int *len)
{

    logoutput_debug("read_name_response_v03: size %i", size);

    *len=get_uint32(buffer);
    *name=&buffer[4]; /* name without trailing zero */

    return (*len + 4);

}

static unsigned int read_attr_response_v03(struct sftp_subsystem_s *sftp, char *buffer, unsigned int size, struct fuse_sftp_attr_s *fuse_attr)
{
    struct sftp_string_s longname;
    unsigned int valid=0;
    unsigned char correction=0;
    unsigned int pos=0;

    logoutput_debug("read_attr_response_v03: size %i", size);

    /* longname */

    longname.len=get_uint32(&buffer[pos]);
    pos+=4;
    longname.name=&buffer[pos];
    pos+=longname.len;

    logoutput_debug("read_attr_response_v03: longname %.*s (length %i)", longname.len, longname.name, longname.len);

    /* valid attributes */

    valid=get_uint32(&buffer[pos]);
    pos+=4;

    logoutput_debug("read_attr_response_v03: valid %i", valid);

    /* attr */

    pos+=read_sftp_attributes(sftp, valid, &buffer[pos], size - pos, fuse_attr);

    /* get type from longname: parse the string which is output of ls -al %filename% */

    switch (longname.name[0]) {

	case '-':

	    fuse_attr->type |= S_IFREG;
	    break;

	case 'd':

	    fuse_attr->type |= S_IFDIR;
	    break;

	case 'l':

	    fuse_attr->type |= S_IFLNK;
	    break;

	case 'c':

	    fuse_attr->type |= S_IFCHR;
	    break;

	case 'b':

	    fuse_attr->type |= S_IFBLK;
	    break;

	case 's':

	    fuse_attr->type |= S_IFSOCK;
	    break;

	default:

	    fuse_attr->type |= S_IFREG;

    }

    logoutput_debug("read_attr_response_v03: type %i", fuse_attr->type);
    fuse_attr->valid[FUSE_SFTP_INDEX_TYPE]=1;
    fuse_attr->received|=FUSE_SFTP_ATTR_TYPE;

    if (longname.len>10) {
	char modestr[11];
	memcpy(modestr, &longname.name[0], 10);
	modestr[10]='\0';
	logoutput_debug("read_attr_response_v03: modestr %s", modestr);

    }

    if (fuse_attr->valid[FUSE_SFTP_INDEX_PERMISSIONS]==0) {

	/* only get permissions from longname if not already from attr */

	fuse_attr->permissions|=(longname.name[1]=='r') ? S_IRUSR : 0;
	fuse_attr->permissions|=(longname.name[2]=='w') ? S_IWUSR : 0;
	fuse_attr->permissions|=(longname.name[3]=='x') ? S_IXUSR : 0;

	fuse_attr->permissions|=(longname.name[4]=='r') ? S_IRGRP : 0;
	fuse_attr->permissions|=(longname.name[5]=='w') ? S_IWGRP : 0;
	fuse_attr->permissions|=(longname.name[6]=='x') ? S_IXGRP : 0;

	fuse_attr->permissions|=(longname.name[7]=='r') ? S_IROTH : 0;
	fuse_attr->permissions|=(longname.name[8]=='w') ? S_IWOTH : 0;
	fuse_attr->permissions|=(longname.name[9]=='x') ? S_IXOTH : 0;

    }

    fuse_attr->valid[FUSE_SFTP_INDEX_PERMISSIONS]=1;
    fuse_attr->received|=FUSE_SFTP_ATTR_PERMISSIONS;

    logoutput_debug("read_attr_response_v03: perm %i", fuse_attr->permissions);

    if (sftp->flags & SFTP_SUBSYSTEM_FLAG_NEWREADDIR) correction=1;

    if (fuse_attr->valid[FUSE_SFTP_INDEX_USER]==0) {
	struct sftp_usermapping_s *usermapping=&sftp->usermapping;
	struct sftp_user_s user;
        char *sep=NULL;

	/* get user */

	user.remote.name.ptr=&longname.name[15 + correction];
	user.remote.name.len=8;
	sep=memchr(user.remote.name.ptr, ' ', 8);
	if (sep) user.remote.name.len=(unsigned int) (sep - (char *)user.remote.name.ptr);

	(* usermapping->get_local_uid)(sftp, &user);

	fuse_attr->user.uid=user.local_uid;

	fuse_attr->valid[FUSE_SFTP_INDEX_USER]=1;
	fuse_attr->received|=FUSE_SFTP_ATTR_USER;

    }

    logoutput_debug("read_attr_response_v03: user %i", fuse_attr->user.uid);

    if (fuse_attr->valid[FUSE_SFTP_INDEX_GROUP]==0) {
	struct sftp_usermapping_s *usermapping=&sftp->usermapping;
	struct sftp_group_s group;
	char *sep=NULL;

	/* get group */

	group.remote.name.ptr=&longname.name[24 + correction];
	group.remote.name.len=8;
	sep=memchr(group.remote.name.ptr, ' ', 8);
	if (sep) group.remote.name.len=(unsigned int) (sep - (char *)group.remote.name.ptr);

	(* usermapping->get_local_gid)(sftp, &group);

	fuse_attr->group.gid=group.local_gid;

	fuse_attr->valid[FUSE_SFTP_INDEX_GROUP]=1;
	fuse_attr->received|=FUSE_SFTP_ATTR_GROUP;

    }

    logoutput("read_attr_response_v03: user %i", fuse_attr->group.gid);

    if (longname.len>42) {
	char sizestr[9];
	memcpy(sizestr, &longname.name[33 + correction], 8);
	sizestr[8]='\0';
	logoutput_debug("read_attr_response_v03: sizestr %s", sizestr);

    }

    if (fuse_attr->valid[FUSE_SFTP_INDEX_SIZE]==0) {

	fuse_attr->size=atoll(&longname.name[33 + correction]);
	fuse_attr->valid[FUSE_SFTP_INDEX_SIZE]=1;
	fuse_attr->received|=FUSE_SFTP_ATTR_SIZE;

    }

    logoutput_debug("read_attr_response_v03: size %i", fuse_attr->size);

    return pos;

}

static void read_sftp_features_v03(struct sftp_subsystem_s *sftp)
{
    struct sftp_supported_s *supported=&sftp->supported;
    supported->fuse_attr_supported=FUSE_SFTP_ATTR_TYPE | FUSE_SFTP_ATTR_SIZE | FUSE_SFTP_ATTR_PERMISSIONS | FUSE_SFTP_ATTR_ATIME | FUSE_SFTP_ATTR_MTIME | FUSE_SFTP_ATTR_CTIME | FUSE_SFTP_ATTR_USER | FUSE_SFTP_ATTR_GROUP;
}

static unsigned int get_attribute_mask_v03(struct sftp_subsystem_s *sftp)
{
    return SSH_FILEXFER_STAT_VALUE;
}

static int get_attribute_info_v03(struct sftp_subsystem_s *sftp, unsigned int valid, const char *what)
{
    if (strcmp(what, "size")==0) return (valid & SSH_FILEXFER_ATTR_SIZE);
    if (strcmp(what, "uid")==0) return (valid & SSH_FILEXFER_ATTR_UIDGID);
    if (strcmp(what, "gid")==0) return (valid & SSH_FILEXFER_ATTR_UIDGID);
    if (strcmp(what, "user@")==0) return -1;
    if (strcmp(what, "group@")==0) return -1;
    if (strcmp(what, "perm")==0) return (valid & SSH_FILEXFER_ATTR_PERMISSIONS);
    if (strcmp(what, "acl")==0) return -1;
    if (strcmp(what, "btime")==0) return -1;
    if (strcmp(what, "atime")==0 || strcmp(what, "ctime")==0 || strcmp(what, "mtime")==0) return (valid & SSH_FILEXFER_ATTR_ACMODTIME);
    if (strcmp(what, "subseconds")==0) return -1;
    return -2;
}

static struct sftp_attr_ops_s attr_ops_v03 = {
    .read_attributes			= read_attributes_v03,
    .write_attributes			= write_attributes_v03,
    .read_name_response			= read_name_response_v03,
    .read_attr_response			= read_attr_response_v03,
    .read_sftp_features			= read_sftp_features_v03,
    .get_attribute_mask			= get_attribute_mask_v03,
    .get_attribute_info			= get_attribute_info_v03,
};

void use_sftp_attr_v03(struct sftp_subsystem_s *sftp_subsystem)
{
    sftp_subsystem->attr_ops=&attr_ops_v03;
}
