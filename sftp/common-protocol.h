/*
  2010, 2011, 2012, 2013, 2014, 2015, 2016 Stef Bon <stefbon@gmail.com>

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

#ifndef FS_WORKSPACE_SFTP_COMMON_PROTOCOL_H
#define FS_WORKSPACE_SFTP_COMMON_PROTOCOL_H

#define SSH_FXP_INIT 				1
#define SSH_FXP_VERSION 			2
#define SSH_FXP_OPEN 				3
#define SSH_FXP_CLOSE 				4
#define SSH_FXP_READ 				5
#define SSH_FXP_WRITE 				6
#define SSH_FXP_LSTAT 				7
#define SSH_FXP_FSTAT 				8
#define SSH_FXP_SETSTAT 			9
#define SSH_FXP_FSETSTAT 			10
#define SSH_FXP_OPENDIR 			11
#define SSH_FXP_READDIR 			12
#define SSH_FXP_REMOVE 				13
#define SSH_FXP_MKDIR 				14
#define SSH_FXP_RMDIR 				15
#define SSH_FXP_REALPATH 			16
#define SSH_FXP_STAT 				17
#define SSH_FXP_RENAME 				18
#define SSH_FXP_READLINK 			19
#define SSH_FXP_SYMLINK 			20
#define SSH_FXP_LINK 				21
#define SSH_FXP_BLOCK 				22
#define SSH_FXP_UNBLOCK 			23

#define SSH_FXP_STATUS 				101
#define SSH_FXP_HANDLE 				102
#define SSH_FXP_DATA 				103
#define SSH_FXP_NAME 				104
#define SSH_FXP_ATTRS 				105

#define SSH_FXP_EXTENDED 			200
#define SSH_FXP_EXTENDED_REPLY 			201

#define SSH_FXP_MAPPING_MIN			210
#define SSH_FXP_MAPPING_MAX			255

#define SFTP_HANDLE_MAXSIZE			255

#define FUSE_SFTP_INDEX_TYPE			0
#define FUSE_SFTP_ATTR_TYPE			1 << FUSE_SFTP_INDEX_TYPE
#define FUSE_SFTP_INDEX_SIZE			1
#define FUSE_SFTP_ATTR_SIZE			1 << FUSE_SFTP_INDEX_SIZE
#define FUSE_SFTP_INDEX_PERMISSIONS		2
#define FUSE_SFTP_ATTR_PERMISSIONS		1 << FUSE_SFTP_INDEX_PERMISSIONS
#define FUSE_SFTP_INDEX_ATIME			3
#define FUSE_SFTP_ATTR_ATIME			1 << FUSE_SFTP_INDEX_ATIME
#define FUSE_SFTP_INDEX_MTIME			4
#define FUSE_SFTP_ATTR_MTIME			1 << FUSE_SFTP_INDEX_MTIME
#define FUSE_SFTP_INDEX_CTIME			5
#define FUSE_SFTP_ATTR_CTIME			1 << FUSE_SFTP_INDEX_CTIME
#define FUSE_SFTP_INDEX_USER			6
#define FUSE_SFTP_ATTR_USER			1 << FUSE_SFTP_INDEX_USER
#define FUSE_SFTP_INDEX_GROUP			7
#define FUSE_SFTP_ATTR_GROUP			1 << FUSE_SFTP_INDEX_GROUP

#define SFTP_REQUEST_STATUS_WAITING		1
#define SFTP_REQUEST_STATUS_RESPONSE		2
#define SFTP_REQUEST_STATUS_INTERRUPT		3

struct network_user_s {
    uid_t			uid;
    unsigned int		domain;
};

struct network_group_s {
    gid_t			gid;
    unsigned int		domain;
};

struct fuse_sftp_attr_s {
    unsigned char		valid[8];
    unsigned int		asked;
    unsigned int		received;
    unsigned int		type;
    uint64_t			size;
    mode_t			permissions;
    int64_t			atime;
    unsigned long		atime_n;
    int64_t			mtime;
    unsigned long		mtime_n;
    int64_t			ctime;
    unsigned long		ctime_n;
    struct network_user_s	user;
    struct network_group_s	group;
};

/*
    responses from SFTP
    these are almos the same for the different sftp versions
    the differences:

    STATUS
    ------

    - the list of error codes is getting longer for the higher versions
      the body of the message looks like:

	uint32		id
	uint32		status code
	string		error message (ISO-10646 UTF-8)
	string		language tag

    - for version 5 and later error specific data is added:

	error specific data

    DATA
    ----

    - version 6 and later added an optional byte is added:

	bool end-of-list (optional)

    NAME
    ----

    - the buffer in the name response for version 3 looks like:

	uint32		id
	uint32		count
	repeats count times:
	    string filename
	    string longname
	    ATTR   attrs

    - for versions 4-5 it looks like:

	uint32		id
	uint32		count
	repeats count times:
	    string filename [UTF-8]
	    ATTR   attrs

    - for later versions (6..) it looks the same as for versions 4 and 5,
      only and optional byte is added:

	bool end-of-list (optional)

*/

struct status_response_s {
    unsigned int 		code;
    unsigned int		linux_error;
    unsigned char		*buff; /* error specific data */
    unsigned int		size;
};

struct handle_response_s {
    unsigned int		len;
    unsigned char		*name;
};

struct data_response_s {
    unsigned int		size;
    unsigned char		*data;
    signed char			eof;
};

struct name_response_s {
    unsigned int		count;
    unsigned int		size;
    signed char			eof; /* optional end-of-data, only supported version >= 6 */
    char			*buff; /* list of names (name, attr) as send by server, leave it to the receiving (FUSE) thread to process */
    char			*pos;
};

struct attr_response_s {
    unsigned int		size;
    unsigned char		*buff; /* attributes as send by server, leave it to the receiving (FUSE) thread to process */
};

struct extension_response_s {
    unsigned int		size;
    unsigned char		*buff;
};

union sftp_response_u {
    struct status_response_s 	status;
    struct handle_response_s	handle;
    struct data_response_s	data;
    struct name_response_s 	names;
    struct attr_response_s	attr;
    struct extension_response_s extension;
};

struct sftp_reply_s {
    unsigned char		type;
    uint32_t			sequence;
    union sftp_response_u	response;
    unsigned int		error;
};

/*
    request to SFTP
*/

struct sftp_path_s {
    unsigned char		*path;
    unsigned int 		len;
};

struct sftp_handle_s {
    unsigned int		len;
    unsigned char		*handle;
};

struct sftp_open_s {
    unsigned char		*path;
    unsigned int		len;
    unsigned int		posix_flags;
};

struct sftp_create_s {
    unsigned char		*path;
    unsigned int		len;
    unsigned int		posix_flags;
    unsigned int		size;
    unsigned char		*buff;
};

struct sftp_read_s {
    unsigned int		len;
    unsigned char		*handle;
    uint64_t			offset;
    uint64_t			size;
};

struct sftp_write_s {
    unsigned int		len;
    unsigned char		*handle;
    uint64_t			offset;
    uint64_t			size;
    char			*data;
};

struct sftp_rename_s {
    unsigned char		*path;
    unsigned int		len;
    unsigned char		*target_path;
    unsigned int		target_len;
    unsigned int		posix_flags;
};

struct sftp_mkdir_s {
    unsigned char		*path;
    unsigned int		len;
    unsigned int		size;
    unsigned char		*buff;
};

struct sftp_setstat_s {
    unsigned char		*path;
    unsigned int		len;
    unsigned int		size;
    unsigned char		*buff;
};

struct sftp_fsetstat_s {
    unsigned char		*handle;
    unsigned int 		len;
    unsigned int		size;
    unsigned char		*buff;
};

struct sftp_link_s {
    unsigned char		*path;
    unsigned int		len;
    unsigned char		*target_path;
    unsigned int		target_len;
    unsigned char		symlink;
};

struct sftp_symlink_s {
    unsigned char		*path;
    unsigned int		len;
    unsigned char		*target_path;
    unsigned int		target_len;
};

struct sftp_block_s {
    unsigned char		*handle;
    unsigned int 		len;
    uint64_t			offset;
    uint64_t			size;
    uint32_t			type;
};

struct sftp_unblock_s {
    unsigned char		*handle;
    unsigned int 		len;
    uint64_t			offset;
    uint64_t			size;
};

struct sftp_data_s {
    unsigned char		*data;
    unsigned int		len;
};

struct sftp_extension_s {
    unsigned char		*name;
    unsigned int		len;
    unsigned int		size;
    unsigned char		*data;
};

struct sftp_custom_s {
    unsigned char		nr;
    unsigned int		size;
    unsigned char		*data;
};

struct sftp_request_s {
    unsigned int			status;
    unsigned int			id;
    union {
	struct sftp_path_s		stat;
	struct sftp_path_s		lstat;
	struct sftp_handle_s		fstat;
	struct sftp_setstat_s		setstat;
	struct sftp_fsetstat_s		fsetstat;
	struct sftp_open_s		open;
	struct sftp_create_s		create;
	struct sftp_path_s		opendir;
	struct sftp_read_s		read;
	struct sftp_write_s		write;
	struct sftp_handle_s		fsync;
	struct sftp_handle_s		readdir;
	struct sftp_handle_s		close;
	struct sftp_path_s		remove;
	struct sftp_rename_s		rename;
	struct sftp_mkdir_s		mkdir;
	struct sftp_path_s		rmdir;
	struct sftp_path_s		readlink;
	struct sftp_link_s 		link;
	struct sftp_symlink_s 		symlink;
	struct sftp_block_s		block;
	struct sftp_unblock_s		unblock;
	struct sftp_handle_s		fstatvfs;
	struct sftp_path_s		realpath;
	struct sftp_extension_s 	extension;
	struct sftp_custom_s		custom;
    } call;
    struct sftp_reply_s		reply;
    struct fuse_request_s	*fuse_request;
};

#endif
