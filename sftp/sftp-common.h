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

#ifndef FS_WORKSPACE_SFTP_COMMON_H
#define FS_WORKSPACE_SFTP_COMMON_H

#include "ssh-common.h"

#define SFTP_SUBSYSTEM_FLAG_READDIRPLUS				1
#define SFTP_SUBSYSTEM_FLAG_NEWREADDIR				2

struct sftp_subsystem_s;

struct sftp_header_s {
    unsigned char			type;
    unsigned int			id;
    unsigned int			sequence;
    unsigned int 			len;
    char				*buffer;
};

/* interface specific data like prefix */


struct sftp_send_ops_s {
    unsigned int			version;
    int					(* init)(struct sftp_subsystem_s *sftp, unsigned int *seq);
    int					(* open)(struct sftp_subsystem_s *sftp, struct sftp_request_s *sftp_r);
    int					(* create)(struct sftp_subsystem_s *sftp, struct sftp_request_s *sftp_r);
    int					(* read)(struct sftp_subsystem_s *sftp, struct sftp_request_s *sftp_r);
    int					(* write)(struct sftp_subsystem_s *sftp, struct sftp_request_s *sftp_r);
    int					(* close)(struct sftp_subsystem_s *sftp, struct sftp_request_s *sftp_r);
    int					(* stat)(struct sftp_subsystem_s *sftp, struct sftp_request_s *sftp_r);
    int					(* lstat)(struct sftp_subsystem_s *sftp, struct sftp_request_s *sftp_r);
    int					(* fstat)(struct sftp_subsystem_s *sftp, struct sftp_request_s *sftp_r);
    int					(* setstat)(struct sftp_subsystem_s *sftp, struct sftp_request_s *sftp_r);
    int					(* fsetstat)(struct sftp_subsystem_s *sftp, struct sftp_request_s *sftp_r);
    int					(* realpath)(struct sftp_subsystem_s *sftp, struct sftp_request_s *sftp_r);
    int					(* readlink)(struct sftp_subsystem_s *sftp, struct sftp_request_s *sftp_r);
    int					(* opendir)(struct sftp_subsystem_s *sftp, struct sftp_request_s *sftp_r);
    int					(* readdir)(struct sftp_subsystem_s *sftp, struct sftp_request_s *sftp_r);
    int					(* remove)(struct sftp_subsystem_s *sftp, struct sftp_request_s *sftp_r);
    int					(* rmdir)(struct sftp_subsystem_s *sftp, struct sftp_request_s *sftp_r);
    int					(* mkdir)(struct sftp_subsystem_s *sftp, struct sftp_request_s *sftp_r);
    int					(* rename)(struct sftp_subsystem_s *sftp, struct sftp_request_s *sftp_r);
    int					(* symlink)(struct sftp_subsystem_s *sftp, struct sftp_request_s *sftp_r);
    int					(* block)(struct sftp_subsystem_s *sftp, struct sftp_request_s *sftp_r);
    int					(* unblock)(struct sftp_subsystem_s *sftp, struct sftp_request_s *sftp_r);
    int					(* extension)(struct sftp_subsystem_s *sftp, struct sftp_request_s *sftp_r);
};

struct sftp_attr_ops_s {
    unsigned int 			(* read_attributes)(struct sftp_subsystem_s *sftp, char *buffer, unsigned int size, struct fuse_sftp_attr_s *fuse_attr);
    unsigned int 			(* write_attributes)(struct sftp_subsystem_s *sftp, char *buffer, unsigned int size, struct fuse_sftp_attr_s *fuse_attr);
    void				(* read_name_response)(struct sftp_subsystem_s *sftp, struct name_response_s *r, char **name, unsigned int *len);
    unsigned int			(* read_attr_response)(struct sftp_subsystem_s *sftp, struct name_response_s *r, struct fuse_sftp_attr_s *f);
    void				(* read_sftp_features)(struct sftp_subsystem_s *sftp);
    unsigned int			(* get_attribute_mask)(struct sftp_subsystem_s *sftp);
};

struct sftp_recv_ops_s {
    void				(* status)(struct sftp_subsystem_s *sftp, struct sftp_header_s *header);
    void				(* handle)(struct sftp_subsystem_s *sftp, struct sftp_header_s *header);
    void				(* data)(struct sftp_subsystem_s *sftp, struct sftp_header_s *header);
    void				(* name)(struct sftp_subsystem_s *sftp, struct sftp_header_s *header);
    void				(* attr)(struct sftp_subsystem_s *sftp, struct sftp_header_s *header);
    void				(* extension)(struct sftp_subsystem_s *sftp, struct sftp_header_s *header);
    void				(* extension_reply)(struct sftp_subsystem_s *sftp, struct sftp_header_s *header);
};

struct sftp_supported_s {
    union {
	struct v06_s {
	    unsigned char			init;
	    unsigned int			attribute_mask;
    	    unsigned int			attribute_bits;
	    unsigned int			open_flags;
	    unsigned int			access_mask;
	    unsigned int			max_read_size;
	    unsigned int			open_block_vector;
	    unsigned int			block_vector;
	    unsigned int			attrib_extension_count;
	    unsigned int			extension_count;
	} v06;
	struct v05_s {
	    unsigned char			init;
	    unsigned int			attribute_mask;
    	    unsigned int			attribute_bits;
	    unsigned int			open_flags;
	    unsigned int			access_mask;
	    unsigned int			max_read_size;
	} v05;
    } version;
    unsigned int			extensions;
    unsigned int			fuse_attr_supported;
};

struct sftp_user_s {
    union {
	struct ssh_string_s 		name;
	unsigned int			id;
    } remote;
    uid_t				local_uid;
};

struct sftp_group_s {
    union {
	struct ssh_string_s 		name;
	unsigned int			id;
    } remote;
    gid_t				local_gid;
};

#define _SFTP_USER_MAPPING_SHARED		1
#define _SFTP_USER_MAPPING_NONSHARED		2

#define _SFTP_USERMAP_LOCAL_GID			1
#define _SFTP_USERMAP_REMOTE_IDS		2
#define _SFTP_USERMAP_LOCAL_IDS_UNKNOWN		4

struct sftp_usermapping_s {
    unsigned char			type;
    uid_t				local_unknown_uid;
    gid_t				local_unknown_gid;
    union {
	struct name_shared_s {
	    pthread_mutex_t		pwd_mutex;
	    pthread_mutex_t		gr_mutex;
	} name_shared;
	struct name_nonshared_s {
	    gid_t			local_gid;
	    struct ssh_string_s		remote_group;
	} name_nonshared;
	struct id_nonshared_s {
	    gid_t			local_gid;
	    uid_t			remote_uid;
	    gid_t			remote_gid;
	} id_nonshared;
    } data;
    void				(* get_local_uid)(struct sftp_subsystem_s *sftp, struct sftp_user_s *user);
    void				(* get_local_gid)(struct sftp_subsystem_s *sftp, struct sftp_group_s *group);
    void				(* get_remote_user)(struct sftp_subsystem_s *sftp, struct sftp_user_s *user);
    void				(* get_remote_group)(struct sftp_subsystem_s *sftp, struct sftp_group_s *group);
};

struct sftp_send_hash_s {
    uint32_t				sftp_request_id;
    pthread_mutex_t			mutex;
    void				*hashtable;
    unsigned int			tablesize;
    struct list_element_s		*t_head;
    struct list_element_s		*t_tail;
};

#define SFTP_STATUS_INIT		1
#define SFTP_STATUS_UP			2

struct sftp_subsystem_s {
    unsigned int			flags;
    pthread_mutex_t			mutex;
    unsigned int			status;
    unsigned int			refcount;
    struct ssh_string_s			remote_home;
    unsigned int 			server_version;
    struct sftp_send_ops_s		*send_ops;
    struct sftp_recv_ops_s		*recv_ops;
    struct sftp_attr_ops_s		*attr_ops;
    struct sftp_supported_s		supported;
    struct sftp_usermapping_s		usermapping;
    struct sftp_send_hash_s		send_hash;
    struct ssh_channel_s		channel;
};

/* prototypes */

void set_sftp_protocol(struct sftp_subsystem_s *sftp_subsystem);
void get_sftp_request_timeout(struct timespec *timeout);

unsigned int get_sftp_version(struct sftp_subsystem_s *sftp);
unsigned int get_sftp_version_ctx(void *ptr);
void set_sftp_server_version(struct sftp_subsystem_s *sftp, unsigned int version);

unsigned int get_sftp_request_id(struct sftp_subsystem_s *sftp);

int connect_sftp_common(uid_t uid, struct context_interface_s *interface, struct context_address_s *address, unsigned int *error);
int start_sftp_common(struct context_interface_s *interface, int fd, void *data);
void umount_sftp_subsystem(struct context_interface_s *interface);

unsigned char get_sftp_features(void *ptr);
unsigned char statfs_support(struct sftp_subsystem_s *sftp);

#endif
