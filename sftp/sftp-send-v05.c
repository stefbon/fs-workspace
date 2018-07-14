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

#include <linux/fs.h>

#include "main.h"
#include "logging.h"
#include "utils.h"

#include "workspace-interface.h"
#include "ssh-common-protocol.h"
#include "ssh-common.h"
#include "ssh-utils.h"
#include "ssh-send.h"

#include "sftp-common-protocol.h"
#include "sftp-common.h"
#include "sftp-send-v03.h"
#include "sftp-send-v04.h"
#include "sftp-protocol-v05.h"

static void get_sftp_openmode(unsigned int posix_access, unsigned int *sftp_access, unsigned int *sftp_flags)
{
    unsigned char b1=(posix_access & O_WRONLY) ? 1 : 0;
    unsigned char b2=(posix_access & O_RDWR) ? 1 : 0;
    unsigned char b3=(posix_access & O_APPEND) ? 1 : 0;
    unsigned char b4=(posix_access & O_CREAT) ? 1 : 0;
    unsigned char b5=(posix_access & O_TRUNC) ? 1 : 0;
    unsigned char b6=b5 * b4; /* for when O_CREAT and O_TRUNC both are defined */
    //unsigned char b7=1 - (b2 | b1); /* when none is defined: O_RDONLY */
    unsigned char b7=1; /* always O_RDONLY */
    unsigned char b8=(posix_access & O_EXCL) ? 1 : 0;

    logoutput("get_sftp_openmode: posix %i", posix_access);

    *sftp_access=0;
    *sftp_flags=0;

    b5-=b6;
    // b4-=b6;

    *sftp_access|=(ACE4_READ_DATA | ACE4_READ_ATTRIBUTES) * b7;
    *sftp_access|=(ACE4_WRITE_DATA | ACE4_WRITE_ATTRIBUTES) * b1;
    *sftp_access|=(ACE4_READ_DATA | ACE4_READ_ATTRIBUTES | ACE4_WRITE_DATA | ACE4_WRITE_ATTRIBUTES) * b2;
    *sftp_access|=(ACE4_WRITE_DATA | ACE4_WRITE_ATTRIBUTES | ACE4_APPEND_DATA) * b3;

    if (b4) {

	/* create */

	if (b8) {

	    /* excl (may not exist) */

	    *sftp_flags|=(SSH_FXF_CREATE_NEW);

	} else if (b5 & b1) {

	    /* truncate and wronly (may exist) */

	    *sftp_flags|=(SSH_FXF_CREATE_TRUNCATE);

	} else {

	    /* (may exist) */

	    *sftp_flags|=(SSH_FXF_OPEN_OR_CREATE);

	}

    } else if (b5) {

	/* must exist */

	*sftp_flags|=(SSH_FXF_TRUNCATE_EXISTING);

    } else if (b3) {

	*sftp_flags|=(SSH_FXF_APPEND_DATA);

    } else {

	/* normal open */

	*sftp_flags|=(SSH_FXF_OPEN_EXISTING);

    }

}

/*
    OPEN a file
    - byte 1 	SSH_FXP_OPEN
    - uint32 	request id
    - uint32 	len path (n)
    - byte[n]	path
    - uint32	desired-access
    - uint32	flags
    - attrs (5) ignored when opening an existing file

*/

int send_sftp_open_v05(struct sftp_subsystem_s *sftp_subsystem, struct sftp_request_s *sftp_r)
{
    char data[26 + sftp_r->call.open.len];
    unsigned int pos=0;
    unsigned int access=0;
    unsigned int flags=0;

    get_sftp_openmode(sftp_r->call.open.posix_flags, &access, &flags);
    sftp_r->id=get_sftp_request_id(sftp_subsystem);

    logoutput("send_sftp_open: access %i flags %i", access, flags);

    store_uint32(&data[pos], 22 + sftp_r->call.open.len);
    pos+=4;
    data[pos]=(unsigned char) SSH_FXP_OPEN;
    pos++;
    store_uint32(&data[pos], sftp_r->id);
    pos+=4;
    store_uint32(&data[pos], sftp_r->call.open.len);
    pos+=4;
    memcpy((char *) &data[pos], sftp_r->call.open.path, sftp_r->call.open.len);
    pos+=sftp_r->call.open.len;
    store_uint32(&data[pos], access);
    pos+=4;
    store_uint32(&data[pos], flags);
    pos+=4;
    store_uint32(&data[pos], 0); /* valid attributes: no attributes */
    pos+=4;
    data[pos]=(unsigned char) SSH_FILEXFER_TYPE_REGULAR;
    pos++;

    return send_channel_data_message(&sftp_subsystem->channel, pos, data, &sftp_r->sequence);

}

/*
    CREATE a file
    - byte 1 	SSH_FXP_OPEN
    - uint32 	request id
    - uint32 	len path (n)
    - byte[n]	path
    - uint32	desired-access
    - uint32	flags
    - attrs (x) 

*/

int send_sftp_create_v05(struct sftp_subsystem_s *sftp_subsystem, struct sftp_request_s *sftp_r)
{
    char data[21 + sftp_r->call.create.len + sftp_r->call.create.size];
    unsigned int pos=0;
    unsigned int access=0;
    unsigned int flags=0;

    get_sftp_openmode(sftp_r->call.create.posix_flags, &access, &flags);
    sftp_r->id=get_sftp_request_id(sftp_subsystem);

    logoutput("send_sftp_create: access %i flags %i", access, flags);

    store_uint32(&data[pos], 17 + sftp_r->call.create.len + sftp_r->call.create.size);
    pos+=4;
    data[pos]=(unsigned char) SSH_FXP_OPEN;
    pos++;
    store_uint32(&data[pos], sftp_r->id);
    pos+=4;
    store_uint32(&data[pos], sftp_r->call.create.len);
    pos+=4;
    memcpy((char *) &data[pos], sftp_r->call.create.path, sftp_r->call.create.len);
    pos+=sftp_r->call.create.len;
    store_uint32(&data[pos], access);
    pos+=4;
    store_uint32(&data[pos], flags);
    pos+=4;
    memcpy((char *) &data[pos], sftp_r->call.create.buff, sftp_r->call.create.size);
    pos+=sftp_r->call.create.size;

    return send_channel_data_message(&sftp_subsystem->channel, pos, data, &sftp_r->sequence);

}

/*
    RENAME
    - byte 1 	SSH_FXP_RENAME
    - uint32 	request id
    - uint32 	len old path (n)
    - byte[n]	old path
    - uint32 	len new path (m)
    - byte[m]	new path
    - uint32	flags
*/

int send_sftp_rename_v05(struct sftp_subsystem_s *sftp_subsystem, struct sftp_request_s *sftp_r)
{
    char data[21 + sftp_r->call.rename.len + sftp_r->call.rename.target_len];
    unsigned int pos=0;
    unsigned int flags=SSH_FXF_RENAME_NATIVE; /* seems reasonable */

    sftp_r->id=get_sftp_request_id(sftp_subsystem);

    if (! (sftp_r->call.rename.posix_flags & RENAME_NOREPLACE)) {

	flags|= SSH_FXF_RENAME_OVERWRITE;

    }

    store_uint32(&data[pos], 17 + sftp_r->call.rename.len + sftp_r->call.rename.target_len);
    pos+=4;
    data[pos]=(unsigned char) SSH_FXP_RENAME;
    pos++;
    store_uint32(&data[pos], sftp_r->id);
    pos+=4;
    store_uint32(&data[pos], sftp_r->call.rename.len);
    pos+=4;
    memcpy((char *) &data[pos], sftp_r->call.rename.path, sftp_r->call.rename.len);
    pos+=sftp_r->call.rename.len;
    store_uint32(&data[pos], sftp_r->call.rename.target_len);
    pos+=4;
    memcpy((char *) &data[pos], sftp_r->call.rename.target_path, sftp_r->call.rename.target_len);
    pos+=sftp_r->call.rename.target_len;
    store_uint32(&data[pos], flags);
    pos+=4;

    return send_channel_data_message(&sftp_subsystem->channel, pos, data, &sftp_r->sequence);

}

static int send_sftp_stat_v05(struct sftp_subsystem_s *sftp_subsystem, struct sftp_request_s *sftp_r)
{
    unsigned int flags=(* sftp_subsystem->attr_ops->get_attribute_mask)(sftp_subsystem);
    return send_sftp_stat_v04_generic(sftp_subsystem, sftp_r, flags & SSH_FILEXFER_STAT_VALUE);
}

static int send_sftp_lstat_v05(struct sftp_subsystem_s *sftp_subsystem, struct sftp_request_s *sftp_r)
{
    unsigned int flags=(* sftp_subsystem->attr_ops->get_attribute_mask)(sftp_subsystem);
    return send_sftp_lstat_v04_generic(sftp_subsystem, sftp_r, flags & SSH_FILEXFER_STAT_VALUE);
}

static int send_sftp_fstat_v05(struct sftp_subsystem_s *sftp_subsystem, struct sftp_request_s *sftp_r)
{
    unsigned int flags=(* sftp_subsystem->attr_ops->get_attribute_mask)(sftp_subsystem);
    return send_sftp_fstat_v04_generic(sftp_subsystem, sftp_r, flags & SSH_FILEXFER_STAT_VALUE);
}

static struct sftp_send_ops_s send_ops_v05 = {
    .version				= 5,
    .init				= send_sftp_init_v04,
    .open				= send_sftp_open_v05,
    .create				= send_sftp_create_v05,
    .read				= send_sftp_read_v03,
    .write				= send_sftp_write_v03,
    .close				= send_sftp_close_v03,
    .stat				= send_sftp_stat_v05,
    .lstat				= send_sftp_lstat_v05,
    .fstat				= send_sftp_fstat_v05,
    .setstat				= send_sftp_setstat_v03,
    .fsetstat				= send_sftp_fsetstat_v03,
    .realpath				= send_sftp_realpath_v03,
    .readlink				= send_sftp_readlink_v03,
    .opendir				= send_sftp_opendir_v03,
    .readdir				= send_sftp_readdir_v03,
    .remove				= send_sftp_remove_v03,
    .rmdir				= send_sftp_rmdir_v03,
    .mkdir				= send_sftp_mkdir_v03,
    .rename				= send_sftp_rename_v05,
    .symlink				= send_sftp_symlink_v03,
    .block				= send_sftp_block_v03,
    .unblock				= send_sftp_unblock_v03,
    .extension				= send_sftp_extension_v03,
};

void use_sftp_send_v05(struct sftp_subsystem_s *sftp_subsystem)
{
    sftp_subsystem->send_ops=&send_ops_v05;
}
