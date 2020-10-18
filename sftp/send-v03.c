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

#include "common-protocol.h"
#include "common.h"
#include "send-v03.h"
#include "protocol-v03.h"

/*
    convert the posix openflags to sftp flags for sftp version 3
    see:
    https://tools.ietf.org/html/draft-ietf-secsh-filexfer-02#section-6.3
*/

static void get_sftp_openmode_v03(unsigned int posix_flags, unsigned int *sftp_flags)
{
    /* convert the posix flags to sftp openmode */

    *sftp_flags=0;

    if (posix_flags & O_WRONLY) {

	*sftp_flags |= SSH_FXF_WRITE;

    } else if (posix_flags & O_RDWR) {

	*sftp_flags |= (SSH_FXF_WRITE | SSH_FXF_READ);

    } else {

	*sftp_flags |= SSH_FXF_READ;

    }

    if (posix_flags & O_APPEND) {

	*sftp_flags |= SSH_FXF_APPEND;

    }

    if (posix_flags & O_CREAT) {

	if (posix_flags & O_EXCL) {

	    *sftp_flags |= (SSH_FXF_CREAT | SSH_FXF_EXCL);

	} else if (posix_flags & O_TRUNC) {

	    *sftp_flags |= (SSH_FXF_CREAT | SSH_FXF_TRUNC);

	}

    }

}

static unsigned int _write_sftp_init(struct sftp_subsystem_s *sftp, char *data)
{

    if (data) {

	store_uint32(&data[0], 5);
	data[4]=(unsigned char) SSH_FXP_INIT;
	store_uint32(&data[5], get_sftp_version(sftp));

	return 9;

    } else {

	return 9;

    }

    return 0;

}

int send_sftp_init_v03(struct sftp_subsystem_s *sftp, unsigned int *seq)
{
    unsigned int len=_write_sftp_init(sftp, NULL);
    char data[len];

    len=_write_sftp_init(sftp, data);

    /* TODO: add extensions (which?) */

    return send_channel_data_message(&sftp->channel, len, data, seq);

}

/*
    OPEN a file
    - byte 1 	SSH_FXP_OPEN
    - uint32 	request id
    - uint32 	len path (n)
    - byte[n]	path
    - uint32	pflags
    - attrs (5) ignored when opening a file

*/

int send_sftp_open_v03(struct sftp_subsystem_s *sftp, struct sftp_request_s *sftp_r)
{
    char data[22 + sftp_r->call.open.len];
    unsigned int pos=0;
    unsigned int pflags=0;

    get_sftp_openmode_v03(sftp_r->call.open.posix_flags, &pflags);

    sftp_r->id=get_sftp_request_id(sftp);

    logoutput_debug("send_sftp_open: pflags %i", pflags);

    store_uint32(&data[pos], 18 + sftp_r->call.open.len);
    pos+=4;
    data[pos]=(unsigned char) SSH_FXP_OPEN;
    pos++;
    store_uint32(&data[pos], sftp_r->id);
    pos+=4;
    store_uint32(&data[pos], sftp_r->call.open.len);
    pos+=4;
    memcpy((char *) &data[pos], sftp_r->call.open.path, sftp_r->call.open.len);
    pos+=sftp_r->call.open.len;

    store_uint32(&data[pos], pflags);
    pos+=4;

    store_uint32(&data[pos], 0); /* valid attributes: no attributes */
    pos+=4;
    data[pos]=(unsigned char) SSH_FILEXFER_TYPE_REGULAR;
    pos++;

    return send_channel_data_message(&sftp->channel, pos, data, &sftp_r->reply.sequence);

}

/*
    CREATE a file
    - byte 1 	SSH_FXP_OPEN
    - uint32 	request id
    - uint32 	len path (n)
    - byte[n]	path
    - uint32	pflags
    - attrs (x) 

*/

int send_sftp_create_v03(struct sftp_subsystem_s *sftp, struct sftp_request_s *sftp_r)
{
    char data[17 + sftp_r->call.create.len + sftp_r->call.create.size];
    unsigned int pos=0;
    unsigned int access=0;
    unsigned int pflags=0;

    get_sftp_openmode_v03(sftp_r->call.open.posix_flags, &pflags);
    sftp_r->id=get_sftp_request_id(sftp);

    logoutput_debug("send_sftp_create: pflags %i", pflags);

    store_uint32(&data[pos], 13 + sftp_r->call.create.len + sftp_r->call.create.size);
    pos+=4;
    data[pos]=(unsigned char) SSH_FXP_OPEN;
    pos++;
    store_uint32(&data[pos], sftp_r->id);
    pos+=4;
    store_uint32(&data[pos], sftp_r->call.create.len);
    pos+=4;
    memcpy((char *) &data[pos], sftp_r->call.create.path, sftp_r->call.create.len);
    pos+=sftp_r->call.create.len;
    store_uint32(&data[pos], pflags);
    pos+=4;
    memcpy((char *) &data[pos], sftp_r->call.create.buff, sftp_r->call.create.size);
    pos+=sftp_r->call.create.size;

    return send_channel_data_message(&sftp->channel, pos, data, &sftp_r->reply.sequence);

}

/*
    OPENDIR
    - byte 1 	SSH_FXP_OPENDIR
    - uint32 	request id
    - uint32 	len path (n)
    - byte[n]	path
*/

int send_sftp_opendir_v03(struct sftp_subsystem_s *sftp, struct sftp_request_s *sftp_r)
{
    char data[13 + sftp_r->call.opendir.len];
    unsigned int pos=0;

    sftp_r->id=get_sftp_request_id(sftp);

    store_uint32(&data[pos], 9 + sftp_r->call.opendir.len);
    pos+=4;
    data[pos]=(unsigned char) SSH_FXP_OPENDIR;
    pos++;
    store_uint32(&data[pos], sftp_r->id);
    pos+=4;
    store_uint32(&data[pos], sftp_r->call.opendir.len);
    pos+=4;
    memcpy((char *) &data[pos], sftp_r->call.opendir.path, sftp_r->call.opendir.len);
    pos+=sftp_r->call.opendir.len;

    return send_channel_data_message(&sftp->channel, pos, data, &sftp_r->reply.sequence);

}

/*
    READ
    - byte 1 	SSH_FXP_READ
    - uint32 	request id
    - uint32 	len handle (n)
    - byte[n]	handle
    - uint64_t	offset
    - uint32_t	size
*/

int send_sftp_read_v03(struct sftp_subsystem_s *sftp, struct sftp_request_s *sftp_r)
{
    char data[25 + sftp_r->call.read.len];
    unsigned int pos=0;

    sftp_r->id=get_sftp_request_id(sftp);

    store_uint32(&data[pos], 21 + sftp_r->call.read.len);
    pos+=4;
    data[pos]=(unsigned char) SSH_FXP_READ;
    pos++;
    store_uint32(&data[pos], sftp_r->id);
    pos+=4;
    store_uint32(&data[pos], sftp_r->call.read.len);
    pos+=4;
    memcpy((char *) &data[pos], sftp_r->call.read.handle, sftp_r->call.read.len);
    pos+=sftp_r->call.read.len;
    store_uint64(&data[pos], sftp_r->call.read.offset);
    pos+=8;
    store_uint32(&data[pos], sftp_r->call.read.size);
    pos+=4;

    return send_channel_data_message(&sftp->channel, pos, data, &sftp_r->reply.sequence);

}

/*
    WRITE
    - byte 1 	SSH_FXP_WRITE
    - uint32 	request id
    - uint32 	len handle (n)
    - byte[n]	handle
    - uint64_t	offset
    - uint32_t	len data (m)
    - byte[m]   data
*/

int send_sftp_write_v03(struct sftp_subsystem_s *sftp, struct sftp_request_s *sftp_r)
{
    char data[25 + sftp_r->call.write.len + sftp_r->call.write.size];
    unsigned int pos=0;

    sftp_r->id=get_sftp_request_id(sftp);

    store_uint32(&data[pos], 21 + sftp_r->call.write.len + sftp_r->call.write.size);
    pos+=4;
    data[pos]=(unsigned char) SSH_FXP_WRITE;
    pos++;
    store_uint32(&data[pos], sftp_r->id);
    pos+=4;
    store_uint32(&data[pos], sftp_r->call.write.len);
    pos+=4;
    memcpy((char *) &data[pos], sftp_r->call.write.handle, sftp_r->call.write.len);
    pos+=sftp_r->call.write.len;
    store_uint64(&data[pos], sftp_r->call.write.offset);
    pos+=8;
    store_uint32(&data[pos], sftp_r->call.write.size);
    pos+=4;
    memcpy(&data[pos], sftp_r->call.write.data, sftp_r->call.write.size);
    pos+=sftp_r->call.write.size;

    return send_channel_data_message(&sftp->channel, pos, data, &sftp_r->reply.sequence);

}

/*
    READDIR
    - byte 1 	SSH_FXP_READDIR
    - uint32 	request id
    - uint32 	len handle (n)
    - byte[n]	handle
*/

int send_sftp_readdir_v03(struct sftp_subsystem_s *sftp, struct sftp_request_s *sftp_r)
{
    char data[13 + sftp_r->call.readdir.len];
    unsigned int pos=0;

    sftp_r->id=get_sftp_request_id(sftp);

    store_uint32(&data[pos], 9 + sftp_r->call.readdir.len);
    pos+=4;
    data[pos]=(unsigned char) SSH_FXP_READDIR;
    pos++;
    store_uint32(&data[pos], sftp_r->id);
    pos+=4;
    store_uint32(&data[pos], sftp_r->call.readdir.len);
    pos+=4;
    memcpy((char *) &data[pos], sftp_r->call.readdir.handle, sftp_r->call.readdir.len);
    pos+=sftp_r->call.readdir.len;

    return send_channel_data_message(&sftp->channel, pos, data, &sftp_r->reply.sequence);

}

/*
    CLOSE (directory or file)
    - byte 1 	SSH_FXP_CLOSE
    - uint32 	request id
    - uint32 	len handle (n)
    - byte[n]	handle
*/

int send_sftp_close_v03(struct sftp_subsystem_s *sftp, struct sftp_request_s *sftp_r)
{
    char data[13 + sftp_r->call.close.len];
    unsigned int pos=0;

    sftp_r->id=get_sftp_request_id(sftp);

    store_uint32(&data[pos], 9 + sftp_r->call.close.len);
    pos+=4;
    data[pos]=(unsigned char) SSH_FXP_CLOSE;
    pos++;
    store_uint32(&data[pos], sftp_r->id);
    pos+=4;
    store_uint32(&data[pos], sftp_r->call.close.len);
    pos+=4;
    memcpy((char *) &data[pos], sftp_r->call.close.handle, sftp_r->call.close.len);
    pos+=sftp_r->call.close.len;

    return send_channel_data_message(&sftp->channel, pos, data, &sftp_r->reply.sequence);

}

/*
    REMOVE
    - byte 1 	SSH_FXP_REMOVE
    - uint32 	request id
    - uint32 	len path (n)
    - byte[n]	path
*/

int send_sftp_remove_v03(struct sftp_subsystem_s *sftp, struct sftp_request_s *sftp_r)
{
    char data[13 + sftp_r->call.remove.len];
    unsigned int pos=0;

    sftp_r->id=get_sftp_request_id(sftp);

    store_uint32(&data[pos], 9 + sftp_r->call.remove.len);
    pos+=4;
    data[pos]=(unsigned char) SSH_FXP_REMOVE;
    pos++;
    store_uint32(&data[pos], sftp_r->id);
    pos+=4;
    store_uint32(&data[pos], sftp_r->call.remove.len);
    pos+=4;
    memcpy((char *) &data[pos], sftp_r->call.remove.path, sftp_r->call.remove.len);
    pos+=sftp_r->call.remove.len;

    return send_channel_data_message(&sftp->channel, pos, data, &sftp_r->reply.sequence);

}

/*
    RENAME
    - byte 1 	SSH_FXP_RENAME
    - uint32 	request id
    - uint32 	len old path (n)
    - byte[n]	old path
    - uint32 	len new path (m)
    - byte[m]	new path
*/

int send_sftp_rename_v03(struct sftp_subsystem_s *sftp, struct sftp_request_s *sftp_r)
{
    char data[17 + sftp_r->call.rename.len + sftp_r->call.rename.target_len];
    unsigned int pos=0;

    sftp_r->id=get_sftp_request_id(sftp);

    store_uint32(&data[pos], 13 + sftp_r->call.rename.len + sftp_r->call.rename.target_len);
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


    return send_channel_data_message(&sftp->channel, pos, data, &sftp_r->reply.sequence);

}

/*
    MKDIR
    - byte 1 	SSH_FXP_MKDIR
    - uint32 	request id
    - uint32 	len path (n)
    - byte[n]	path
    - attr	attributes

    NOTE:
    here the attributes block is a buffer of size bytes, the construction of this block is done by the caller
*/

int send_sftp_mkdir_v03(struct sftp_subsystem_s *sftp, struct sftp_request_s *sftp_r)
{
    char data[13 + sftp_r->call.mkdir.len + sftp_r->call.mkdir.size];
    unsigned int pos=0;

    sftp_r->id=get_sftp_request_id(sftp);

    store_uint32(&data[pos], 9 + sftp_r->call.mkdir.len + sftp_r->call.mkdir.size);
    pos+=4;
    data[pos]=(unsigned char) SSH_FXP_MKDIR;
    pos++;
    store_uint32(&data[pos], sftp_r->id);
    pos+=4;
    store_uint32(&data[pos], sftp_r->call.mkdir.len);
    pos+=4;
    memcpy((char *) &data[pos], sftp_r->call.mkdir.path, sftp_r->call.mkdir.len);
    pos+=sftp_r->call.mkdir.len;
    memcpy((char *) &data[pos], sftp_r->call.mkdir.buff, sftp_r->call.mkdir.size);
    pos+=sftp_r->call.mkdir.size;

    return send_channel_data_message(&sftp->channel, pos, data, &sftp_r->reply.sequence);

}

/*
    RMDIR
    - byte 1 	SSH_FXP_RMDIR
    - uint32 	request id
    - uint32 	len path (n)
    - byte[n]	path
*/

int send_sftp_rmdir_v03(struct sftp_subsystem_s *sftp, struct sftp_request_s *sftp_r)
{
    char data[13 + sftp_r->call.remove.len];
    unsigned int pos=0;

    sftp_r->id=get_sftp_request_id(sftp);

    store_uint32(&data[pos], 9 + sftp_r->call.remove.len);
    pos+=4;
    data[pos]=(unsigned char) SSH_FXP_RMDIR;
    pos++;
    store_uint32(&data[pos], sftp_r->id);
    pos+=4;
    store_uint32(&data[pos], sftp_r->call.remove.len);
    pos+=4;
    memcpy((char *) &data[pos], sftp_r->call.remove.path, sftp_r->call.remove.len);
    pos+=sftp_r->call.remove.len;

    return send_channel_data_message(&sftp->channel, pos, data, &sftp_r->reply.sequence);

}

/*
    STAT
    - byte 1 	SSH_FXP_STAT
    - uint32 	request id
    - uint32 	len path (n)
    - byte[n]	path
*/

int send_sftp_stat_v03(struct sftp_subsystem_s *sftp, struct sftp_request_s *sftp_r)
{
    char data[13 + sftp_r->call.stat.len];
    unsigned int pos=0;

    sftp_r->id=get_sftp_request_id(sftp);

    store_uint32(&data[pos], 9 + sftp_r->call.stat.len);
    pos+=4;
    data[pos]=(unsigned char) SSH_FXP_STAT;
    pos++;
    store_uint32(&data[pos], sftp_r->id);
    pos+=4;
    store_uint32(&data[pos], sftp_r->call.stat.len);
    pos+=4;
    memcpy((char *) &data[pos], sftp_r->call.stat.path, sftp_r->call.stat.len);
    pos+=sftp_r->call.stat.len;

    return send_channel_data_message(&sftp->channel, pos, data, &sftp_r->reply.sequence);

}

/*
    LSTAT
    - byte 1 	SSH_FXP_LSTAT
    - uint32 	request id
    - uint32 	len path (n)
    - byte[n]	path
*/

int send_sftp_lstat_v03(struct sftp_subsystem_s *sftp, struct sftp_request_s *sftp_r)
{
    char data[13 + sftp_r->call.lstat.len];
    unsigned int pos=0;

    sftp_r->id=get_sftp_request_id(sftp);

    store_uint32(&data[pos], 9 + sftp_r->call.lstat.len);
    pos+=4;
    data[pos]=(unsigned char) SSH_FXP_LSTAT;
    pos++;
    store_uint32(&data[pos], sftp_r->id);
    pos+=4;
    store_uint32(&data[pos], sftp_r->call.lstat.len);
    pos+=4;
    memcpy((char *) &data[pos], sftp_r->call.lstat.path, sftp_r->call.lstat.len);
    pos+=sftp_r->call.lstat.len;

    return send_channel_data_message(&sftp->channel, pos, data, &sftp_r->reply.sequence);

}

/*
    FSTAT
    - byte 1 	SSH_FXP_FSTAT
    - uint32 	request id
    - uint32 	len handle (n)
    - byte[n]	handle
*/

int send_sftp_fstat_v03(struct sftp_subsystem_s *sftp, struct sftp_request_s *sftp_r)
{
    char data[13 + sftp_r->call.fstat.len];
    unsigned int pos=0;

    sftp_r->id=get_sftp_request_id(sftp);

    store_uint32(&data[pos], 9 + sftp_r->call.fstat.len);
    pos+=4;
    data[pos]=(unsigned char) SSH_FXP_FSTAT;
    pos++;
    store_uint32(&data[pos], sftp_r->id);
    pos+=4;
    store_uint32(&data[pos], sftp_r->call.fstat.len);
    pos+=4;
    memcpy((char *) &data[pos], sftp_r->call.fstat.handle, sftp_r->call.fstat.len);
    pos+=sftp_r->call.fstat.len;

    return send_channel_data_message(&sftp->channel, pos, data, &sftp_r->reply.sequence);

}

/*
    SETSTAT
    - byte 1 	SSH_FXP_SETSTAT
    - uint32 	request id
    - uint32 	len path (n)
    - byte[n]	path
    - attr	attributes

    NOTE:

    here the attributes block is a buffer of size bytes,
    the construction of this block is done by the caller (and depends on the version negotiated)
*/

int send_sftp_setstat_v03(struct sftp_subsystem_s *sftp, struct sftp_request_s *sftp_r)
{
    char data[13 + sftp_r->call.setstat.len + sftp_r->call.setstat.size];
    unsigned int pos=0;

    sftp_r->id=get_sftp_request_id(sftp);

    store_uint32(&data[pos], 9 + sftp_r->call.setstat.len + sftp_r->call.setstat.size);
    pos+=4;
    data[pos]=(unsigned char) SSH_FXP_SETSTAT;
    pos++;
    store_uint32(&data[pos], sftp_r->id);
    pos+=4;
    store_uint32(&data[pos], sftp_r->call.setstat.len);
    pos+=4;
    memcpy((char *) &data[pos], sftp_r->call.setstat.path, sftp_r->call.setstat.len);
    pos+=sftp_r->call.setstat.len;
    memcpy((char *) &data[pos], sftp_r->call.setstat.buff, sftp_r->call.setstat.size);
    pos+=sftp_r->call.setstat.size;

    return send_channel_data_message(&sftp->channel, pos, data, &sftp_r->reply.sequence);

}

/*
    FSETSTAT
    - byte 1 	SSH_FXP_FSETSTAT
    - uint32 	request id
    - uint32 	len handle (n)
    - byte[n]	handle
    - attr	attributes

    NOTE:
    here the attributes block is a buffer of size bytes,
    the construction of this block is done by the caller (and depends on the version negotiated)
*/

int send_sftp_fsetstat_v03(struct sftp_subsystem_s *sftp, struct sftp_request_s *sftp_r)
{
    char data[13 + sftp_r->call.fsetstat.len + sftp_r->call.fsetstat.size];
    unsigned int pos=0;

    sftp_r->id=get_sftp_request_id(sftp);

    store_uint32(&data[pos], 9 + sftp_r->call.fsetstat.len + sftp_r->call.fsetstat.size);
    pos+=4;
    data[pos]=(unsigned char) SSH_FXP_FSETSTAT;
    pos++;
    store_uint32(&data[pos], sftp_r->id);
    pos+=4;
    store_uint32(&data[pos], sftp_r->call.fsetstat.len);
    pos+=4;
    memcpy((char *) &data[pos], sftp_r->call.fsetstat.handle, sftp_r->call.fsetstat.len);
    pos+=sftp_r->call.fsetstat.len;
    memcpy((char *) &data[pos], sftp_r->call.fsetstat.buff, sftp_r->call.fsetstat.size);
    pos+=sftp_r->call.fsetstat.size;

    return send_channel_data_message(&sftp->channel, pos, data, &sftp_r->reply.sequence);

}

/*
    READLINK
    - byte 1 	SSH_FXP_READLINK
    - uint32 	request id
    - uint32 	len path (n)
    - byte[n]	path
*/

int send_sftp_readlink_v03(struct sftp_subsystem_s *sftp, struct sftp_request_s *sftp_r)
{
    char data[13 + sftp_r->call.readlink.len];
    unsigned int pos=0;

    sftp_r->id=get_sftp_request_id(sftp);

    store_uint32(&data[pos], 9 + sftp_r->call.readlink.len);
    pos+=4;
    data[pos]=(unsigned char) SSH_FXP_READLINK;
    pos++;
    store_uint32(&data[pos], sftp_r->id);
    pos+=4;
    store_uint32(&data[pos], sftp_r->call.readlink.len);
    pos+=4;
    memcpy((char *) &data[pos], sftp_r->call.readlink.path, sftp_r->call.readlink.len);
    pos+=sftp_r->call.readlink.len;

    return send_channel_data_message(&sftp->channel, pos, data, &sftp_r->reply.sequence);

}

/*
    SYMLINK
    - byte 1 	SSH_FXP_SYMLINK
    - uint32 	request id
    - uint32 	len path (n)
    - byte[n]	path
    - uint32 	len target path (m)
    - byte[m]	target path
*/

int send_sftp_symlink_v03(struct sftp_subsystem_s *sftp, struct sftp_request_s *sftp_r)
{
    char data[17 + sftp_r->call.link.len + sftp_r->call.link.target_len];
    unsigned int pos=0;

    sftp_r->id=get_sftp_request_id(sftp);

    store_uint32(&data[pos], 13 + sftp_r->call.link.len + sftp_r->call.link.target_len);
    pos+=4;
    data[pos]=(unsigned char) SSH_FXP_SYMLINK;
    pos++;
    store_uint32(&data[pos], sftp_r->id);
    pos+=4;
    store_uint32(&data[pos], sftp_r->call.link.len);
    pos+=4;
    memcpy((char *) &data[pos], sftp_r->call.link.path, sftp_r->call.link.len);
    pos+=sftp_r->call.link.len;
    store_uint32(&data[pos], sftp_r->call.link.target_len);
    pos+=4;
    memcpy((char *) &data[pos], sftp_r->call.link.target_path, sftp_r->call.link.target_len);
    pos+=sftp_r->call.link.target_len;

    return send_channel_data_message(&sftp->channel, pos, data, &sftp_r->reply.sequence);

}

/*
    BLOCK (byte range lock)
    absent
*/


int send_sftp_block_v03(struct sftp_subsystem_s *sftp, struct sftp_request_s *sftp_r)
{
    sftp_r->reply.error=ENOSYS;
    return -1;
}

/*
    UNBLOCK (byte range unlock)
    absent
*/

int send_sftp_unblock_v03(struct sftp_subsystem_s *sftp, struct sftp_request_s *sftp_r)
{
    sftp_r->reply.error=ENOSYS;
    return -1;
}

/*
    REALPATH

    - byte 1		SSH_FXP_REALPATH
    - uint32		request id
    - string		original path
*/

int send_sftp_realpath_v03(struct sftp_subsystem_s *sftp, struct sftp_request_s *sftp_r)
{
    char data[13 + sftp_r->call.realpath.len];
    unsigned int pos=0;

    sftp_r->id=get_sftp_request_id(sftp);

    store_uint32(&data[pos], 9 + sftp_r->call.realpath.len);
    pos+=4;
    data[pos]=(unsigned char) SSH_FXP_REALPATH;
    pos++;
    store_uint32(&data[pos], sftp_r->id);
    pos+=4;
    store_uint32(&data[pos], sftp_r->call.realpath.len);
    pos+=4;
    memcpy((char *) &data[pos], sftp_r->call.realpath.path, sftp_r->call.realpath.len);
    pos+=sftp_r->call.realpath.len;

    return send_channel_data_message(&sftp->channel, pos, data, &sftp_r->reply.sequence);

}

/*
    EXTENSION

    - byte 1		SSH_FXP_EXTENDED
    - uint32		request id
    - string		name extension
    - extension specific data
*/

int send_sftp_extension_v03(struct sftp_subsystem_s *sftp, struct sftp_request_s *sftp_r)
{
    char data[13 + sftp_r->call.extension.len + sftp_r->call.extension.size];
    unsigned int pos=0;

    logoutput_debug("send_sftp_extension_v03: name %.*s", sftp_r->call.extension.len, sftp_r->call.extension.name);

    sftp_r->id=get_sftp_request_id(sftp);

    store_uint32(&data[pos], 9 + sftp_r->call.extension.len + sftp_r->call.extension.size);
    pos+=4;
    data[pos]=(unsigned char) SSH_FXP_EXTENDED;
    pos++;
    store_uint32(&data[pos], sftp_r->id);
    pos+=4;

    store_uint32(&data[pos], sftp_r->call.extension.len);
    pos+=4;
    memcpy((char *) &data[pos], sftp_r->call.extension.name, sftp_r->call.extension.len);
    pos+=sftp_r->call.extension.len;

    memcpy((char *) &data[pos], sftp_r->call.extension.data, sftp_r->call.extension.size);
    pos+=sftp_r->call.extension.size;

    return send_channel_data_message(&sftp->channel, pos, data, &sftp_r->reply.sequence);

}

/*
    CUSTOM

    - byte 1		custom
    - uint32		request id
    - extension specific data
*/

int send_sftp_custom_v03(struct sftp_subsystem_s *sftp, struct sftp_request_s *sftp_r)
{
    char data[9 + sftp_r->call.custom.size];
    unsigned int pos=0;

    logoutput_debug("send_sftp_custom_v03: nr %i", sftp_r->call.custom.nr);

    sftp_r->id=get_sftp_request_id(sftp);

    store_uint32(&data[pos], 9 + sftp_r->call.custom.size);
    pos+=4;
    data[pos]=(unsigned char) sftp_r->call.custom.nr;
    pos++;
    store_uint32(&data[pos], sftp_r->id);
    pos+=4;

    /* data is custom extension specific */

    memcpy((char *) &data[pos], sftp_r->call.custom.data, sftp_r->call.custom.size);
    pos+=sftp_r->call.custom.size;

    return send_channel_data_message(&sftp->channel, pos, data, &sftp_r->reply.sequence);

}

static struct sftp_send_ops_s send_ops_v03 = {
    .version				= 3,
    .init				= send_sftp_init_v03,
    .open				= send_sftp_open_v03,
    .create				= send_sftp_create_v03,
    .read				= send_sftp_read_v03,
    .write				= send_sftp_write_v03,
    .close				= send_sftp_close_v03,
    .stat				= send_sftp_stat_v03,
    .lstat				= send_sftp_lstat_v03,
    .fstat				= send_sftp_fstat_v03,
    .setstat				= send_sftp_setstat_v03,
    .fsetstat				= send_sftp_fsetstat_v03,
    .realpath				= send_sftp_realpath_v03,
    .readlink				= send_sftp_readlink_v03,
    .opendir				= send_sftp_opendir_v03,
    .readdir				= send_sftp_readdir_v03,
    .remove				= send_sftp_remove_v03,
    .rmdir				= send_sftp_rmdir_v03,
    .mkdir				= send_sftp_mkdir_v03,
    .rename				= send_sftp_rename_v03,
    .symlink				= send_sftp_symlink_v03,
    .block				= send_sftp_block_v03,
    .unblock				= send_sftp_unblock_v03,
    .extension				= send_sftp_extension_v03,
    .custom				= send_sftp_custom_v03,
};

void use_sftp_send_v03(struct sftp_subsystem_s *sftp_subsystem)
{
    sftp_subsystem->send_ops=&send_ops_v03;
}
