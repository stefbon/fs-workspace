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

#include "workspace-interface.h"
#include "ssh-common.h"
#include "ssh-common-protocol.h"
#include "ssh-utils.h"

#include "ssh-channel.h"

#include "sftp-common-protocol.h"
#include "sftp-common.h"
#include "sftp-request-hash.h"

#include "sftp-recv-v03.h"
#include "sftp-recv-v04.h"
#include "sftp-recv-v05.h"
#include "sftp-protocol-v06.h"

static unsigned int linux_error_map[] = {
    [SSH_FX_OK]				= 0,
    [SSH_FX_EOF]			= ENODATA,
    [SSH_FX_NO_SUCH_FILE]		= ENOENT,
    [SSH_FX_PERMISSION_DENIED]  	= EPERM,
    [SSH_FX_FAILURE]			= EIO,
    [SSH_FX_BAD_MESSAGE]		= EBADMSG,
    [SSH_FX_NO_CONNECTION]		= ENOTCONN,
    [SSH_FX_CONNECTION_LOST]		= ESHUTDOWN,
    [SSH_FX_OP_UNSUPPORTED]		= EOPNOTSUPP,
    [SSH_FX_INVALID_HANDLE]		= EINVAL,
    [SSH_FX_NO_SUCH_PATH]		= ENOENT,
    [SSH_FX_FILE_ALREADY_EXISTS]	= EEXIST,
    [SSH_FX_WRITE_PROTECT]		= EACCES,
    [SSH_FX_NO_MEDIA]			= ENODEV,
    [SSH_FX_NO_SPACE_ON_FILESYSTEM]	= ENOSPC,
    [SSH_FX_QUOTA_EXCEEDED]		= EDQUOT,
    [SSH_FX_UNKNOWN_PRINCIPAL]		= EIO,
    [SSH_FX_LOCK_CONFLICT]		= EWOULDBLOCK,
    [SSH_FX_DIR_NOT_EMPTY]		= ENOTEMPTY,
    [SSH_FX_NOT_A_DIRECTORY]		= ENOTDIR,
    [SSH_FX_INVALID_FILENAME]		= EINVAL,
    [SSH_FX_LINK_LOOP]			= ELOOP,
    [SSH_FX_CANNOT_DELETE]		= EPERM,
    [SSH_FX_INVALID_PARAMETER]		= EINVAL,
    [SSH_FX_FILE_IS_A_DIRECTORY]	= EISDIR,
    [SSH_FX_BYTE_RANGE_LOCK_CONFLICT]	= EPERM,
    [SSH_FX_BYTE_RANGE_LOCK_REFUSED]	= EPERM,
    [SSH_FX_DELETE_PENDING]		= EINPROGRESS,
    [SSH_FX_FILE_CORRUPT]		= EIO,
    [SSH_FX_OWNER_INVALID]		= EINVAL,
    [SSH_FX_GROUP_INVALID]		= EINVAL,
    [SSH_FX_NO_MATCHING_BYTE_RANGE_LOCK]= ENOLCK};

static unsigned int map_sftp_error(unsigned int ssh_fx_error)
{

    if (ssh_fx_error < (sizeof(linux_error_map)/sizeof(linux_error_map[0]))) {

	return linux_error_map[ssh_fx_error];

    }

    return EIO;

}

/*
    SFTP callbacks
    sftp is encapsulated in SSH_MSG_CHANNEL_DATA
    so these functions are called when receiving am message of above type

    format for sftp data (except SSH_FXP_VERSION) :

    - uint32			length minus length field self 
    - byte			type
    - uint32			request-id
    - ... type specific fields ...

    (see: draft-ietf-secsh-filexfer 4. General Packet Format)

    when receiving the SSH_MSG_CHANNEL_DATA, the lenght and the type fields are already read
    and set in the sftp_header
    the buffer is the rest

*/

/*
    functions to handle "normal" replies from sftp

    there are only 5 different replies:
    - status
    - handle
    - data
    - name
    - attr

    the common values for these replies like:

    - byte	type
    - uint32	request id

    are stored in sftp_header

    the rest is in buffer
*/

void receive_sftp_status_v06(struct sftp_subsystem_s *sftp_subsystem, struct sftp_header_s *sftp_header)
{
    unsigned int error=0;
    struct sftp_request_s *sftp_r=NULL;
    unsigned int pos=0;
    void *req=NULL;

    req=get_sftp_request(sftp_subsystem, sftp_header->id, &sftp_r, &error);

    if (req) {
	char *buffer=sftp_header->buffer;
	unsigned int len=0;

	sftp_r->type=sftp_header->type;
	sftp_r->response.status.code=get_uint32(&buffer[pos]);
	sftp_r->response.status.linux_error=map_sftp_error(sftp_r->response.status.code);

	pos+=4;
	len=get_uint32(&buffer[pos]);
	pos+=4;

	if (len>0) {
	    char errormessage[len+1];

	    memcpy(errormessage, &buffer[pos], len);
	    errormessage[len]='\0';
	    pos+=len;

	    logoutput_notice("receive_sftp_status_v06: error %i:%s", sftp_r->response.status.code, errormessage);

	} else {

	    logoutput_notice("receive_sftp_status_v06: error %i", sftp_r->response.status.code);

	}

	/* language tag for error message */

	len=get_uint32(&buffer[pos]);
	pos+=4+len;

	/* error specific data */

	if (pos<sftp_header->len) {

	    sftp_r->response.status.buff=malloc(sftp_header->len - pos);

	    if (sftp_r->response.status.buff) {

		memcpy(sftp_r->response.status.buff, &buffer[pos], sftp_header->len - pos);
		sftp_r->response.status.size=sftp_header->len - pos;

	    }

	}

	signal_sftp_received_id(sftp_subsystem, req);

    } else {

	logoutput("receive_sftp_status_v06: error %i storing status (%s)", error, strerror(error));

    }

}

void receive_sftp_data_v06(struct sftp_subsystem_s *sftp_subsystem, struct sftp_header_s *sftp_header)
{
    unsigned int error=0;
    struct sftp_request_s *sftp_r=NULL;
    unsigned int pos=0;
    void *req=NULL;
    char *buffer=sftp_header->buffer;

    req=get_sftp_request(sftp_subsystem, sftp_header->id, &sftp_r, &error);
    if (req==NULL) return;

    sftp_r->type=sftp_header->type;
    sftp_r->response.data.size=get_uint32(&buffer[pos]);
    pos+=4;
    sftp_r->response.data.eof=-1;

    /* there is an extra byte for eol */

    if (sftp_r->response.data.size + pos + 1 == sftp_header->len) sftp_r->response.data.eof=(unsigned char) buffer[sftp_r->response.data.size + pos];

    logoutput("receive_sftp_data_v06: received %i bytes len %i", sftp_r->response.data.size, sftp_header->len);

    memmove(buffer, &buffer[pos], sftp_r->response.data.size);
    buffer=realloc(buffer, sftp_r->response.data.size);

    /* let the processing of this into names, attr to the receiving (FUSE) thread */
    sftp_r->response.data.data=buffer;
    sftp_header->buffer=NULL;

    if (sftp_r->response.data.data==NULL) sftp_r->error=ENOMEM;

    signal_sftp_received_id(sftp_subsystem, req);

}

static struct sftp_recv_ops_s recv_ops_v06 = {
    .status				= receive_sftp_status_v06,
    .handle				= receive_sftp_handle_v03,
    .data				= receive_sftp_data_v06,
    .name				= receive_sftp_name_v03,
    .attr				= receive_sftp_attr_v03,
    .extension				= receive_sftp_extension_v03,
    .extension_reply			= receive_sftp_extension_reply_v03,
};

void use_sftp_recv_v06(struct sftp_subsystem_s *sftp_subsystem)
{
    sftp_subsystem->recv_ops=&recv_ops_v06;
}
