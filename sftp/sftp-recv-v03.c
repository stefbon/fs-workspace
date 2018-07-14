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
#include "sftp-protocol-v03.h"

static struct ssh_string_s ext_fsnotify={0, strlen(SFTP_EXTENSION_FSNOTIFY_BONONLINE_NL), SFTP_EXTENSION_FSNOTIFY_BONONLINE_NL};

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

static unsigned int linux_error_map[] = {
    [SSH_FX_OK]				= 0,
    [SSH_FX_EOF]			= ENODATA,
    [SSH_FX_NO_SUCH_FILE]		= ENOENT,
    [SSH_FX_PERMISSION_DENIED]  	= EPERM,
    [SSH_FX_FAILURE]			= EIO,
    [SSH_FX_BAD_MESSAGE]		= EBADMSG,
    [SSH_FX_NO_CONNECTION]		= ENOTCONN,
    [SSH_FX_CONNECTION_LOST]		= ESHUTDOWN,
    [SSH_FX_OP_UNSUPPORTED]		= EOPNOTSUPP};


static unsigned int map_sftp_error(unsigned int ssh_fx_error)
{

    if (ssh_fx_error < (sizeof(linux_error_map)/sizeof(linux_error_map[0]))) {

	return linux_error_map[ssh_fx_error];

    }

    return EIO;

}


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

void receive_sftp_status_v03(struct sftp_subsystem_s *sftp_subsystem, struct sftp_header_s *sftp_header)
{
    unsigned int error=0;
    struct sftp_request_s *sftp_r=NULL;
    unsigned int pos=0;
    void *req=NULL;

    req=get_sftp_request(sftp_subsystem, sftp_header->id, &sftp_r, &error);

    if (req) {
	char *buffer=sftp_header->buffer;

	sftp_r->type=sftp_header->type;
	sftp_r->response.status.code=get_uint32(&buffer[pos]);
	sftp_r->response.status.linux_error=map_sftp_error(sftp_r->response.status.code);

	signal_sftp_received_id(sftp_subsystem, req);

    } else {

	logoutput("receive_sftp_status: error %i storing status (%s)", error, strerror(error));

    }

}

void receive_sftp_handle_v03(struct sftp_subsystem_s *sftp_subsystem, struct sftp_header_s *sftp_header)
{
    unsigned int error=0;
    struct sftp_request_s *sftp_r=NULL;
    unsigned int pos=0;
    void *req=NULL;

    req=get_sftp_request(sftp_subsystem, sftp_header->id, &sftp_r, &error);

    if (req) {
	char *buffer=sftp_header->buffer;

	sftp_r->type=sftp_header->type;
	sftp_r->response.handle.len=get_uint32(&buffer[pos]);
	pos+=4;

	/* TODO: check the length is not bigger than buffer */

	if (sftp_r->response.handle.len < 256) {

	    memmove(buffer, &buffer[pos], sftp_r->response.handle.len);
	    buffer=realloc(buffer, sftp_r->response.handle.len);

	    sftp_r->response.handle.name=buffer;
	    if (sftp_r->response.handle.name==NULL) sftp_r->error=ENOMEM;

	    sftp_header->buffer=NULL;

	} else {

	    sftp_r->error=EPROTO;
	    logoutput("receive_sftp_handle: error received handle len %i too long", sftp_r->response.handle.len);

	}

	signal_sftp_received_id(sftp_subsystem, req);

    }

}

void receive_sftp_data_v03(struct sftp_subsystem_s *sftp_subsystem, struct sftp_header_s *sftp_header)
{
    unsigned int error=0;
    struct sftp_request_s *sftp_r=NULL;
    unsigned int pos=0;
    void *req=NULL;

    req=get_sftp_request(sftp_subsystem, sftp_header->id, &sftp_r, &error);

    if (req) {
	char *buffer=sftp_header->buffer;

	sftp_r->type=sftp_header->type;
	sftp_r->response.data.size=get_uint32(&buffer[pos]);
	pos+=4;

	memmove(buffer, &buffer[pos], sftp_r->response.data.size);
	buffer=realloc(buffer, sftp_r->response.data.size);

	logoutput("receive_sftp_data: received %i bytes len %i", sftp_r->response.data.size, sftp_header->len);

	/* let the processing of this into names, attr to the receiving (FUSE) thread */
	sftp_r->response.data.data=buffer;
	sftp_r->response.data.eof=-1;

	sftp_header->buffer=NULL;

	signal_sftp_received_id(sftp_subsystem, req);

    } else {

	logoutput("receive_sftp_data: error %i storing data (%s)", error, strerror(error));

    }

}

void receive_sftp_name_v03(struct sftp_subsystem_s *sftp_subsystem, struct sftp_header_s *sftp_header)
{
    unsigned int error=0;
    struct sftp_request_s *sftp_r=NULL;
    unsigned int pos=0;
    void *req=NULL;

    req=get_sftp_request(sftp_subsystem, sftp_header->id, &sftp_r, &error);

    if (req) {
	char *buffer=sftp_header->buffer;

	sftp_r->type=sftp_header->type;
	sftp_r->response.names.left=get_uint32(&buffer[pos]);
	pos+=4;
	sftp_r->response.names.size=sftp_header->len - pos; /* minus the count field */

	memmove(buffer, &buffer[pos], sftp_r->response.names.size);
	buffer=realloc(buffer, sftp_r->response.names.size);

	/* let the processing of this into names, attr to the receiving (FUSE) thread */
	sftp_r->response.names.buff=buffer;
	sftp_r->response.names.eof=-1;
	sftp_header->buffer=NULL;

	if (sftp_r->response.names.buff==NULL) sftp_r->error=ENOMEM;

	sftp_r->response.names.pos=sftp_r->response.names.buff;

	signal_sftp_received_id(sftp_subsystem, req);

    } else {

	logoutput("receive_sftp_name: error %i storing data (%s)", error, strerror(error));

    }

}

void receive_sftp_attr_v03(struct sftp_subsystem_s *sftp_subsystem, struct sftp_header_s *sftp_header)
{
    unsigned int error=0;
    struct sftp_request_s *sftp_r=NULL;
    unsigned int pos=0;
    void *req=NULL;

    req=get_sftp_request(sftp_subsystem, sftp_header->id, &sftp_r, &error);

    if (req) {
	char *buffer=sftp_header->buffer;

	sftp_r->type=sftp_header->type;
	sftp_r->response.attr.size=sftp_header->len;
	sftp_r->response.attr.buff=buffer;
	sftp_header->buffer=NULL;

	signal_sftp_received_id(sftp_subsystem, req);

    } else {

	logoutput("receive_sftp_attr: error %i storing data for id %i (%s)", error, sftp_header->id, strerror(error));

    }

}

void receive_sftp_extension_v03(struct sftp_subsystem_s *sftp, struct sftp_header_s *sftp_header)
{
    char *buffer=sftp_header->buffer;
    unsigned int len=get_uint32(buffer);
    unsigned int pos=4;

    if (len==ext_fsnotify.len && memcmp(&buffer[pos], ext_fsnotify.ptr, len)==0) {
	uint64_t unique=0;
	uint32_t mask=0;
	struct ssh_string_s who;
	struct ssh_string_s host;
	struct ssh_string_s file;
	unsigned int pos=0;

	/* format:
	- uint64_t		unique
	- uint32_t		mask
	- string		who
	- string		host
	- string		file
	*/

	who.ptr=NULL;
	who.len=0;
	host.ptr=NULL;
	host.len=0;
	file.ptr=NULL;
	file.len=0;

	unique=get_uint64(&buffer[pos]);
	pos+=8;
	mask=get_uint32(&buffer[pos]);
	pos+=4;
	who.len=get_uint32(&buffer[pos]);
	pos+=4;

	if (who.len>0) {
	    who.ptr=&buffer[pos];
	    pos+=who.len;
	}

	host.len=get_uint32(&buffer[pos]);
	pos+=4;

	if (host.len>0) {
	    host.ptr=&buffer[pos];
	    pos+=host.len;
	}

	file.len=get_uint32(&buffer[pos]);
	pos+=4;

	if (file.len>0) {
	    file.ptr=&buffer[pos];
	    pos+=file.len;
	}

	sftp_fsnotify_event(sftp, unique, mask, &who, &host, &file);

    }

}

void receive_sftp_extension_reply_v03(struct sftp_subsystem_s *sftp_subsystem, struct sftp_header_s *sftp_header)
{
    unsigned int error=0;
    struct sftp_request_s *sftp_r=NULL;
    unsigned int pos=0;
    void *req=NULL;

    req=get_sftp_request(sftp_subsystem, sftp_header->id, &sftp_r, &error);

    if (req) {
	char *buffer=sftp_header->buffer;

	sftp_r->type=sftp_header->type;
	sftp_r->response.extension.size=sftp_header->len;
	sftp_r->response.extension.buff=buffer;

	sftp_header->buffer=NULL;

	signal_sftp_received_id(sftp_subsystem, req);

    } else {

	logoutput("receive_sftp_extension_reply: error %i storing data for id %i (%s)", error, sftp_header->id, strerror(error));

    }

}

static struct sftp_recv_ops_s recv_ops_v03 = {
    .status				= receive_sftp_status_v03,
    .handle				= receive_sftp_handle_v03,
    .data				= receive_sftp_data_v03,
    .name				= receive_sftp_name_v03,
    .attr				= receive_sftp_attr_v03,
    .extension				= receive_sftp_extension_v03,
    .extension_reply			= receive_sftp_extension_reply_v03,
};

void use_sftp_recv_v03(struct sftp_subsystem_s *sftp_subsystem)
{
    sftp_subsystem->recv_ops=&recv_ops_v03;
}
