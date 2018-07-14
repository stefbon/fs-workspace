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

#include "ssh-common-protocol.h"
#include "ssh-common.h"
#include "ssh-utils.h"

#include "sftp-common-protocol.h"
#include "sftp-common.h"
#include "sftp-request-hash.h"

#include "ssh-channel.h"

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

static void process_sftp_error(struct sftp_subsystem_s *sftp_subsystem, struct ssh_payload_s *payload, unsigned int error)
{
    struct sftp_request_s *sftp_r=NULL;
    unsigned int pos=10;
    unsigned int tmp_error=0;
    unsigned int id=0;
    void *req=NULL;

    /* something is wrong with message: try to send a signal to waiting thread */

    id=get_uint32(&payload->buffer[pos]);
    req=get_sftp_request(sftp_subsystem, id, &sftp_r, &tmp_error);

    if (req) {
	struct ssh_signal_s *signal=sftp_subsystem->channel.payload_queue.signal;

	pthread_mutex_lock(signal->mutex);

	signal->sequence_number_error=sftp_r->sequence;
	signal->error=error;

	pthread_cond_broadcast(signal->cond);
	pthread_mutex_lock(signal->mutex);

    }

}

void receive_sftp_reply(struct ssh_channel_s *channel, struct ssh_payload_s **p_payload)
{
    struct sftp_subsystem_s *sftp_subsystem=(struct sftp_subsystem_s *) ( ((char *) channel) - offsetof(struct sftp_subsystem_s, channel));
    struct sftp_header_s sftp_header;
    struct ssh_payload_s *payload=*p_payload;
    unsigned int pos=9;
    unsigned int len=0;

    logoutput("receive_sftp_reply");

    len=get_uint32(&payload->buffer[pos]);

    /*
	SFTP has the form
	- uint32		length minus this field
	- byte			type
	- uint32		request id
	- type specific data
    */

    /*
	length of sftp data plus 4 is equal to the length of the payload
    */

    if (13 + len != payload->len) {

	logoutput("receive_sftp_reply: sftp size %i not equal to length %i", 13 + len, payload->len);
	process_sftp_error(sftp_subsystem, payload, EPROTO);
	free_payload(p_payload);
	return;

    }

    pos+=4;

    sftp_header.len=len;
    sftp_header.type=(unsigned char) payload->buffer[pos];
    sftp_header.id=0;
    sftp_header.sequence=payload->sequence;
    sftp_header.buffer=NULL;
    pos++;
    sftp_header.len--;

    logoutput("receive_sftp_reply: type %i", sftp_header.type);

    switch (sftp_header.type) {

	case SSH_FXP_STATUS: {

	    sftp_header.id=get_uint32(&payload->buffer[pos]);
	    pos+=4;
	    sftp_header.len-=4;

	    sftp_header.buffer=isolate_payload_buffer(p_payload, pos, sftp_header.len);

	    (* sftp_subsystem->recv_ops->status)(sftp_subsystem, &sftp_header);

	    if (sftp_header.buffer) free(sftp_header.buffer);
	    }

	    break;

	case SSH_FXP_HANDLE: {

	    sftp_header.id=get_uint32(&payload->buffer[pos]);
	    pos+=4;
	    sftp_header.len-=4;

	    sftp_header.buffer=isolate_payload_buffer(p_payload, pos, sftp_header.len);

	    (* sftp_subsystem->recv_ops->handle)(sftp_subsystem, &sftp_header);

	    if (sftp_header.buffer) free(sftp_header.buffer);
	    }

	    break;

	case SSH_FXP_DATA: {

	    sftp_header.id=get_uint32(&payload->buffer[pos]);
	    pos+=4;
	    sftp_header.len-=4;

	    sftp_header.buffer=isolate_payload_buffer(p_payload, pos, sftp_header.len);

	    (* sftp_subsystem->recv_ops->data)(sftp_subsystem, &sftp_header);

	    if (sftp_header.buffer) free(sftp_header.buffer);
	    }

	    break;

	case SSH_FXP_NAME: {

	    sftp_header.id=get_uint32(&payload->buffer[pos]);
	    pos+=4;
	    sftp_header.len-=4;

	    sftp_header.buffer=isolate_payload_buffer(p_payload, pos, sftp_header.len);

	    (* sftp_subsystem->recv_ops->name)(sftp_subsystem, &sftp_header);

	    if (sftp_header.buffer) free(sftp_header.buffer);
	    }

	    break;

	case SSH_FXP_ATTRS: {

	    sftp_header.id=get_uint32(&payload->buffer[pos]);
	    pos+=4;
	    sftp_header.len-=4;

	    sftp_header.buffer=isolate_payload_buffer(p_payload, pos, sftp_header.len);

	    (* sftp_subsystem->recv_ops->attr)(sftp_subsystem, &sftp_header);

	    if (sftp_header.buffer) free(sftp_header.buffer);
	    payload=NULL;
	    }

	    break;

	case SSH_FXP_EXTENDED: {

	    sftp_header.id=get_uint32(&payload->buffer[pos]);
	    pos+=4;
	    sftp_header.len-=4;

	    sftp_header.buffer=isolate_payload_buffer(p_payload, pos, sftp_header.len);

	    (* sftp_subsystem->recv_ops->extension)(sftp_subsystem, &sftp_header);

	    if (sftp_header.buffer) free(sftp_header.buffer);
	    }

	    break;

	case SSH_FXP_EXTENDED_REPLY: {

	    sftp_header.id=get_uint32(&payload->buffer[pos]);
	    pos+=4;
	    sftp_header.len-=4;

	    sftp_header.buffer=isolate_payload_buffer(p_payload, pos, sftp_header.len);

	    (* sftp_subsystem->recv_ops->extension_reply)(sftp_subsystem, &sftp_header);

	    if (sftp_header.buffer) free(sftp_header.buffer);
	    }

	    break;

	default:

	    logoutput("receive_sftp_reply: error sftp type %i not reckognized", sftp_header.type);

    }

    if (*p_payload) free_payload(p_payload);


}

void receive_sftp_eof(struct ssh_channel_s *channel)
{
}
