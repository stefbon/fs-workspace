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
#include "common-utils/utils.h"

#include "ssh-common-protocol.h"
#include "ssh-common.h"
#include "ssh-channel.h"
#include "ssh-utils.h"
#include "ssh-send.h"

static unsigned int run_remote_command_exec(struct ssh_channel_s *channel, char *command, struct server_reply_s *server_reply, struct timespec *send, struct timespec *received)
{
    unsigned int seq=0;

    if (!(channel->flags & CHANNEL_FLAG_OPEN) || channel->flags & CHANNEL_FLAG_NODATA || channel->flags & CHANNEL_FLAG_OPENFAILURE) {

	server_reply->error=EIO;
	return 0;

    } else if (!(channel->type==_CHANNEL_TYPE_EXEC)) {

	server_reply->error=EINVAL;
	return 0;

    }

    if (send) get_current_time(send);

    if (send_start_command_message(channel, "exec", command, 0, &seq)==0) {
	struct timespec expire;
	struct ssh_payload_s *payload=NULL;

	logoutput("start_remote_command_exec: send command %s", command);

	get_channel_expire_init(channel, &expire);

	getexecreply:

	payload=get_ssh_payload_channel(channel, &expire, &seq, &server_reply->error);

	if (! payload) {

	    if (server_reply->error==0) server_reply->error=EIO;
	    logoutput("start_remote_command_exec: error %i waiting for packet (%s)", server_reply->error, strerror(server_reply->error));
	    return 0;

	}

	if (received) get_current_time(received);

	if (payload->type==SSH_MSG_CHANNEL_FAILURE) {

	    logoutput("send_remote_command_exec: server failed to execute %s", command);

	} else if (payload->type==SSH_MSG_CHANNEL_DATA) {

	    server_reply->reply=SSH_MSG_CHANNEL_DATA;
	    server_reply->error=EPROTO;

	    if (payload->len>9) {

    		server_reply->response.data.size=get_uint32(&payload->buffer[5]);

		if (server_reply->response.data.size>0) {

		    server_reply->response.data.ptr=isolate_payload_buffer(&payload, 9, server_reply->response.data.size);

		    if (server_reply->response.data.ptr) {

			//replace_cntrl_char(server_reply->response.data.ptr, server_reply->response.data.size, REPLACE_CNTRL_FLAG_BINARY);
			replace_newline_char(server_reply->response.data.ptr, server_reply->response.data.size);
			server_reply->error=0;

		    } else {

			server_reply->response.data.size=0;
			server_reply->error=ENOMEM;

		    }

		}

	    }

	} else if (payload->type==SSH_MSG_CHANNEL_EXTENDED_DATA) {

	    server_reply->reply=SSH_MSG_CHANNEL_EXTENDED_DATA;
	    server_reply->error=EPROTO;

	    if (payload->len>13) {
		unsigned int code=get_uint32(&payload->buffer[5]);

		if (code==SSH_EXTENDED_DATA_STDERR) {

		    server_reply->response.data.size=get_uint32(&payload->buffer[9]);

		    if (server_reply->response.data.size>0) {

			if (server_reply->response.data.size>256) server_reply->response.data.size=256;

			server_reply->response.data.ptr=isolate_payload_buffer(&payload, 13, server_reply->response.data.size);

			if (server_reply->response.data.ptr) {

			    replace_cntrl_char(server_reply->response.data.ptr, server_reply->response.data.size, REPLACE_CNTRL_FLAG_TEXT);
			    // replace_newline_char(server_reply->response.data.ptr, &server_reply->response.data.size);
			    server_reply->error=0;

			} else {

			    server_reply->response.data.size=0;
			    server_reply->error=ENOMEM;

			}

		    }

		}

	    }

	} else if (payload->type==SSH_MSG_CHANNEL_CLOSE) {

	    channel->flags|=CHANNEL_FLAG_SERVER_CLOSE;

	} else {

	    logoutput("send_remote_command_exec: received unknown reply %i", payload->type);

	}

	free_payload(&payload);
	if (!(channel->flags & CHANNEL_FLAG_CLIENT_CLOSE))
	    (* channel->close)(channel, CHANNEL_FLAG_CLIENT_CLOSE);

    } else {

	logoutput("send_remote_command_exec: error sending message");
	return 0;

    }

    return server_reply->response.data.size;

}

/*
    run a command on the remote server
    a new channel is created 
    the exec request is send
    output is received (also in case of error)
    channel is closed and removed
*/

unsigned int start_remote_command_exec(struct ssh_session_s *session, char *command, struct server_reply_s *server_reply, struct timespec *send, struct timespec *received)
{
    struct ssh_channel_s *channel=NULL;
    struct channel_table_s *table=&session->channel_table;
    unsigned int size=0;

    channel=create_channel(session, session->connections.main, _CHANNEL_TYPE_EXEC);
    if (channel==NULL) return 0;

    if (add_channel(channel, CHANNEL_FLAG_OPEN)==0) {

	size=run_remote_command_exec(channel, command, server_reply, send, received);
	remove_channel(channel, CHANNEL_FLAG_CLIENT_CLOSE | CHANNEL_FLAG_SERVER_CLOSE);

    } else {

	logoutput("start_remote_command_exec: unable to add/start channel");

    }

    (* channel->free)(channel);
    channel=NULL;

    return size;

}

