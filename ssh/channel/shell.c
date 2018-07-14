/*
  2017, 2018 Stef Bon <stefbon@gmail.com>

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

int start_remote_shell(struct ssh_channel_s *channel, unsigned int *error)
{
    unsigned int seq=0;
    int result=-1;

    if (!(channel->flags & CHANNEL_FLAG_OPEN) || channel->flags & CHANNEL_FLAG_NODATA || channel->flags & CHANNEL_FLAG_OPENFAILURE) {

	*error=EIO;
	return -1;

    } else if (!(channel->type==_CHANNEL_TYPE_SHELL)) {

	*error=EINVAL;
	return -1;

    }

    /* start the remote shell on the channel */

    logoutput("start_remote_shell");

    if (send_start_command_message(channel, "shell", NULL, 1, &seq)==0) {
	struct timespec expire;
	struct ssh_payload_s *payload=NULL;

	get_channel_expire_init(channel, &expire);

	payload=get_ssh_payload_channel(channel, &expire, &seq, error);

	if (! payload) {

	    logoutput("start_remote_shell: error %i waiting for packet (%s)", *error, strerror(*error));
	    return -1;

	}

	if (payload->type==SSH_MSG_CHANNEL_SUCCESS) {

	    /* ready: channel ready to use */

	    logoutput("start_remote_shell: server started shell");
	    result=0;

	} else if (payload->type==SSH_MSG_CHANNEL_FAILURE) {

	    logoutput("start_remote_shell: server failed to start shell");

	} else {

	    logoutput("start_remote_shell: got unexpected reply %i", payload->type);

	}

	free_payload(&payload);

    } else {

	logoutput("start_remote_shell: error sending shell request");

    }

    if (result==0) {
	struct timespec expire;
	struct ssh_payload_s *payload=NULL;

	/* process any message from server like banners */

	get_current_time(&expire);
	expire.tv_sec+=1;

	processdatashell:

	payload=get_ssh_payload_channel(channel, &expire, NULL, error);

	if (payload) {

	    if (payload->type==SSH_MSG_CHANNEL_DATA) {
		unsigned int len=get_uint32(&payload->buffer[5]);
		char buffer[len+1];

		memcpy(buffer, &payload->buffer[9], len);
		buffer[len]='\0';

		replace_cntrl_char(buffer, len);
		// replace_newline_char(buffer, &len);

		logoutput("start_remote_shell: received %s", buffer);

	    } else {

		logoutput("start_remote_shell: got unexpected reply %i", payload->type);

	    }

	    free(payload);
	    payload=NULL;

	    goto processdatashell;

	}

    }

    return result;

}

unsigned int start_remote_command_shell(struct ssh_channel_s *channel, char *command, struct server_reply_s *server_reply, struct timespec *send, struct timespec *received)
{
    unsigned int len=strlen(command);
    unsigned int seq=0;
    char buffer[len+2];

    if (!(channel->flags & CHANNEL_FLAG_OPEN) || channel->flags & CHANNEL_FLAG_NODATA || channel->flags & CHANNEL_FLAG_OPENFAILURE) {

	server_reply->error=EIO;
	return 0;

    } else if (!(channel->type==_CHANNEL_TYPE_SHELL)) {

	server_reply->error=EINVAL;
	return 0;

    }

    memcpy(buffer, command, len);

    /* add CRLF to command (CR=ascii 13 LF=ascii 10) */

    buffer[len]=13;
    buffer[len+1]=10;

    if (send) get_current_time(send);

    if (send_channel_data_message(channel, len+2, buffer, &seq)==0) {
	struct ssh_payload_s *payload=NULL;
	struct timespec expire;

	/* wait for output from command */

	get_channel_expire_init(channel, &expire);

	getpayload:

	payload=get_ssh_payload_channel(channel, &expire, &seq, &server_reply->error);

	if (! payload) {

	    logoutput("start_remote_command_shell: error %i waiting for packet (%s)", server_reply->error, strerror(server_reply->error));
	    return 0;

	}

	if (received) get_current_time(received);

	if (payload->type==SSH_MSG_CHANNEL_DATA) {

	    server_reply->reply=SSH_MSG_CHANNEL_DATA;
	    server_reply->response.data.size=get_uint32(&payload->buffer[5]);

	    if (server_reply->response.data.size>0) {

		//replace_cntrl_char((char *) &payload->buffer[9], server_reply->response.data.size);
		replace_newline_char((char *) &payload->buffer[9], &server_reply->response.data.size);

		server_reply->response.data.ptr=malloc(server_reply->response.data.size);

		if (server_reply->response.data.ptr) {

		    memcpy(server_reply->response.data.ptr, &payload->buffer[9], server_reply->response.data.size);

		} else {

		    server_reply->response.data.size=0;
		    server_reply->error=ENOMEM;

		}

	    }

	} else if (payload->type==SSH_MSG_CHANNEL_EXTENDED_DATA) {
	    unsigned int code=get_uint32(&payload->buffer[5]);

	    server_reply->reply=SSH_MSG_CHANNEL_EXTENDED_DATA;

	    if (code==SSH_EXTENDED_DATA_STDERR) {
		unsigned int size=0;

		logoutput("start_remote_command_shell: error output from command %s", command);

		size=get_uint32(&payload->buffer[9]);

		if (size>0) {
		    char errorstring[size+1];

		    memcpy(errorstring, (char *) &payload->buffer[13], size);
		    replace_cntrl_char(errorstring, size);
		    errorstring[size]='\0';

		    logoutput("start_remote_command_shell: error %s", errorstring);

		    free(payload);
		    payload=NULL;

		    goto getpayload;

		}

	    } else {

		logoutput("start_remote_command_shell: unknown code %i", code);
		server_reply->error=EIO;

	    }

	} else {

	    logoutput("start_remote_command_shell: received unknown reply %i", payload->type);
	    server_reply->error=EIO;

	}

	free_payload(&payload);

    } else {

	logoutput("start_remote_command_shell: error sending comman %s", command);
	server_reply->error=EIO;

    }

    return server_reply->response.data.size;

}

void add_shell_channel(struct ssh_session_s *session)
{
    struct ssh_channel_s *channel=NULL;
    struct channel_table_s *table=&session->channel_table;
    unsigned int error=0;

    logoutput("add_shell_channel");

    channel=create_channel(session, _CHANNEL_TYPE_SHELL);

    if (! channel) {

	logoutput("add_shell_channel: unable to create shell channel");
	return;

    }

    if (add_channel(channel, CHANNEL_FLAG_OPEN)==-1) {

	free(channel);
	channel=NULL;
	return;

    }

    /* start a shell on the channel */

    if (start_remote_shell(channel, &error)==0) {

	logoutput("add_shell_channel: started remote shell");
	table->shell=channel;

    } else {

	remove_channel(channel, CHANNEL_FLAG_CLIENT_CLOSE | CHANNEL_FLAG_SERVER_CLOSE);
	(* channel->free)(channel);
	channel=NULL;

    }

}

