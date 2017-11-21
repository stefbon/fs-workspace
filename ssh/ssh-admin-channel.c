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

#include "ssh-common-protocol.h"
#include "ssh-common.h"
#include "ssh-hostinfo.h"
#include "ssh-connection.h"
#include "ssh-common-list.h"
#include "ssh-channel.h"
#include "ssh-admin-channel.h"
#include "ssh-channel-utils.h"

#include "ssh-send-channel.h"
#include "ssh-receive-channel.h"
#include "ssh-utils.h"

static void get_admin_channel_expire_init(struct ssh_channel_s *channel, struct timespec *expire)
{
    get_current_time(expire);
    expire->tv_sec+=5;

}

/*
    send an exec command
    store reply in server_reply
    when defined register send and receive times
    send channel close when finished
    wait for channel close from server (with timeout)
*/

static unsigned int send_command(struct ssh_channel_s *channel, char *command, struct server_reply_s *server_reply, struct timespec *send, struct timespec *received)
{
    unsigned int seq=0;

    if (send) get_current_time(send);

    if (send_start_command_message(channel, "exec", command, 0, &seq)==0) {
	struct timespec expire;
	struct ssh_payload_s *payload=NULL;

	logoutput("send_command: send command %s", command);

	get_channel_expire_init(channel, &expire);

	getexecreply:

	payload=get_ssh_payload_channel(channel, &expire, &seq, &server_reply->error);

	if (! payload) {

	    if (server_reply->error==0) server_reply->error=EIO;
	    logoutput("send_command: error %i waiting for packet (%s)", server_reply->error, strerror(server_reply->error));
	    return 0;

	}

	if (payload->type==SSH_MSG_CHANNEL_FAILURE) {

	    logoutput("send_command: server failed to execute %s", command);
	    free(payload);
	    return 0;

	} else if (payload->type==SSH_MSG_CHANNEL_DATA) {

	    if (received) get_current_time(received);

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

	    if (received) get_current_time(received);

	    server_reply->reply=SSH_MSG_CHANNEL_EXTENDED_DATA;

	    if (code==SSH_EXTENDED_DATA_STDERR) {

		server_reply->response.data.size=get_uint32(&payload->buffer[9]);

		if (server_reply->response.data.size>0) {

		    replace_cntrl_char((char *) &payload->buffer[13], server_reply->response.data.size);
		    // replace_newline_char((char *) &payload->buffer[13], &server_reply->response.data.size);

		    if (server_reply->response.data.size>256) server_reply->response.data.size=256;
		    server_reply->response.data.ptr=malloc(server_reply->response.data.size);

		    if (server_reply->response.data.ptr) {

			memcpy(server_reply->response.data.ptr, &payload->buffer[13], server_reply->response.data.size);

		    } else {

			server_reply->response.data.size=0;
			server_reply->error=ENOMEM;

		    }

		}

	    } else {

		logoutput("send_command: unknown code %i", code);
		server_reply->error=EIO;

	    }

	} else if (payload->type==SSH_MSG_CHANNEL_CLOSE) {

	    channel->substatus|=CHANNEL_SUBSTATUS_S_CLOSE;

	} else {

	    logoutput("send_command: received unknown reply %i", payload->type);

	}

	free(payload);

	if (!(channel->substatus & CHANNEL_SUBSTATUS_C_CLOSE)) {

	    send_channel_close_message(channel);
	    channel->substatus|=CHANNEL_SUBSTATUS_C_CLOSE;

	}

	/* no close received from server? */

	if (!(channel->substatus & CHANNEL_SUBSTATUS_S_CLOSE)) {
	    unsigned int error=0;

	    get_channel_expire_init(channel, &expire);

	    waitchannelclose:

	    payload=get_ssh_payload_channel(channel, &expire, &seq, &error);

	    if (! payload) {

		if (error==0) error=EIO;
		logoutput("send_command: error %i waiting for packet (%s)", error, strerror(error));

	    } else {

		if (payload->type==SSH_MSG_CHANNEL_EOF) {

		    logoutput("send_command: received EOF");
		    free(payload);
		    goto waitchannelclose;

		} else if (payload->type==SSH_MSG_CHANNEL_CLOSE) {

		    channel->substatus|=CHANNEL_SUBSTATUS_S_CLOSE;

		} else {

		    logoutput("send_command: received unknown reply %i", payload->type);
		    free(payload);
		    goto waitchannelclose;

		}

		free(payload);

	    }

	}

    } else {

	logoutput("send_command: error sending message");
	return 0;

    }

    return server_reply->response.data.size;

}


int start_remote_shell_admin(struct ssh_channel_s *channel)
{
    struct ssh_session_s *session=channel->session;
    unsigned int seq=0;
    unsigned int error=0;
    struct ssh_payload_s *payload=NULL;
    struct timespec expire;

    /*
	start the remote shell on the channel
    */

    logoutput("start_remote_shell_admin: send start shell");

    if (send_start_command_message(channel, "shell", NULL, 1, &seq)==0) {

	get_channel_expire_init(channel, &expire);

	payload=get_ssh_payload_channel(channel, &expire, &seq, &error);

	if (! payload) {

	    if (session->status.error==0) session->status.error=(error>0) ? error : EIO;
	    logoutput("start_remote_shell_admin: error %i waiting for packet (%s)", session->status.error, strerror(session->status.error));
	    goto error;

	}

	if (payload->type==SSH_MSG_CHANNEL_SUCCESS) {

	    /* ready: channel ready to use */

	    logoutput("start_remote_shell_admin: server started shell");

	} else if (payload->type==SSH_MSG_CHANNEL_FAILURE) {

	    logoutput("start_remote_shell_admin: server failed to start shell");
	    goto error;

	} else {

	    logoutput("start_remote_shell_admin: got unexpected reply %i", payload->type);
	    goto error;

	}

	free(payload);
	payload=NULL;

    } else {

	logoutput("start_remote_shell_admin: error sending shell request");
	goto error;

    }

    /* process any message from server like banners */

    processdatashell:

    get_admin_channel_expire_init(channel, &expire);

    payload=get_ssh_payload_channel(channel, &expire, &seq, &error);

    if (payload) {

	if (payload->type==SSH_MSG_CHANNEL_DATA) {
	    unsigned int len=get_uint32(&payload->buffer[5]);
	    char buffer[len+1];

	    memcpy(buffer, &payload->buffer[9], len);
	    buffer[len]='\0';

	    replace_cntrl_char(buffer, len);
	    // replace_newline_char(buffer, &len);

	    logoutput("start_remote_shell_admin: received %s", buffer);

	} else {

	    logoutput("start_remote_shell_admin: got unexpected reply %i", payload->type);

	}

	free(payload);
	payload=NULL;

	goto processdatashell;

    }

    return 0;

    error:

    return -1;

}

unsigned int start_shell_command_remote(struct ssh_channel_s *channel, char *command, struct server_reply_s *server_reply, struct timespec *send, struct timespec *received)
{
    struct ssh_session_s *session=channel->session;
    unsigned int len=strlen(command);
    unsigned int seq=0;
    unsigned char buffer[len+2];

    logoutput("start_shell_command_remote");

    memcpy((char *)buffer, command, len);

    /* add CRLF to command (CR=ascii 13 LF=ascii 10) */

    buffer[len]=13;
    buffer[len+1]=10;

    if (send) get_current_time(send);

    if (send_channel_data_message(channel, len+2, buffer, &seq)==0) {
	struct ssh_payload_s *payload=NULL;
	struct timespec expire;
	unsigned int error=0;

	/* wait for output from command */

	get_admin_channel_expire_init(channel, &expire);

	getpayload:

	payload=get_ssh_payload_channel(channel, &expire, &seq, &error);

	if (! payload) {

	    if (session->status.error==0) session->status.error=(error>0) ? error : EIO;
	    logoutput("start_shell_command_remote: error %i waiting for packet (%s)", session->status.error, strerror(session->status.error));
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

		logoutput("start_shell_command_remote: error output from command %s", command);

		size=get_uint32(&payload->buffer[9]);

		if (size>0) {
		    char errorstring[size+1];

		    memcpy(errorstring, (char *) &payload->buffer[13], size);
		    replace_cntrl_char(errorstring, size);
		    errorstring[size]='\0';

		    logoutput("start_shell_command_remote: error %s", errorstring);

		    free(payload);
		    payload=NULL;

		    goto getpayload;

		}

	    } else {

		logoutput("start_shell_command_remote: unknown code %i", code);
		server_reply->error=EIO;

	    }

	} else {

	    logoutput("start_shell_command_remote: received unknown reply %i", payload->type);
	    server_reply->error=EIO;

	}

	free(payload);
	payload=NULL;

    } else {

	logoutput("start_shell_command_remote: error sending comman %s", command);
	server_reply->error=EIO;

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

unsigned int run_command_remote(struct ssh_session_s *session, char *command, struct server_reply_s *server_reply, struct timespec *send, struct timespec *received)
{
    struct ssh_channel_s *channel=NULL;
    struct channel_table_s *table=&session->channel_table;
    unsigned int size=0;

    /* create a new channel */

    channel=new_admin_channel(session);

    if (channel) {

	if (start_new_channel(channel)==0) {

	    size=send_command(channel, command, server_reply, send, received);

	}

    }

    if (channel) {

	remove_channel_table(channel);
	free_ssh_channel(channel);

    }

    return size;

}

unsigned int _get_result_common(struct ssh_session_s *session, const char *command, unsigned char *buffer, unsigned int len, struct timespec *send, struct timespec *recv, unsigned int *error)
{
    struct channel_table_s *table=&session->channel_table;
    struct server_reply_s server_reply;
    unsigned int size=0;

    memset(&server_reply, 0, sizeof(struct server_reply_s));
    server_reply.response.data.ptr=NULL;
    server_reply.response.data.size=0;

    if (table->admin) {

	logoutput("get_result_common: start %s through admin shell", command);
	size=start_shell_command_remote(table->admin, command, &server_reply, send, recv);

    } else {

	logoutput("get_result_common: start %s as remote command", command);
	size=run_command_remote(session, command, &server_reply, send, recv);

    }

    if (size==0 || server_reply.error>0) {

	*error=(server_reply.error>0) ? server_reply.error : EIO;
	size=0;
	goto finish;

    }

    if (server_reply.reply==SSH_MSG_CHANNEL_DATA) {
	char *sep=NULL;
	unsigned char *name=NULL;
	unsigned int left=0;

	/* remove any space/tab/newlines/linefeed */

	replace_cntrl_char((char *)server_reply.response.data.ptr, server_reply.response.data.size);

	size=server_reply.response.data.size;
	if (size>len) size=len;
	memcpy((char *)buffer, server_reply.response.data.ptr, size);

    } else if (server_reply.reply==SSH_MSG_CHANNEL_EXTENDED_DATA) {
	char string[server_reply.response.data.size + 1];

	memcpy(string, server_reply.response.data.ptr, server_reply.response.data.size);
	string[server_reply.response.data.size]='\0';

	logoutput("get_result_common: error output %s", string);

    }

    finish:

    if (server_reply.response.data.ptr) {

	free(server_reply.response.data.ptr);
	server_reply.response.data.ptr=NULL;

    }

    return size;

}

unsigned int get_result_common(struct ssh_session_s *session, const char *command, unsigned char *buffer, unsigned int len, unsigned int *error)
{
    return _get_result_common(session, command, buffer, len, NULL, NULL, error);
}

unsigned int get_result_common_timed(struct ssh_session_s *session, char *command, unsigned char *buffer, unsigned int len, struct timespec *send, struct timespec *recv, unsigned int *error)
{
    return _get_result_common(session, command, buffer, len, send, recv, error);
}

static unsigned int get_timeinfo_command(struct ssh_session_s *session, char *buffer)
{
    unsigned int size=0;

    if (buffer) {
	unsigned int len=0;

	memcpy(buffer, "echo ", 5);
	size+=5;

	len=strlen("remotetime=$(date +%s:%N):");
	memcpy(&buffer[size], "remotetime=$(date +%s.%N):", len);
	size+=len;

    } else {

	size+=5;
	size+=strlen("remotetime=$(date +%s.%N):");

    }

    return size;

}

static unsigned int get_servername_command(struct ssh_session_s *session, char *buffer)
{
    unsigned int size=0;

    if (buffer) {
	unsigned int len=0;

	len=strlen("echo $(/usr/lib/fs-workspace/getservername)");
	memcpy(buffer, "echo $(/usr/lib/fs-workspace/getservername)", len);
	size+=len;

    } else {
	unsigned int len=0;

	len=strlen("echo $(/usr/lib/fs-workspace/getservername)");
	size+=len;

    }

    return size;

}

static unsigned int get_services_command(struct ssh_session_s *session, char *buffer)
{
    unsigned int size=0;

    if (buffer) {
	unsigned int len=0;

	len=strlen("echo $(/usr/lib/fs-workspace/getservices)");
	memcpy(buffer, "echo $(/usr/lib/fs-workspace/getservices)", len);
	size+=len;

    } else {

	size+=strlen("echo $(/usr/lib/fs-workspace/getservices)");

    }

    return size;

}

/*
    get services supported by server*/

static unsigned int get_supported_services(struct ssh_session_s *session, unsigned char *buffer, unsigned int len, unsigned int *error)
{
    unsigned int size=get_services_command(session, NULL);
    char command[size+1];

    size=get_services_command(session, command);
    command[size]='\0';

    logoutput("get_supported_services: command %s", command);

    return get_result_common(session, command, buffer, len, error);

}

/*
    get server name (including domainname) */

static unsigned int get_servername(struct ssh_session_s *session, unsigned char *buffer, unsigned int len, unsigned int *error)
{
    unsigned int size=get_servername_command(session, NULL);
    char command[size+1];

    size=get_servername_command(session, command);
    command[size]='\0';

    logoutput("get_servername: command %s", command);

    return get_result_common(session, command, buffer, len, error);

}

/*
    get time on server as product of command */

unsigned int get_timeinfo_server(struct ssh_session_s *session, unsigned char *buffer, unsigned int len, struct timespec *send, struct timespec *recv, unsigned int *error)
{
    int size=get_timeinfo_command(session, NULL);
    char command[size+1];
    struct timespec send_client;
    struct timespec recv_client;
    struct timespec set_server;

    size=get_timeinfo_command(session, command);
    command[size]='\0';

    return get_result_common_timed(session, command, buffer, len, send, recv, error);

}

unsigned int get_ssh_interface_info(struct context_interface_s *interface, const char *what, void *data, unsigned char *buffer, unsigned int size, unsigned int *error)
{
    struct ssh_session_s *session=NULL;
    unsigned int result=0;

    logoutput("get_ssh_interface_info: what %s", what);

    if (interface->ptr) {

	session=(struct ssh_session_s *) interface->ptr;

    } else {

	session=(struct ssh_session_s *) data;

    }

    if (! session) {

	*error=ENOENT;
	return 0;

    }

    if (strcmp(what, "servername")==0) {

	result=get_servername(session, buffer, size, error);

	/* when server does not give a (custom) hostname (as output from script on server) get the name of the system */

	if (result==0) {
	    char *remotename=get_ssh_hostname(session, 1, error);

	    /* fallback to ip address when no hostname is found */

	    if (remotename==NULL) remotename=get_ssh_ipv4(session, 1, error);

	    if (remotename) {
		unsigned int len=strlen(remotename);

		if (len>size) {

		    memcpy(buffer, remotename, size);
		    result=size;

		} else {

		    memcpy(buffer, remotename, len);
		    result=len;

		}

		free(remotename);

	    } else {

		/* no remote name found */

		logoutput("get_ssh_interface_info: error %i getting remote hostname (%s)", *error, strerror(*error));

	    }

	}

    } else if (strcmp(what, "status")==0) {
	unsigned int status=1;
	unsigned int *dest=(unsigned int *) buffer;

	status=(session->status.status==SESSION_STATUS_COMPLETE) ? 0 : 1;
	memcpy(dest, &status, sizeof(unsigned int));

	return (sizeof(unsigned int));

    } else if (strcmp(what, "services")==0) {

	result=get_supported_services(session, buffer, size, error);

    } else {

	result=get_result_common(session, what, buffer, size, error);

    }

    return result;
}
