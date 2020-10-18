/*
  2016, 2017 Stef Bon <stefbon@gmail.com>

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

int start_channel(struct ssh_channel_s *channel, unsigned int *error)
{
    int result=-1;
    unsigned int seq=0;
    struct ssh_session_s *session=channel->session;
    unsigned int dummy=0;

    if (error==NULL) error=&dummy;

    if (!(channel->flags & CHANNEL_FLAG_TABLE)) {

	*error=EINVAL;
	return -1;

    } else if (channel->flags & CHANNEL_FLAG_OPEN) {

	*error=EINVAL;
	return -1;

    }

    logoutput("start_channel: send channel open message");

    if (send_channel_open_message(channel, &seq)==0) {
	struct timespec expire;
	struct ssh_payload_s *payload=NULL;

	get_channel_expire_init(channel, &expire);

	getpayload:

	payload=get_ssh_payload_channel(channel, &expire, &seq, error);

	if (! payload) {

	    logoutput("start_channel: error %i waiting for packet (%s)", *error, strerror(*error));
	    goto out;

	}

	if (payload->type==SSH_MSG_CHANNEL_OPEN_CONFIRMATION) {
	    unsigned int window=0;

	    channel->remote_channel=get_uint32(&payload->buffer[5]);
	    channel->remote_window=get_uint32(&payload->buffer[9]);
	    channel->max_packet_size=get_uint32(&payload->buffer[13]);

	    channel->flags |= CHANNEL_FLAG_OPEN;

	    logoutput("start_channel: created a new channel local:remote %i:%i local window %u remote window %u max packet size %i", channel->local_channel, channel->remote_channel, channel->local_window, channel->remote_window, channel->max_packet_size);
	    result=0;
	    free_payload(&payload);

	} else if (payload->type==SSH_MSG_CHANNEL_OPEN_FAILURE) {
	    unsigned int reasoncode=0;
	    unsigned int len=0;

	    reasoncode=get_uint32(&payload->buffer[5]);
	    len=get_uint32(&payload->buffer[9]);

	    if (13 + len <= payload->len) {
		unsigned char string[len+1];

		memcpy(string, &payload->buffer[13], len);
		string[len]='\0';

		logoutput("start_channel: failed by server: %s/%s", get_openfailure_reason(reasoncode), string);

	    } else {

		logoutput("start_channel: failed by server: %s", get_openfailure_reason(reasoncode));

	    }

	    channel->flags |= CHANNEL_FLAG_OPENFAILURE;
	    free_payload(&payload);

	} else {

	    logoutput("start_channel: unexpected reply from server: %i", payload->type);
	    free_payload(&payload);
	    goto getpayload;

	}

    } else {

	logoutput("start_channel: error sending open channel message");

    }

    out:

    if (result==0) {
	struct ssh_signal_s *signal=channel->queue.signal;

	pthread_mutex_lock(signal->mutex);
	pthread_cond_broadcast(signal->cond);
	pthread_mutex_unlock(signal->mutex);

    }

    return result;

}

void close_channel(struct ssh_channel_s *channel, unsigned int flags)
{

    if (!(channel->flags & CHANNEL_FLAG_OPEN)) {

	return;

    }

    logoutput("close_channel: %i", channel->local_channel);

    if ((flags & CHANNEL_FLAG_CLIENT_CLOSE) && (channel->flags & CHANNEL_FLAG_CLIENT_CLOSE)==0) {

	channel->flags|=CHANNEL_FLAG_CLIENT_CLOSE;

	if (send_channel_close_message(channel)==-1) {

	    logoutput("close_channel: error sending close channel");

	}

    }

    if ((flags & CHANNEL_FLAG_SERVER_CLOSE) && (channel->flags & CHANNEL_FLAG_SERVER_CLOSE)==0) {
	struct timespec expire;
	struct ssh_signal_s *signal=channel->queue.signal;

	/* TODO: do not wait when there are connection problems */

	get_channel_expire_init(channel, &expire);

	pthread_mutex_lock(signal->mutex);

	while((channel->flags & CHANNEL_FLAG_SERVER_CLOSE)==0) {

	    if (pthread_cond_timedwait(signal->cond, signal->mutex, &expire)==ETIMEDOUT) {

		logoutput("close_channel: timeout waiting for server close");
		break;

	    }

	}

	pthread_mutex_unlock(signal->mutex);

    }

    channel->flags -= CHANNEL_FLAG_OPEN;

}
