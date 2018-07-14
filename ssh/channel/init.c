/*
  2018 Stef Bon <stefbon@gmail.com>

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
#include "startclose.h"

void clean_ssh_channel_queue(struct ssh_channel_s *channel)
{
    struct payload_queue_s *queue=&channel->payload_queue;
    struct ssh_payload_s *payload=queue->list.head;

    while (payload) {

	queue->list.head=payload->next;
	logoutput("clean_ssh_channel_queue: found type %i", payload->type);
	free(payload);
	payload=queue->list.head;

    }

}

void clear_ssh_channel(struct ssh_channel_s *channel)
{
    clean_ssh_channel_queue(channel);

    if (channel->type==_CHANNEL_TYPE_DIRECT_STREAMLOCAL) {

	if (channel->target.socket.path) {

	    free(channel->target.socket.path);
	    channel->target.socket.path=NULL;

	}

    } else if (channel->type==_CHANNEL_TYPE_DIRECT_TCPIP) {

	if (channel->target.tcpip.host) {

	    free(channel->target.tcpip.host);
	    channel->target.tcpip.host=NULL;

	}

    }

    pthread_mutex_destroy(&channel->mutex);

}

void free_ssh_channel(struct ssh_channel_s *channel)
{
    clear_ssh_channel(channel);
    free(channel);
}

static void process_incoming_bytes_default(struct ssh_channel_s *channel, unsigned int size)
{
    logoutput("process_incoming_bytes_default: local window %u len %i", channel->local_window, size);
    /* decrease local window */
    channel->local_window-=size;

    /* when local_window < max packet size then send a window adjust message */
}

static void process_outgoing_bytes_default(struct ssh_channel_s *channel, unsigned int size)
{
    pthread_mutex_lock(&channel->mutex);

    /* decrease the remote window */
    channel->remote_window-=size;

    /* when remote window < max packet size wait for a window adjust message */

    pthread_mutex_unlock(&channel->mutex);
}

void init_ssh_channel(struct ssh_session_s *session, struct ssh_channel_s *channel, unsigned char type)
{
    channel->session=session;
    channel->type=type;

    channel->local_channel=0;
    channel->remote_channel=0;

    channel->flags=CHANNEL_FLAG_INIT;

    channel->max_packet_size=0; /* filled later */
    channel->actors=0;
    channel->local_window=get_window_size(session);
    channel->process_incoming_bytes=process_incoming_bytes_default;
    channel->remote_window=0; /* to be received from server */
    channel->process_outgoing_bytes=process_outgoing_bytes_default;

    /* make use of the central mutex/cond for announcing payload has arrived */

    channel->payload_queue.signal=&session->receive.signal;
    channel->payload_queue.list.head=NULL;
    channel->payload_queue.list.tail=NULL;

    pthread_mutex_init(&channel->mutex, NULL);
    channel->list.next=NULL;
    channel->list.prev=NULL;

    channel->start=start_channel;
    channel->close=close_channel;
    switch_channel_send_data(channel, "default");
    switch_channel_receive_data(channel, "init", NULL);
    channel->free=free_ssh_channel;

}

struct ssh_channel_s *create_channel(struct ssh_session_s *session, unsigned char type)
{
    struct ssh_channel_s *channel=NULL;

    channel=malloc(sizeof(struct ssh_channel_s));

    if (channel) {

	memset(channel, 0, sizeof(struct ssh_channel_s));
	init_ssh_channel(session, channel, type);

    }

    return channel;

}
