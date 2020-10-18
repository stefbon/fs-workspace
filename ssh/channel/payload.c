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
#include "ssh-receive.h"

struct ssh_payload_s *get_ssh_payload_channel(struct ssh_channel_s *channel, struct timespec *expire, unsigned int *seq, unsigned int *error)
{
    logoutput("get_ssh_payload_channel");

    if (channel->flags & (CHANNEL_FLAG_SERVER_CLOSE | CHANNEL_FLAG_SERVER_EOF | CHANNEL_FLAG_OPENFAILURE)) {

	*error=ENOTCONN;
	return NULL;

    }

    return get_ssh_payload(channel->connection, &channel->queue, expire, seq, error);
}

void queue_ssh_payload_channel(struct ssh_channel_s *channel, struct ssh_payload_s *payload)
{
    logoutput("queue_ssh_payload_channel: type %i", payload->type);
    queue_ssh_payload(&channel->queue, payload);
}
