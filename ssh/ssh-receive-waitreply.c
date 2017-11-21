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
#include <poll.h>
#include <sys/epoll.h>

#include "logging.h"
#include "main.h"

#include "utils.h"

#include "ssh-common.h"
#include "ssh-common-protocol.h"

#include "ssh-receive.h"
#include "ssh-utils.h"

int wait_reply_server_greeter(struct ssh_session_s *session, struct timespec *expire, unsigned int *error)
{
    struct ssh_receive_s *receive=&session->receive;
    struct rawdata_queue_s *queue=&receive->rawdata_queue;
    int result=0;

    pthread_mutex_lock(&queue->mutex);

    while (session->data.greeter_server.ptr==NULL) {

	result=pthread_cond_timedwait(&queue->cond, &queue->mutex, expire);

	if (session->data.greeter_server.ptr) {

	    *error=0;
	    break;

	} else if (result==ETIMEDOUT) {

	    *error=result;
	    result=-1;
	    break;

	}

    }

    pthread_mutex_unlock(&queue->mutex);

    return result;

}

void signal_reply_server(struct ssh_session_s *session)
{
    struct ssh_receive_s *receive=&session->receive;
    struct rawdata_queue_s *queue=&receive->rawdata_queue;

    /* signal any waiting thread */

    pthread_mutex_lock(&queue->mutex);
    pthread_cond_broadcast(&queue->cond);
    pthread_mutex_unlock(&queue->mutex);

}
