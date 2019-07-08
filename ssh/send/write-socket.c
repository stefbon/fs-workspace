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
#include "workerthreads.h"

#include "utils.h"

#include "ssh-common.h"
#include "ssh-common-protocol.h"
#include "ssh-send.h"
#include "ssh-utils.h"

int write_socket(struct ssh_session_s *session, struct ssh_packet_s *packet, unsigned int *error)
{
    struct socket_ops_s *sops=session->connection.io.socket.sops;
    ssize_t written=0;
    char *pos=packet->buffer;
    unsigned int left=packet->size;

    writesocket:

    logoutput("write_socket: seq %i len %i", packet->sequence, left);

    written=(* sops->send)(&session->connection.io.socket, pos, left, 0);

    if (written==-1) {

	if (errno==EAGAIN || errno==EWOULDBLOCK) goto writesocket;

	*error=errno;
	return -1;

    }

    pos+=written;
    left-=written;

    if (left>0) goto writesocket;

    return 0;
}
