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

#include "logging.h"
#include "main.h"
#include "utils.h"

#include "ssh-common.h"
#include "ssh-utils.h"
#include "ssh-receive.h"

static unsigned int populate_decompress(struct ssh_session_s *session, struct decompress_ops_s *ops, struct algo_list_s *alist, unsigned int start)
{

    if (alist) {

	alist[start].type=SSH_ALGO_TYPE_COMPRESS_S2C;
	alist[start].order=SSH_ALGO_ORDER_LOW;
	alist[start].sshname="none";
	alist[start].libname="none";
	alist[start].ptr=(void *)ops;

    }

    start++;

    return start;

}

static unsigned int get_handle_size(struct ssh_decompress_s *d)
{
    return 0;
}

static int decompress_packet(struct ssh_decompressor_s *d, struct ssh_packet_s *packet, struct ssh_payload_s **p_payload, unsigned int *error)
{
    unsigned int len=packet->len - packet->padding - 1;
    struct ssh_payload_s *payload=malloc(sizeof(struct ssh_payload_s) + len);

    if (payload) {

	*p_payload=payload;

	payload->flags=SSH_PAYLOAD_FLAG_ALLOCATED;
	payload->len=len;
	memcpy(payload->buffer, &packet->buffer[5], len);
	payload->type=(unsigned char) payload->buffer[0];
	payload->sequence=packet->sequence;
	payload->next=NULL;
	payload->prev=NULL;
	set_alloc_payload_dynamic(payload);
	return 0;

    }

    *error=ENOMEM;
    *p_payload=NULL;
    return -1;

}

static void clear_decompressor(struct ssh_decompressor_s *d)
{
}

static int init_decompressor(struct ssh_decompressor_s *d)
{
    d->decompress_packet	= decompress_packet;
    d->clear			= clear_decompressor;
    return 0;
}

static struct decompress_ops_s none_d_ops = {
    .name			= "none",
    .populate			= populate_decompress,
    .get_handle_size		= get_handle_size,
    .init_decompressor		= init_decompressor,
    .list			= {NULL, NULL},
};

void init_decompress_none()
{
    add_decompress_ops(&none_d_ops);
}

void set_decompress_none(struct ssh_session_s *session)
{
    struct ssh_decompress_s *decompress=&session->receive.decompress;
    decompress->ops=&none_d_ops;
}
