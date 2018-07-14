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
#include <ctype.h>
#include <inttypes.h>

#include <sys/param.h>
#include <sys/types.h>
#include <sys/stat.h>

#include "ssh-payload.h"

#define LOGGING
#include "logging.h"

static struct ssh_payload_s *realloc_payload_static(struct ssh_payload_s *payload, unsigned int size)
{

    /* allocator for a new payload when payload is static */

    return (struct ssh_payload_s *) malloc(sizeof(struct ssh_payload_s) + size);

}

static void free_static(struct ssh_payload_s **p)
{
}

static struct ssh_payload_s *realloc_payload_dynamic(struct ssh_payload_s *payload, unsigned int size)
{

    return (struct ssh_payload_s *) realloc((void *)payload, sizeof(struct ssh_payload_s) + size);
}

static void free_dynamic(struct ssh_payload_s **p)
{
    struct ssh_payload_s *payload=*p;
    free(payload);
    *p=NULL;
}

struct ssh_payload_s *realloc_payload(struct ssh_payload_s *payload, unsigned int size)
{
    return (*payload->realloc)(payload, size);
}

void free_payload(struct ssh_payload_s **p)
{
    struct ssh_payload_s *payload=*p;
    (* payload->free)(p);
}

void copy_payload_header(struct ssh_payload_s *a, struct ssh_payload_s *b)
{
    b->flags=a->flags;
    b->type=a->type;
    b->sequence=a->sequence;
    b->len=a->len;
    b->next=a->next;
    b->prev=a->prev;
}

void fill_payload_buffer(struct ssh_payload_s *a, char *buffer, unsigned int len)
{
    memcpy(a->buffer, buffer, len);
    a->len=len;
}

void init_ssh_payload(struct ssh_payload_s *payload, unsigned int size)
{

    memset(payload, 0, sizeof(struct ssh_payload_s) + size);

    payload->flags=0;
    payload->type=0;
    payload->sequence=0;
    payload->len=size;
    payload->next=NULL;
    payload->prev=NULL;

}

struct ssh_payload_s *malloc_payload(unsigned int size)
{
    return malloc(sizeof(struct ssh_payload_s) + size);
}

static char *isolate_payload_buffer_dynamic(struct ssh_payload_s **p_payload, unsigned int pos, unsigned int size)
{
    char *buffer=NULL;
    struct ssh_payload_s *payload=*p_payload;

    if (pos + size <= payload->len) {

	logoutput("isolate_payload_buffer_dynamic: resize buffer from %i to %i", payload->len, size);

	buffer=(char *) payload;
	memmove(buffer, &payload->buffer[pos], size);
	buffer=realloc(buffer, size);

	*p_payload=NULL;

    }

    return buffer;

}

static char *isolate_payload_buffer_static(struct ssh_payload_s **p_payload, unsigned int pos, unsigned int size)
{
    char *buffer=NULL;
    struct ssh_payload_s *payload=*p_payload;

    if (pos + size <= payload->len) {

	buffer=malloc(size);
	if (buffer) memmove(buffer, &payload->buffer[pos], size);

	*p_payload=NULL;

    }

    return buffer;

}

char *isolate_payload_buffer(struct ssh_payload_s **p_payload, unsigned int pos, unsigned int size)
{
    struct ssh_payload_s *payload=*p_payload;
    return (* payload->isolate_buffer)(p_payload, pos, size);
}

void set_alloc_payload_dynamic(struct ssh_payload_s *payload)
{
    payload->realloc=realloc_payload_dynamic;
    payload->free=free_dynamic;
    payload->isolate_buffer=isolate_payload_buffer_dynamic;
}

void set_alloc_payload_static(struct ssh_payload_s *payload)
{
    payload->realloc=realloc_payload_static;
    payload->free=free_static;
    payload->isolate_buffer=isolate_payload_buffer_static;
}
