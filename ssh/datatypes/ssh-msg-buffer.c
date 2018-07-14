/*
  2010, 2011, 2012, 2103, 2014, 2015, 2016, 2017, 2018 Stef Bon <stefbon@gmail.com>

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

#include "ssh-uint.h"
#include "ssh-string.h"
#include "ssh-uint.h"
#include "ssh-payload.h"
#include "ssh-msg-buffer.h"

void nowrite_byte(struct msg_buffer_s *mb, unsigned char b)
{
    mb->pos++;
}

void dowrite_byte(struct msg_buffer_s *mb, unsigned char b)
{

    if (mb->pos<mb->len) {

	mb->data[mb->pos]=b;

    } else {

	set_msg_buffer_fatal_error(mb, ENOBUFS);

    }

    mb->pos++;

}

void nowrite_bytes(struct msg_buffer_s *mb, unsigned char *bytes, unsigned int len)
{
    mb->pos+=len;
}

void dowrite_bytes(struct msg_buffer_s *mb, unsigned char *bytes, unsigned int len)
{

    if (mb->pos + len <= mb->len) {

	memcpy(&mb->data[mb->pos], bytes, len);

    } else {

	set_msg_buffer_fatal_error(mb, ENOBUFS);

    }

    mb->pos+=len;

}

unsigned int start_ssh_string(struct msg_buffer_s *mb)
{
    unsigned int pos=mb->pos;
    ( mb->write_ssh_string)(mb, 'l', NULL);
    return pos;
}

void nowrite_ssh_string(struct msg_buffer_s *mb, const unsigned char type, void *ptr)
{
    mb->pos+=write_ssh_string(NULL, 0, type, ptr);
}

void dowrite_ssh_string(struct msg_buffer_s *mb, const unsigned char type, void *ptr)
{
    unsigned int len = write_ssh_string(NULL, 0, type, ptr);

    if (mb->pos + len < mb->len) {

	mb->pos+=write_ssh_string(&mb->data[mb->pos], (unsigned int)(mb->len - mb->pos), type, ptr);

    } else {

	set_msg_buffer_fatal_error(mb, ENOBUFS);
	mb->pos+=len;

    }

}

void nowrite_complete_ssh_string(struct msg_buffer_s *mb, unsigned int pos)
{
}

void dowrite_complete_ssh_string(struct msg_buffer_s *mb, unsigned int pos)
{
    unsigned int len = (mb->pos - pos - write_ssh_string(NULL, 0, 'l', NULL));
    write_ssh_string(&mb->data[pos], 0, 'l', (void *) &len);
}

void nostore_uint32(struct msg_buffer_s *mb, uint32_t value)
{
    mb->pos += 4;
}

void dostore_uint32(struct msg_buffer_s *mb, uint32_t value)
{
    if (mb->pos + 4 <= mb->len) {

	store_uint32(&mb->data[mb->pos], value);
	mb->pos += 4;

    } else {

	set_msg_buffer_fatal_error(mb, ENOBUFS);
	mb->pos+=4;

    }

}

void nostore_uint64(struct msg_buffer_s *mb, uint64_t value)
{
    mb->pos += 8;
}

void dostore_uint64(struct msg_buffer_s *mb, uint64_t value)
{
    if (mb->pos + 8 <= mb->len) {

	store_uint64(&mb->data[mb->pos], value);
	mb->pos += 8;

    } else {

	set_msg_buffer_fatal_error(mb, ENOBUFS);
	mb->pos+=8;

    }

}

static void _fill_commalist(struct msg_buffer_s *mb, void (* cb)(struct msg_buffer_s *mb, void *ptr), void *ptr)
{
    unsigned int pos=(* mb->start_ssh_string)(mb);

    (* cb)(mb, ptr);
    (* mb->complete_ssh_string)(mb, pos);
}

void nofill_commalist(struct msg_buffer_s *mb, void (* cb)(struct msg_buffer_s *mb, void *ptr), void *ptr)
{
    _fill_commalist(mb, cb, ptr);
}

unsigned int start_count(struct msg_buffer_s *mb)
{
    unsigned int pos=mb->pos;
    (mb->store_uint32)(mb, 0); /* count is unknown, store zero for now */
    return pos;
}

void nowrite_complete_count(struct msg_buffer_s *mb, unsigned int pos, unsigned int count)
{
}

static void dowrite_complete_count(struct msg_buffer_s *mb, unsigned int pos, unsigned int count)
{
    store_uint32(&mb->data[pos], count);
}

struct msg_buffer_s init_msg_buffer = {
    .data					= NULL,
    .len					= 0,
    .pos					= 0,
    .error					= 0,
    .write_byte					= nowrite_byte,
    .write_bytes				= nowrite_bytes,
    .start_ssh_string				= start_ssh_string,
    .write_ssh_string				= nowrite_ssh_string,
    .complete_ssh_string			= nowrite_complete_ssh_string,
    .store_uint32				= nostore_uint32,
    .store_uint64				= nostore_uint64,
    .fill_commalist				= nofill_commalist,
    .start_count				= start_count,
    .complete_count				= nowrite_complete_count,
};

void msg_read_byte(struct msg_buffer_s *mb, unsigned char *b)
{
    if (mb->error==0) {

	if (mb->pos < mb->len) {

	    if (b ) *b=mb->data[mb->pos];
	    mb->pos++;

	} else {

	    mb->error=EIO;

	}

    }

}

void msg_read_bytes(struct msg_buffer_s *mb, unsigned char *b, unsigned int *plen)
{

    if (mb->error==0) {

	if (b && plen) {
	    unsigned int len = *plen;

	    if (mb->pos < mb->len) {

		if (len > mb->len - mb->pos) {

		    len = (mb->len - mb->pos);
		    mb->error=EIO;
		    *plen=len; /* less bytes read */

		}

		memcpy(b, &mb->data[mb->pos], len);
		mb->pos+=len;

	    } else {

		mb->error=EIO;

	    }

	}

    }

}

void msg_read_uint32(struct msg_buffer_s *mb, unsigned int *result)
{
    if (mb->error==0) {

	*result=get_uint32(&mb->data[mb->pos]);
	mb->pos+=4;

    }
}

void msg_read_uint64(struct msg_buffer_s *mb, uint64_t *result)
{
    if (mb->error==0) {

	*result=get_uint64(&mb->data[mb->pos]);
	mb->pos+=8;

    }
}

void msg_read_ssh_string_header(struct msg_buffer_s *mb, unsigned int *len)
{

    if (mb->error==0) {

	if (mb->pos < mb->len) {

	    mb->pos+=read_ssh_string_header(&mb->data[mb->pos], mb->len - mb->pos, len);

	}

    }

}

void msg_read_ssh_string(struct msg_buffer_s *mb, struct ssh_string_s *s)
{

    if (mb->error==0) {

	if (mb->pos < mb->len) {

	    mb->pos+=read_ssh_string(&mb->data[mb->pos], mb->len - mb->pos, s);

	}

    }

}

static void set_msg_buffer_write(struct msg_buffer_s *mb)
{
    mb->write_byte=dowrite_byte;
    mb->write_bytes=dowrite_bytes;
    mb->start_ssh_string=start_ssh_string;
    mb->write_ssh_string=dowrite_ssh_string;
    mb->complete_ssh_string=dowrite_complete_ssh_string;
    mb->store_uint32=dostore_uint32;
    mb->store_uint64=dostore_uint64;
    mb->fill_commalist=_fill_commalist;
    mb->start_count=start_count;
    mb->complete_count=dowrite_complete_count;
}

static void set_msg_buffer_nowrite(struct msg_buffer_s *mb)
{
    mb->write_byte=nowrite_byte;
    mb->write_bytes=nowrite_bytes;
    mb->start_ssh_string=start_ssh_string;
    mb->write_ssh_string=nowrite_ssh_string;
    mb->complete_ssh_string=nowrite_complete_ssh_string;
    mb->store_uint32=nostore_uint32;
    mb->store_uint64=nostore_uint64;
    mb->fill_commalist=_fill_commalist;
    mb->start_count=start_count;
    mb->complete_count=nowrite_complete_count;
}

void set_msg_buffer(struct msg_buffer_s *mb, char *data, unsigned int len)
{

    if (data) {

	mb->data=data;
	mb->len=len;
	mb->pos=0;
	mb->error=0;
	set_msg_buffer_write(mb);

    } else {

	mb->data=NULL;
	mb->len=0;
	mb->pos=0;
	mb->error=0;
	set_msg_buffer_nowrite(mb);

    }

}

void set_msg_buffer_payload(struct msg_buffer_s *mb, struct ssh_payload_s *p)
{
    set_msg_buffer(mb, p->buffer, p->len);
}

void set_msg_buffer_string(struct msg_buffer_s *mb, struct ssh_string_s *s)
{
    set_msg_buffer(mb, s->ptr, s->len);
}

void set_msg_buffer_fatal_error(struct msg_buffer_s *mb, unsigned int error)
{
    mb->error=error;
    set_msg_buffer_nowrite(mb);
}

void msg_write_byte(struct msg_buffer_s *mb, unsigned char byte)
{
    (* mb->write_byte)(mb, byte);
}

void msg_write_bytes(struct msg_buffer_s *mb, unsigned char *bytes, unsigned int len)
{
    (* mb->write_bytes)(mb, bytes, len);
}

void msg_write_ssh_string(struct msg_buffer_s *mb, const unsigned char type, void *ptr)
{
    (* mb->write_ssh_string)(mb, type, ptr);
}

void msg_complete_ssh_string(struct msg_buffer_s *mb, unsigned int pos)
{
    (* mb->complete_ssh_string)(mb, pos);
}

void msg_store_uint32(struct msg_buffer_s *mb, uint32_t value)
{
    (* mb->store_uint32)(mb, value);
}

void msg_store_uint64(struct msg_buffer_s *mb, uint64_t value)
{
    (* mb->store_uint64)(mb, value);
}

void msg_fill_commalist(struct msg_buffer_s *mb, void (* cb)(struct msg_buffer_s *mb, void *ptr), void *ptr)
{
    (* mb->fill_commalist)(mb, cb, ptr);
}

unsigned int msg_start_count(struct msg_buffer_s *mb)
{
    return (* mb->start_count)(mb);
}

void msg_complete_count(struct msg_buffer_s *mb, unsigned int pos, unsigned int count)
{
    return (* mb->complete_count)(mb, pos, count);
}

unsigned int msg_count_strings(struct msg_buffer_s *mb, unsigned int max)
{

    if (mb->data==NULL) {

	return 0;

    } else if (mb->pos + 4 > mb->len) {

	return 0;

    }

    return buffer_count_strings(&mb->data[mb->pos], mb->len - mb->pos, max);

}
