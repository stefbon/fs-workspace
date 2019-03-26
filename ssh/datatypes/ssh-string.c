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

void init_ssh_string(struct ssh_string_s *s)
{
    s->ptr=NULL;
    s->len=0;
}

void free_ssh_string(struct ssh_string_s *s)
{
    if (s->ptr) {

	free(s->ptr);
	s->ptr=NULL;

    }

    init_ssh_string(s);
}

unsigned int create_ssh_string(struct ssh_string_s *s, unsigned int len)
{
    s->ptr=malloc(len);
    if (s->ptr) return len;

    return 0;
}

unsigned int get_ssh_string_length(struct ssh_string_s *s, unsigned int flags)
{
    unsigned int len=0;

    if (flags & SSH_STRING_FLAG_HEADER) len+=4;
    if (flags & SSH_STRING_FLAG_DATA) len+=s->len;
    return len;
}

unsigned int read_ssh_string_header(char *buffer, unsigned int size, unsigned int *len)
{

    if (size >= 4) {

	if (len) *len=get_uint32(buffer);
	return 4;

    }

    return 0;

}

unsigned int write_ssh_string_header(char *buffer, unsigned int size, unsigned int len)
{

    if (size >= 4 + len) {

	store_uint32(buffer, len);
	return 4;
    }

    return 0;
}

unsigned int read_ssh_string(char *buffer, unsigned int size, struct ssh_string_s *s)
{
    struct ssh_string_s dummy;

    if (s==NULL) s=&dummy;

    s->len=0;
    s->ptr=NULL;

    if (size >= 4) {

	s->len=get_uint32(buffer);

	if (size >= 4 + s->len) {

	    s->ptr=(char *) (buffer + 4);
	    return (4 + s->len);

	}

    }

    return 0;

}

int get_ssh_string_from_buffer(char **b, unsigned int size, struct ssh_string_s *s)
{
    char *pos = *b;

    if (size > 4) {

	s->len=get_uint32(pos);
	pos+=4;
	size-=4;

    } else {

	/* buffer is not large enough */
	return -1;

    }

    if (s->len <= size) {

	if (create_ssh_string(s, s->len)>0) {

	    memcpy(s->ptr, pos, s->len);
	    pos+=s->len;

	} else {

	    /* allocation problem */
	    return -1;

	}

    } else {

	/* not enough data in buffer */
	return -1;

    }

    *b=pos;

    return (4 + s->len);

}

unsigned int write_ssh_string(char *buffer, unsigned int size, const unsigned char type, void *ptr)
{
    char *pos=NULL;

    switch (type) {

    case 's' : {
	struct ssh_string_s *s=(struct ssh_string_s *) ptr;

	if (buffer) {
	    char *pos=buffer;

	    store_uint32(pos, s->len);
	    pos+=4;
	    memcpy(pos, s->ptr, s->len);

	}

	return (4 + s->len);
	break;
    }
    case 'c' : {
	char *data=(char *) ptr;
	unsigned int len=strlen(data);

	if (buffer) {
	    char *pos=buffer;

	    store_uint32(pos, len);
	    pos+=4;
	    memcpy(pos, data, len);

	}

	return (4 + len);
	break;
    }
    case 'l' : {
	unsigned int len=(ptr) ? *((unsigned int *) ptr) : 0;

	if (buffer) store_uint32(buffer, len);
	return 4;
    }
    default :

	break;

    }

    return 0;

}

void move_ssh_string(struct ssh_string_s *a, struct ssh_string_s *b)
{
    a->ptr=b->ptr;
    a->len=b->len;
    b->ptr=NULL;
    b->len=0;
}

int ssh_string_compare(struct ssh_string_s *s, const unsigned char type, void *ptr)
{

    switch (type) {

    case 's' : {
	struct ssh_string_s *t=(struct ssh_string_s *) ptr;

	if (s->len==0 && t->len==0) {

	    return 0;

	} else if (s->len==t->len) {

	    return strncmp(s->ptr, t->ptr, s->len);

	}

	return -1;
    }
    case 'c' : {
	char *data=(char *) ptr;
	unsigned int len=strlen(data);

	if (s->len==0 && len==0) {

	    return 0;

	} else if (s->len==len) {

	    return strncmp(s->ptr, data, len);

	}

	return -1;
    }
    }

    return -1;

}

unsigned int buffer_count_strings(char *buffer, unsigned int size, unsigned int max)
{
    unsigned int count=0;
    unsigned int pos=0;
    unsigned int len=0;

    readstring:

    len=get_uint32(&buffer[pos]);

    if (pos + 4 + len <= size) {

	pos += 4 + len;
	count++;
	if (max>0 && count==max) goto out;
	if (pos < size) goto readstring;

    }

    out:

    return count;

}
