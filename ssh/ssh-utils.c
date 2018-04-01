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
#include <glib.h>

#include "logging.h"
#include "main.h"
#include "utils.h"
#include "workspace-interface.h"

#include "ssh-common.h"
#include "ssh-utils.h"
#include "ssh-utils-libgcrypt.h"

extern int initialize_group_ssh_sessions(unsigned int *error);
extern void free_group_ssh_sessions();

static struct ssh_utils_s utils;
static unsigned char done=0;

/* host specific n to h */

/* little endian */

uint64_t ntohll_le(uint64_t nvalue)
{
    return ( (((uint64_t)ntohl(nvalue))<<32) + ntohl(nvalue >> 32) );
}

/* big endian */

uint64_t ntohll_be(uint64_t nvalue)
{
    return nvalue;
}

/* append name to a commalist */

unsigned int add_name_to_commalist(const char *name, struct commalist_s *clist, unsigned int *error)
{
    unsigned int lenname=strlen(name);

    if (! clist) return lenname + 1;

    if (clist->len + lenname + 1 > clist->size) {

	*error=ENAMETOOLONG;
	logoutput("add_name_to_commalist: add %s failed: list too short %i + %i + 1 > %i", name, clist->len, lenname, clist->size);

    } else {

	/* does fit in the buffer */

	if (clist->len==0) {

	    memcpy(clist->list, name, lenname);
	    clist->len += lenname;
	    return lenname;

	} else {

	    *(clist->list + clist->len)=','; /* replace the trailing zero with a comma */
	    memcpy(clist->list + clist->len + 1, name, lenname);
	    clist->len += lenname+1;
	    return lenname+1;

	}

    }

    return 0;

}

void free_list_commalist(struct commalist_s *clist)
{

    if (clist->list) {

	free(clist->list);
	clist->list=NULL;

    }

    clist->size=0;
    clist->len=0;

}

unsigned char string_found_commalist(char *commalist, char *name)
{
    char *pos=commalist;

    search:

    pos=strstr(pos, name);

    if (! pos) {

	/* not found */

	return 0;

    } else {
	char *seek=strchr(pos+1, ',');

	/* found, look for next comma */

	if (seek) {

	    *seek='\0';

	    if (strcmp(pos, name)==0) {

		/* found */

		*seek=',';
		return 1;

	    } else {

		/* only partial match */

		*seek=',';
		pos=seek+1;
		goto search;

	    }

	} else {

	    if (strcmp(pos, name)==0) {

		/* found */

		return 1;

	    } else {

		return 0;

	    }

	}

    }

    return 0;

}

unsigned int check_add_generic(char *options, const char *name, struct commalist_s *clist)
{
    unsigned int error=0;

    if (options) {

	if (string_found_commalist(options, (char *) name)==0) return 0;

    }

    return add_name_to_commalist(name, clist, &error);

    return 0;

}

int init_sshlibrary()
{
    unsigned int endian_test=1;
    unsigned int error=0;

    if (done==0) {

	/* determine the ntohll function to use for this host (big or litlle endian) */

	if (*((char *) &endian_test) == 1) {

	    /* little endian */

	    utils.ntohll=ntohll_le;

	} else {

	    /* big endian */

	    utils.ntohll=ntohll_be;

	}

	init_sshutils_libgcrypt(&utils);

	if (initialize_group_ssh_sessions(&error)==-1) {

	    logoutput("init_sshlibrary: failed to initialize hash table for sessions");
	    return -1;

	}

	done=1;

    }

    return (* utils.init_library)(&error);

}

void end_sshlibrary()
{
    free_group_ssh_sessions();
}

void store_uint32(char *buff, uint32_t value)
{
    unsigned char *tmp=(unsigned char *) buff;

    tmp[0] = (value >> 24) & 0xFF;
    tmp[1] = (value >> 16) & 0xFF;
    tmp[2] = (value >> 8) & 0xFF;
    tmp[3] = value & 0xFF;

}

void store_uint64(unsigned char *buff, uint64_t value)
{
    buff[0] = (value >> 56) & 0xFF;
    buff[1] = (value >> 48) & 0xFF;
    buff[2] = (value >> 40) & 0xFF;
    buff[3] = (value >> 32) & 0xFF;
    buff[4] = (value >> 24) & 0xFF;
    buff[5] = (value >> 16) & 0xFF;
    buff[6] = (value >> 8) & 0xFF;
    buff[7] = value & 0xFF;

}

unsigned int store_ssh_string(char *buff, struct ssh_string_s *string)
{
    if (buff) {
	store_uint32(buff, string->len);
	memcpy(buff+4, string->ptr, string->len);
    }
    return string->len + 4;
}

uint32_t get_uint32(char *buf)
{
    unsigned char *tmp=(unsigned char *) buf;
    return (uint32_t) (((uint32_t) tmp[0] << 24) | ((uint32_t) tmp[1] << 16) | ((uint32_t) tmp[2] << 8) | (uint32_t) tmp[3]);
}

uint16_t get_uint16(unsigned char *buf)
{
    return (uint16_t) ((buf[0] << 8) | buf[1]);
}

uint64_t get_uint64(unsigned char *buf)
{
    uint64_t a;
    uint32_t b;

    a = (uint64_t) (((uint64_t) buf[0] << 56) | ((uint64_t) buf[1] << 48) | ((uint64_t) buf[2] << 40) | ((uint64_t) buf[3] << 32));
    b = (uint32_t) (((uint32_t) buf[4] << 24) | ((uint32_t) buf[5] << 16) | ((uint32_t) buf[6] << 8) | (uint32_t) buf[7]);

    return (uint64_t)(a | b);
}

uint64_t get_int64(unsigned char *buf)
{
    uint64_t a;
    uint32_t b;

    a = (uint64_t) (((uint64_t) buf[0] << 56) | ((uint64_t) buf[1] << 48) | ((uint64_t) buf[2] << 40) | ((uint64_t) buf[3] << 32));
    b = (uint32_t) (((uint32_t) buf[4] << 24) | ((uint32_t) buf[5] << 16) | ((uint32_t) buf[6] << 8) | ((uint32_t) buf[7]));

    return (int64_t)(a | b);
}

unsigned int hash(const char *name, struct common_buffer_s *in, struct ssh_string_s *out, unsigned int *error)
{
    return (* utils.hash)(name, in, out, error);
}

unsigned int get_digest_len(const char *name)
{
    return (* utils.get_digest_len)(name);
}

uint64_t ntohll(uint64_t value)
{
    return (* utils.ntohll)(value);
}

unsigned int fill_random(char *pos, unsigned int len)
{
    return (* utils.fill_random)(pos, len);
}

unsigned char isvalid_ipv4(char *address)
{
    struct in_addr tmp_addr;

    if (inet_pton(AF_INET, address, &tmp_addr)==1) return 1;

    return 0;

}

void replace_cntrl_char(char *buffer, unsigned int size)
{
    for (unsigned int i=0; i<size; i++) {

	if (iscntrl(buffer[i])) {

	    buffer[i]=' ';

	}

    }
}

void replace_newline_char(char *ptr, unsigned int *size)
{
    char *sep=NULL;
    unsigned int tmp=*size;

    // logoutput("replace_newline_char: prev %i", tmp);

    sep=memchr(ptr, 13, tmp);

    if (sep) {

	*sep='\0';
	tmp=(unsigned int) (sep - ptr);

	// logoutput("replace_newline_char: new %i", tmp);
	*size=tmp;

    }

}

char *decode_base64(struct common_buffer_s *buffer, unsigned int *len)
{
    unsigned int left=(unsigned int)(buffer->ptr + buffer->len - buffer->pos);
    gsize size=0;
    char tmp[left + 1];
    guchar *decoded=NULL;

    *len=0;

    memcpy(tmp, buffer->pos, left);
    tmp[left]='\0';

    decoded=g_base64_decode(tmp, &size);
    *len=(unsigned int) size;

    return (char *) decoded;
}

int compare_encoded_base64(char *encoded, struct common_buffer_s *buffer)
{
    unsigned int len=strlen(encoded);
    char tmp[len+1];
    gsize size=0;

    memcpy(tmp, encoded, len);
    tmp[len]='\0';

    g_base64_decode_inplace((gchar *)tmp, &size);

    if (size==buffer->size && strcmp(buffer->ptr, tmp)==0) return 0;

    return -1;

}

unsigned int copy_ssh_string_to_buffer(struct common_buffer_s *b, struct ssh_string_s *s)
{

    if (b && b->pos) {

	store_uint32(b->pos, s->len);
	b->pos+=4;
	memcpy(b->pos, s->ptr, s->len);
	b->pos+=s->len;

    }

    return (unsigned int) (4 + s->len);
}

unsigned int copy_buffer_to_buffer(struct common_buffer_s *b, struct common_buffer_s *s)
{

    if (b && b->pos) {

	store_uint32(b->pos, s->len);
	b->pos+=4;
	memcpy(b->pos, s->ptr, s->len);
	b->pos+=s->len;

    }

    return (4 + s->len);
}

unsigned int copy_char_to_buffer(struct common_buffer_s *b, char *s, unsigned int len)
{

    if (b && b->pos) {

	store_uint32(b->pos, len);
	b->pos+=4;
	memcpy(b->pos, s, len);
	b->pos+=len;

    }

    return (4 + len);
}

unsigned int copy_byte_to_buffer(struct common_buffer_s *b, unsigned char s)
{

    if (b && b->pos) {

	*(b->pos)=s;
	b->pos++;

    }

    return 1;
}

