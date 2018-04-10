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

unsigned int check_add_generic(char *options, const char *name, struct commalist_s *clist)
{
    unsigned int error=0;

    if (options) {

	if (string_found_commalist(options, (char *) name)==0) return 0;

    }

    return add_name_to_commalist(name, clist, &error);

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
