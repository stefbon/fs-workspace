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
#include <errno.h>
#include <err.h>
#include <sys/time.h>
#include <time.h>
#include <ctype.h>
#include <inttypes.h>

#include <sys/param.h>
#include <sys/types.h>

#ifdef HAVE_LIBGCRYPT
#include <gcrypt.h>
#endif

#include "logging.h"
#include "main.h"
#include "utils.h"

#include "ssh-common.h"
#include "ssh-utils.h"

#include "ctx-options.h"

static unsigned int check_add_pubkeyname(const char *name, struct commalist_s *clist)
{
    return check_add_generic(get_ssh_options("pubkey"), name, clist);
}

#ifdef HAVE_LIBGCRYPT

static int test_pubkey_algo(const char *name)
{
    int result=-1;
    int algo=0;

    if (strncmp(name, "ssh-", 4)==0) {

	algo=gcry_pk_map_name((const char *)(name + 4));

    } else {

	algo=gcry_pk_map_name(name);

    }

    if (algo>0) {

	if (gcry_pk_test_algo(algo)==0) result=0;

    }

    logoutput("test_pubkey_algo: test %s result %i", name, result);

    return result;

}

#else

static int test_pubkey_algo(const char *name)
{
    return -1;
}

#endif

unsigned int ssh_get_pubkey_list(struct commalist_s *clist)
{
    unsigned int len=0;

    if (test_pubkey_algo("ssh-rsa")==0) len+=check_add_pubkeyname("ssh-rsa", clist);
    if (test_pubkey_algo("ssh-dss")==0) len+=check_add_pubkeyname("ssh-dss", clist);

    /* add ssh-ed25519 ... */

    return len;

}
