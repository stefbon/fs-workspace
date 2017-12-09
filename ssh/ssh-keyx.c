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

#include "ssh-common.h"
#include "ssh-utils.h"
#include "ssh-keyx.h"
#include "ssh-keyx-dh.h"

#include "ctx-options.h"

static int start_keyx_dummy(struct ssh_session_s *session, struct ssh_keyx_s *keyx, struct ssh_kexinit_algo *algos)
{
    return 0;
}

static void free_keyx_dummy(struct ssh_keyx_s *keyx)
{
}

int start_keyx(struct ssh_session_s *session, struct ssh_keyx_s *keyx, struct ssh_kexinit_algo *algos)
{
    return (* keyx->start_keyx)(session, keyx, algos);
}

void free_keyx(struct ssh_keyx_s *keyx)
{
    (* keyx->free)(keyx);
}

void init_keyx(struct ssh_keyx_s *keyx)
{

    memset(keyx, 0, sizeof(struct ssh_keyx_s));
    memset(keyx->digestname, '\0', sizeof(keyx->digestname));
    keyx->type_hostkey=0;

    keyx->start_keyx=start_keyx_dummy;
    keyx->free=free_keyx_dummy;

}

int set_keyx(struct ssh_keyx_s *keyx, const char *name, const char *keyname, unsigned int *error)
{

    /*
	TODO
	20160907: for now only "simple" diffie hellmans are supported
	(and none)
    */

    keyx->type_hostkey=get_pubkey_type((unsigned char *) keyname, strlen(keyname));

    if (keyx->type_hostkey==0) {

	*error=EINVAL;
	return -1;

    }

    if (strcmp(name, "diffie-hellman-group1-sha1")==0 || strcmp(name, "diffie-hellman-group14-sha1")==0) {

	return set_keyx_dh(keyx, name, error);

    } else if (strcmp(name, "none") == 0) {

	logoutput_warning("init_keyx: error none as key exchange method");

    } else {

	logoutput_warning("init_keyx: key exchange method %s not reckognized", name);
	*error=EINVAL;
	return -1;

    }

    return 0;

}

/* get a list of supported key exchange algo's like diffie-hellman */

unsigned int check_add_keyxname(const char *name, struct commalist_s *clist)
{
    return check_add_generic(get_ssh_options("keyx"), name, clist);
}

unsigned int ssh_get_keyx_list(struct commalist_s *clist)
{
    unsigned int len=0;

    len+=check_add_keyxname("diffie-hellman-group1-sha1", clist);
    len+=check_add_keyxname("diffie-hellman-group14-sha1", clist);

    return len;
}
