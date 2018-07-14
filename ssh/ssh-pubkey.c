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

void init_ssh_pubkey(struct ssh_session_s *session)
{
    struct ssh_pubkey_s *pubkey=&session->pubkey;

    pubkey->ids_pkalgo=0;
    pubkey->ids_pksign=0;

}

/* build a bitwise number of pkalgo's used in this session/per keyexchange */

static void build_pubkey_list(char *list_c, char *list_s, struct ssh_pubkey_s *pubkey)
{
    char *c_name=NULL, *c_sep=NULL;
    unsigned int size=0;

    /* find the common pk methods by starting at the client list and test the name is also on the server list */

    c_name=list_c;

    search:

    c_sep=strchr(c_name+1, ',');
    if (c_sep) {
	unsigned int len=(unsigned int)(c_sep - c_name + 1);

	/* if algo on client list is also found on server list enable the bit */

	if (memmem(list_s, strlen(list_s), c_name, len)) {
	    int index=0;
	    struct ssh_pkalgo_s *pkalgo=NULL;

	    *c_sep='\0';
	    pkalgo=get_pkalgo(c_name + 1, len-2, &index);

	    if (pkalgo) {

		pubkey->ids_pkalgo |= (1 << (index - 1));
		logoutput("build_pubkey_list: found %s", c_name + 1);

	    }

	    *c_sep=',';

	}

	c_name=c_sep;
	goto search;

    }

}

void store_algo_pubkey_negotiation(struct ssh_session_s *session, struct ssh_string_s *clist_c, struct ssh_string_s *clist_s)
{
    char list_c[clist_c->len+3];
    char list_s[clist_s->len+3];

    logoutput("store_algo_pubkey_negotiation");

    if (clist_c->len==0 || clist_c->ptr==NULL || clist_s->len==0 || clist_c->ptr==NULL) {

	session->pubkey.ids_pkalgo=0;
	return;

    }

    /* create lists starting with a comma */

    list_c[0]=',';
    memcpy(&list_c[1], clist_c->ptr, clist_c->len);
    list_c[clist_c->len+1]=',';
    list_c[clist_c->len+2]='\0';
    list_s[0]=',';
    memcpy(&list_s[1], clist_s->ptr, clist_s->len);
    list_s[clist_s->len+1]=',';
    list_s[clist_s->len+2]='\0';

    build_pubkey_list(list_c, list_s, &session->pubkey);

}

/* find the name in the pubkey commalist
    this commalist is like:
    ,first-name,second-name,third-name,
    name is zero terminated */

int find_pubkey_negotiation(struct ssh_session_s *session, char *name)
{
    struct ssh_pubkey_s *pubkey=&session->pubkey;

    if (pubkey->ids_pkalgo>0) {
	int index=0;
	struct ssh_pkalgo_s *pkalgo=NULL;

	pkalgo=get_pkalgo(name, strlen(name), &index);

	if (pkalgo && (pubkey->ids_pkalgo & (1 << (index - 1)))) return index;

    }

    return -1;

}

void free_ssh_pubkey(struct ssh_session_s *session)
{
    struct ssh_pubkey_s *pubkey=&session->pubkey;

    pubkey->ids_pkalgo=0;
    pubkey->ids_pksign=0;

}
