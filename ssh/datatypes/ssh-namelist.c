/*
  2018 Stef Bon <stefbon@gmail.com>

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

#include "logging.h"

#include "ssh-namelist.h"

/* append name to a commalist */

unsigned int add_name_to_commalist(const char *name, struct commalist_s *clist, unsigned int *error)
{
    unsigned int lenname=strlen(name);

    if (! clist) return lenname + 1;

    if (clist->len + lenname + 1 > clist->size) {

	if (error) *error=ENAMETOOLONG;
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

unsigned char string_found_commalist(char *list, char *name)
{
    unsigned int lenlist = strlen(list);
    char tmp[lenlist + 3];
    unsigned int len = strlen(name);
    char dummy[len + 3];

    /* create a tmp list to add a first and last comma: searching gets easier that way */

    tmp[0] = ',';
    memcpy(&tmp[1], list, lenlist);
    tmp[lenlist + 1] = ',';
    tmp[lenlist + 2] = '\0';

    /* add comma's */

    dummy[0] = ',';
    memcpy(&dummy[1], name, len);
    dummy[len+1] = ',';
    dummy[len+2] = '\0';

    return (strstr(tmp, dummy) ? 1 : 0);

}

unsigned char name_found_namelist(struct commalist_s *clist, char *name)
{

    if (clist->len>0) {
	char tmp[clist->len + 1];

	memcpy(tmp, clist->list, clist->len);
	tmp[clist->len] = '\0';

	return string_found_commalist(tmp, name);

    }

    return 0;
}