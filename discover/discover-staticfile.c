/*
 
  2017 Stef Bon <stefbon@gmail.com>

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

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <err.h>
#include <string.h>
#include <errno.h>
#include <err.h>
#include <sys/time.h>
#include <time.h>
#include <ctype.h>
#include <inttypes.h>

#include <sys/param.h>
#include <sys/types.h>

#define LOGGING
#include "logging.h"
#include "utils.h"

#include "ssh/ssh-utils.h"
#include "discover.h"

extern void add_net_service_staticfile(const char *type, char *hostname, char *ipv4, unsigned int port);

void browse_services_staticfile(char *file)
{
    FILE *fp=NULL;
    char *line=NULL;
    size_t size=0;
    char *start=NULL;
    char *sep=NULL;
    unsigned int len=0;
    char *type=NULL;
    char *hostname=NULL;
    unsigned int port=0;
    char *ipv4=NULL;

    fp=fopen(file, "r");
    if (fp==NULL) {

	logoutput("browse_services_staticfile: error %i when trying to open file %s (%s)", errno, file, strerror(errno));
	return;

    }

    while (getline(&line, &size, fp)>0) {

	/* format type,hostname,port,ipv4 */

	len=(unsigned int) size;
	sep=memchr(line, '\n', len);
	if (sep) {

	    *sep='\0';
	    len=strlen(line);

	}

	if (len==0) continue;
	replace_cntrl_char(line, len, REPLACE_CNTRL_FLAG_TEXT);
	if (line[0] == '#' || line[0] == '|') continue;
	start=line;

	type=NULL;
	hostname=NULL;
	port=0;
	ipv4=NULL;

	sep=memchr(start, ' ', len);

	if (sep) {

	    /* type */

	    type=start;
	    *sep='\0';
	    start=sep+1;

	} else {

	    continue;

	}

	sep=memchr(start, ' ', len);

	if (sep) {

	    /* hostname */

	    hostname=start;
	    *sep='\0';
	    start=sep+1;

	} else {

	    continue;

	}

	sep=memchr(start, ' ', len);

	if (sep) {

	    /* port */

	    *sep='\0';
	    port=atoi(start);
	    start=sep+1;

	} else {

	    continue;

	}

	sep=memchr(start, ' ', len);

	if (sep) {

	    /* ipv4 (optional) */

	    ipv4=start;
	    *sep='\0';
	    start=sep+1;

	}

	add_net_service_generic(type, hostname, ipv4, port, DISCOVER_METHOD_STATICFILE);

    }

    if (line) {

	free(line);
	line=NULL;

    }
    fclose(fp);

}
