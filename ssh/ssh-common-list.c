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

#include "main.h"

#include "utils.h"
#include "simple-hash.h"

#include "workspace-interface.h"

#include "ssh-common-protocol.h"
#include "ssh-common.h"
#include "ssh-utils.h"

static struct simple_hash_s group_ssh_sessions;
static uint64_t unique_sessions=0;

/* functions to lookup a ssh session using the unique number */

static unsigned int calculate_unique_hash(uint64_t unique)
{
    return unique % group_ssh_sessions.len;
}

static unsigned int unique_hashfunction(void *data)
{
    struct ssh_session_s *session=(struct ssh_session_s *) data;
    return calculate_unique_hash(session->status.unique);
}

struct ssh_session_s *lookup_ssh_session(uint64_t unique)
{
    unsigned int hashvalue=calculate_unique_hash(unique);
    void *index=NULL;
    struct ssh_session_s *session=(struct ssh_session_s *) get_next_hashed_value(&group_ssh_sessions, &index, hashvalue);

    while(session) {

	if (session->status.unique==unique) break;
	session=(struct ssh_session_s *) get_next_hashed_value(&group_ssh_sessions, &index, hashvalue);

    }

    return session;

}

void add_ssh_session_group(struct ssh_session_s *s)
{
    s->status.unique=unique_sessions;
    unique_sessions++;
    add_data_to_hash(&group_ssh_sessions, (void *) s);
}

void remove_ssh_session_group(struct ssh_session_s *s)
{
    remove_data_from_hash(&group_ssh_sessions, (void *) s);
}

void lock_group_ssh_sessions()
{
    writelock_hashtable(&group_ssh_sessions);
}

void unlock_group_ssh_sessions()
{
    unlock_hashtable(&group_ssh_sessions);
}

struct ssh_session_s *get_next_ssh_session(void **index, unsigned int *hashvalue)
{
    struct ssh_session_s *session=(struct ssh_session_s *) get_next_hashed_value(&group_ssh_sessions, index, *hashvalue);

    /* find every session */

    while(session==NULL && *hashvalue<group_ssh_sessions.len) {

	(*hashvalue)++;
	session=(struct ssh_session_s *) get_next_hashed_value(&group_ssh_sessions, index, *hashvalue);

    }

    return session;
}

int initialize_group_ssh_sessions(unsigned int *error)
{
    int result=0;

    /* create a hashtable with size 8 */

    result=initialize_group(&group_ssh_sessions, unique_hashfunction, 8, error);

    if (result<0) {

	*error=abs(result);
    	//logoutput("initialize_ssh_sessions: error %i:%s initializing hashtable ssh sessions", *error, strerror(*error));
	return -1;

    }

    return 0;

}

void free_group_ssh_sessions()
{
    free_group(&group_ssh_sessions, NULL);
}
