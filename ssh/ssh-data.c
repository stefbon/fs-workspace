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
#include "beventloop.h"

#include "utils.h"

#include "ssh-common.h"
#include "ssh-utils.h"

int store_ssh_session_id(struct ssh_session_s *session, struct ssh_string_s *H)
{
    return create_copy_ssh_string(&session->data.sessionid, H);
}

void init_session_data(struct ssh_session_s *session)
{
    struct session_data_s *data=&session->data;

    memset(data, 0, sizeof(struct session_data_s));
    data->remote_version_major=0;
    data->remote_version_minor=0;
    init_ssh_string(&data->sessionid);
    init_ssh_string(&data->greeter_server);
    init_ssh_string(&data->greeter_client);
}

void free_session_data(struct ssh_session_s *session)
{
    struct session_data_s *data=&session->data;

    free_ssh_string(&data->sessionid);
    free_ssh_string(&data->greeter_server);
    free_ssh_string(&data->greeter_client);
}
