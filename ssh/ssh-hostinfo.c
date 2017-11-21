/*
  2010, 2011, 2012, 2103, 2014, 2015, 2016, 2017 Stef Bon <stefbon@gmail.com>

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

#include "pwd.h"
#include "grp.h"

#include "logging.h"
#include "main.h"

#include "utils.h"

#include "workspace-interface.h"
#include "ssh-common.h"
#include "ssh-utils.h"

#include "ctx-options.h"

/*
    functions to correct the difference in time between server and localhost
*/

static void correct_time_dummy(struct ssh_session_s *session, struct timespec *time)
{
    /* does nothing */
}

/* correct the time when difference is positive (other side is behind) */

static void correct_time_positive(struct ssh_session_s *session, struct timespec *time)
{
    struct ssh_hostinfo_s *hostinfo=&session->hostinfo;

    time->tv_nsec+=hostinfo->delta.tv_nsec;

    if (time->tv_nsec>1000000000) {

	time->tv_sec++;
	time->tv_nsec-=1000000000;

    }

    time->tv_sec+=hostinfo->delta.tv_sec;

}

/* correct the time when difference is negative (other side is ahead) */

static void correct_time_negative(struct ssh_session_s *session, struct timespec *time)
{
    struct ssh_hostinfo_s *hostinfo=&session->hostinfo;

    time->tv_nsec-=hostinfo->delta.tv_nsec;

    if (time->tv_nsec<0) {

	time->tv_sec+=1000000000;
	time->tv_nsec=-time->tv_nsec;

    }

    time->tv_sec-=hostinfo->delta.tv_sec;

}

void set_time_correction_server_behind(struct ssh_session_s *session, struct timespec *delta)
{
    struct ssh_hostinfo_s *hostinfo=&session->hostinfo;

    hostinfo->correct_time_s2c=correct_time_positive;
    hostinfo->correct_time_c2s=correct_time_negative;
    hostinfo->delta.tv_sec=delta->tv_sec;
    hostinfo->delta.tv_nsec=delta->tv_nsec;

}

void set_time_correction_server_ahead(struct ssh_session_s *session, struct timespec *delta)
{
    struct ssh_hostinfo_s *hostinfo=&session->hostinfo;

    hostinfo->correct_time_s2c=correct_time_negative;
    hostinfo->correct_time_c2s=correct_time_positive;
    hostinfo->delta.tv_sec=delta->tv_sec;
    hostinfo->delta.tv_nsec=delta->tv_nsec;

}

/* initialize the mapping of the local users to remote users */

void init_hostinfo(struct ssh_session_s *session)
{
    struct ssh_hostinfo_s *hostinfo=&session->hostinfo;

    /* correction function for differences in time */

    hostinfo->flags=0;
    hostinfo->delta.tv_sec=0;
    hostinfo->delta.tv_nsec=0;
    hostinfo->correct_time_s2c=correct_time_dummy;
    hostinfo->correct_time_c2s=correct_time_dummy;

}

void correct_time_s2c(struct ssh_session_s *session, struct timespec *time)
{
    struct ssh_hostinfo_s *hostinfo=&session->hostinfo;
    (* hostinfo->correct_time_s2c)(session, time);
}

void correct_time_c2s(struct ssh_session_s *session, struct timespec *time)
{
    struct ssh_hostinfo_s *hostinfo=&session->hostinfo;
    (* hostinfo->correct_time_c2s)(session, time);
}

/*
    this function will get the remote user to use to connect
    if there is a remote user set in the configuration
    for this server (for openssh in ~/.ssh/config)
*/

void free_hostinfo(struct ssh_session_s *ssh_session)
{
    struct ssh_hostinfo_s *hostinfo=&ssh_session->hostinfo;
    memset(hostinfo, 0, sizeof(struct ssh_hostinfo_s));

}

/*
    after receiving time from server calculate the time difference to apply to time related messages */

void set_time_delta(struct ssh_session_s *session, struct timespec *send, struct timespec *recv, struct timespec *output)
{
    struct timespec delta;
    double send_d=send->tv_sec + ((double) send->tv_nsec ) / 1000000000;
    double recv_d=recv->tv_sec + ((double) recv->tv_nsec ) / 1000000000;
    double output_d=output->tv_sec + ((double) output->tv_nsec ) / 1000000000;
    double delta_d=0;

    delta_d=((recv_d + send_d ) / 2 ) - output_d;

    logoutput("set_time_delta: out %.3f send %.3f recv %.3f delta %.3f", output_d, send_d, recv_d, delta_d);

    if (delta_d>0) {

	/* server is behind */

	delta.tv_sec=(time_t) delta_d;
	delta.tv_nsec=(long) ((delta_d - delta.tv_sec) * 1000000000);

	set_time_correction_server_behind(session, &delta);

    } else if (delta_d<0) {

	/* server is ahead */

	delta_d=abs(delta_d);

	delta.tv_sec=(time_t) delta_d;
	delta.tv_nsec=(long) ((delta_d - delta.tv_sec) * 1000000000);

	set_time_correction_server_ahead(session, &delta);

    }

}
