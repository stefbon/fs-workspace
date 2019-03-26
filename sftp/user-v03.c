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
#include "ssh-channel.h"
#include "ssh-hostinfo.h"
#include "ssh-utils.h"

#include "common-protocol.h"
#include "common.h"
#include "protocol-v03.h"
#include "attr-common.h"

static pthread_mutex_t pwd_mutex=PTHREAD_MUTEX_INITIALIZER;
static pthread_mutex_t grp_mutex=PTHREAD_MUTEX_INITIALIZER;

static void get_local_uid_shared_v03(struct sftp_subsystem_s *sftp, struct sftp_user_s *user)
{
    if (user->remote.name.ptr) {
	struct sftp_usermapping_s *usermapping=&sftp->usermapping;
	char name[user->remote.name.len + 1];
	struct passwd *pwd=NULL;

	user->local_uid=usermapping->local_unknown_uid;

	memcpy(name, user->remote.name.ptr, user->remote.name.len);
	name[user->remote.name.len]='\0';

	pthread_mutex_lock(&pwd_mutex);

	pwd=getpwnam(name);
	if (pwd) user->local_uid=pwd->pw_uid;

	pthread_mutex_unlock(&pwd_mutex);

    } else {

	user->local_uid=user->remote.id;

    }
}

static void get_local_uid_nonshared_v03(struct sftp_subsystem_s *sftp, struct sftp_user_s *user)
{
    struct sftp_usermapping_s *usermapping=&sftp->usermapping;

    user->local_uid=usermapping->local_unknown_uid;

    if (user->remote.id==usermapping->data.id_nonshared.remote_uid) {
	struct ssh_session_s *session=sftp->channel.session;

	user->local_uid=session->identity.pwd.pw_uid;

    } else if (user->remote.id==0) {

	user->local_uid=0;

    //} else if (user->remote.id==usermapping->data.id_nonshared.remote_uid_nobody) {

	//user->local_uid=usermapping->data.id_nonshared.local_uid_nobody;

    }

}

static void get_local_gid_shared_v03(struct sftp_subsystem_s *sftp, struct sftp_group_s *group)
{
    if (group->remote.name.ptr) {
	struct sftp_usermapping_s *usermapping=&sftp->usermapping;
	char name[group->remote.name.len + 1];
	struct group *grp=NULL;

	group->local_gid=usermapping->local_unknown_gid;

	memcpy(name, group->remote.name.ptr, group->remote.name.len);
	name[group->remote.name.len]='\0';

	pthread_mutex_lock(&grp_mutex);

	grp=getgrnam(name);
	if (grp) group->local_gid=grp->gr_gid;

	pthread_mutex_unlock(&grp_mutex);

    } else {

	group->local_gid=group->remote.id;

    }
}

static void get_local_gid_nonshared_v03(struct sftp_subsystem_s *sftp, struct sftp_group_s *group)
{
    struct sftp_usermapping_s *usermapping=&sftp->usermapping;
    struct ssh_session_s *session=sftp->channel.session;
    struct ssh_hostinfo_s *hostinfo=&session->hostinfo;

    group->local_gid=usermapping->local_unknown_gid;

    if (group->remote.id==usermapping->data.id_nonshared.remote_gid) {

	group->local_gid=usermapping->data.id_nonshared.local_gid;

    } else if (group->remote.id==0) {

	group->local_gid=0;

    //} else if (gid==usermapping->mapping.id_nonshared.remote_gid_nobody) {

	//group->local_gid=usermapping->mapping.id_nonshared.local_gid_nobody;

    }

}

static void get_remote_user_shared_v03(struct sftp_subsystem_s *sftp, struct sftp_user_s *user)
{
    user->remote.id=user->local_uid;
}

static void get_remote_user_nonshared_v03(struct sftp_subsystem_s *sftp, struct sftp_user_s *user)
{
    struct sftp_usermapping_s *usermapping=&sftp->usermapping;
    struct ssh_session_s *session=sftp->channel.session;
    struct ssh_hostinfo_s *hostinfo=&session->hostinfo;

    user->remote.id=0;

    if (user->local_uid==0) {

	user->remote.id=0;

    } else if (user->local_uid==session->identity.pwd.pw_uid) {

	user->remote.id=usermapping->data.id_nonshared.remote_uid;


    //} else if (user->local_uid==usermapping->data.id_nonshared.local_uid_nobody) {

	//user->remote.id=usermapping->data.id_nonshared.remote_uid_nobody

    }

}

static void get_remote_group_shared_v03(struct sftp_subsystem_s *sftp, struct sftp_group_s *group)
{
    group->remote.id=group->local_gid;
}

static void get_remote_group_nonshared_v03(struct sftp_subsystem_s *sftp, struct sftp_group_s *group)
{
    struct sftp_usermapping_s *usermapping=&sftp->usermapping;
    struct ssh_session_s *session=sftp->channel.session;
    struct ssh_hostinfo_s *hostinfo=&session->hostinfo;

    if (group->local_gid==0) {

	group->remote.id=0;

    } else if (group->local_gid==usermapping->data.id_nonshared.local_gid) {

	group->remote.id=usermapping->data.id_nonshared.remote_gid;

    //} else if (group->local_gid==usermapping->data.id_nonshared.local_gid_nobody) {

	//group->remote.id=usermapping->data.id_nonshared.remote_gid_nobody

    }

    /* more id's ? */

}

void use_sftp_user_v03(struct sftp_subsystem_s *sftp_subsystem, unsigned char mapping)
{
    struct sftp_usermapping_s *usermapping=&sftp_subsystem->usermapping;

    if (mapping==_SFTP_USER_MAPPING_SHARED) {

	usermapping->get_local_uid=get_local_uid_shared_v03;
	usermapping->get_local_gid=get_local_gid_shared_v03;

	usermapping->get_remote_user=get_remote_user_shared_v03;
	usermapping->get_remote_group=get_remote_group_shared_v03;

    } else {

	usermapping->get_local_uid=get_local_uid_nonshared_v03;
	usermapping->get_local_gid=get_local_gid_nonshared_v03;

	usermapping->get_remote_user=get_remote_user_nonshared_v03;
	usermapping->get_remote_group=get_remote_group_nonshared_v03;

    }

}
