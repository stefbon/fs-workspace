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

#include <pwd.h>
#include <grp.h>

#include "logging.h"
#include "main.h"
#include "utils.h"

#include "workspace-interface.h"
#include "ssh-common.h"
#include "ssh-channel.h"
#include "ssh-utils.h"
#include "ssh-hostinfo.h"

#include "sftp-common-protocol.h"
#include "sftp-common.h"
#include "sftp-attr-common.h"
#include "sftp-protocol-v04.h"

static void get_local_uid_shared_v04(struct sftp_subsystem_s *sftp, struct sftp_user_s *user)
{
    struct sftp_usermapping_s *usermapping=&sftp->usermapping;
    struct passwd *pwd=NULL;
    char name[user->remote.name.len + 1];
    char *sep=NULL;

    user->local_uid=usermapping->local_unknown_uid;

    memcpy(name, user->remote.name.ptr, user->remote.name.len);
    name[user->remote.name.len]='\0';
    sep=memchr(name, '@', user->remote.name.len);
    if (sep) *sep='\0';

    pthread_mutex_lock(&usermapping->data.name_shared.pwd_mutex);

    pwd=getpwnam(name);
    if (pwd) user->local_uid=pwd->pw_uid;

    pthread_mutex_unlock(&usermapping->data.name_shared.pwd_mutex);

}

static void get_local_gid_shared_v04(struct sftp_subsystem_s *sftp, struct sftp_group_s *group)
{
    struct sftp_usermapping_s *usermapping=&sftp->usermapping;
    struct group *grp=NULL;
    char name[group->remote.name.len + 1];
    char *sep=NULL;

    group->local_gid=usermapping->local_unknown_gid;

    memcpy(name, group->remote.name.ptr, group->remote.name.len);
    name[group->remote.name.len]='\0';
    sep=memchr(name, '@', group->remote.name.len);
    if (sep) *sep='\0';

    pthread_mutex_lock(&usermapping->data.name_shared.gr_mutex);

    grp=getgrnam(name);
    if (grp) group->local_gid=grp->gr_gid;

    pthread_mutex_unlock(&usermapping->data.name_shared.gr_mutex);

}

static void get_local_uid_nonshared_v04(struct sftp_subsystem_s *sftp, struct sftp_user_s *user)
{
    struct ssh_session_s *session=sftp->channel.session;
    struct ssh_identity_s *identity=&session->identity;
    struct sftp_usermapping_s *usermapping=&sftp->usermapping;
    char name[user->remote.name.len + 1];
    char *sep=NULL;

    user->local_uid=usermapping->local_unknown_uid;

    memcpy(name, user->remote.name.ptr, user->remote.name.len);
    name[user->remote.name.len]='\0';

    sep=memchr(name, '@', user->remote.name.len);

    if (sep) {

	/* only look at the first part without the domain ... */

	*sep='\0';
	user->remote.name.len=(unsigned int) (sep - name);

    }

    if (user->remote.name.len==identity->remote_user.len && memcmp(name, identity->remote_user.ptr, user->remote.name.len)==0) {

	user->local_uid=session->identity.pwd.pw_uid;

    } else if (user->remote.name.len==4 && memcmp(name, "root", 4)==0) {

	user->local_uid=0;

    //} else if (user->remote.len==usermapping->data.name_nonshared.remote_user_nobody.len && memcmp(name, usermapping->data.name_nonshared.remote_user_nobody.ptr, usermapping->data.name_nonshared.remote_user_nobody.len)==0) {

	//user->local_uid=usermapping->local_uid_nobody;

    }

}

static void get_local_gid_nonshared_v04(struct sftp_subsystem_s *sftp, struct sftp_group_s *group)
{
    struct ssh_session_s *session=sftp->channel.session;
    struct ssh_hostinfo_s *hostinfo=&session->hostinfo;
    struct sftp_usermapping_s *usermapping=&sftp->usermapping;
    char name[group->remote.name.len + 1];
    char *sep=NULL;

    group->local_gid=usermapping->local_unknown_gid;

    memcpy(name, group->remote.name.ptr, group->remote.name.len);
    name[group->remote.name.len]='\0';

    sep=memchr(name, '@', group->remote.name.len);

    if (sep) {

	*sep='\0';
	group->remote.name.len=(unsigned int) (sep - name);

    }

    if (group->remote.name.len==usermapping->data.name_nonshared.remote_group.len && memcmp(name, usermapping->data.name_nonshared.remote_group.ptr, group->remote.name.len)==0) {

	group->local_gid=usermapping->data.name_nonshared.local_gid;

    } else if (group->remote.name.len==4 && memcmp(name, "root", 4)==0) {

	group->local_gid=0;

    // } else if (group->remote.len==usermapping->data.name_nonshared.remote_group_nobody.len && memcmp(name, usermapping->data.name_nonshared.remote_group_nobody.ptr, usermapping->data.name_nonshared.remote_group_nobody.len)==0) {

	//group->local_gid=usermapping->local_gid_nobody;

    }

}

static void get_remote_user_shared_v04(struct sftp_subsystem_s *sftp, struct sftp_user_s *user)
{
    struct sftp_usermapping_s *usermapping=&sftp->usermapping;
    struct passwd *pwd=NULL;

    pthread_mutex_lock(&usermapping->data.name_shared.pwd_mutex);

    pwd=getpwuid(user->local_uid);
    user->remote.name.len=strlen(pwd->pw_name);
    if (user->remote.name.ptr) memcpy(user->remote.name.ptr, pwd->pw_name, user->remote.name.len);

    pthread_mutex_unlock(&usermapping->data.name_shared.pwd_mutex);

}

static void get_remote_group_shared_v04(struct sftp_subsystem_s *sftp, struct sftp_group_s *group)
{
    struct sftp_usermapping_s *usermapping=&sftp->usermapping;
    struct group *grp=NULL;

    pthread_mutex_lock(&usermapping->data.name_shared.gr_mutex);

    grp=getgrgid(group->local_gid);
    group->remote.name.len=strlen(grp->gr_name);
    if (group->remote.name.ptr) memcpy(group->remote.name.ptr, grp->gr_name, group->remote.name.len);

    pthread_mutex_unlock(&usermapping->data.name_shared.gr_mutex);

}

static void get_remote_user_nonshared_v04(struct sftp_subsystem_s *sftp, struct sftp_user_s *user)
{
    struct ssh_session_s *session=sftp->channel.session;
    struct sftp_usermapping_s *usermapping=&sftp->usermapping;

    if (user->local_uid==session->identity.pwd.pw_uid) {
	struct ssh_identity_s *identity=&session->identity;

	user->remote.name.len=identity->remote_user.len;
	if (user->remote.name.ptr) memcpy(user->remote.name.ptr, identity->remote_user.ptr, identity->remote_user.len);

    } else if (user->local_uid==0) {

	user->remote.name.len=4;
	if (user->remote.name.ptr) memcpy(user->remote.name.ptr, "root", 4);

    //} else if (user->local_uid==usermapping->data.name_nonshared.remote_uid_nobody) {

	//user->remote.name.len=usermapping->data.name_nonshared.remote_user_nobody.len;
	//if(user->remote.name.ptr) memcpy(user->remote.name.ptr, usermapping->data.name_nonshared.remote_user_nobody.ptr, user->remote.name.len);

    } else {
	struct ssh_identity_s *identity=&session->identity;

	user->remote.name.len=identity->remote_user.len;
	if (user->remote.name.ptr) memcpy(user->remote.name.ptr, identity->remote_user.ptr, identity->remote_user.len);

    }

}

static void get_remote_group_nonshared_v04(struct sftp_subsystem_s *sftp, struct sftp_group_s *group)
{
    struct ssh_session_s *session=sftp->channel.session;
    struct sftp_usermapping_s *usermapping=&sftp->usermapping;

    if (group->local_gid==usermapping->data.name_nonshared.local_gid) {

	group->remote.name.len=usermapping->data.name_nonshared.remote_group.len;
	if (group->remote.name.ptr) memcpy(group->remote.name.ptr, usermapping->data.name_nonshared.remote_group.ptr, group->remote.name.len);

    } else if (group->local_gid==0) {

	group->remote.name.len=4;
	if (group->remote.name.ptr) memcpy(group->remote.name.ptr, "root", 4);

    //} else if (group->local_gid==usermapping->data.name_nonshared.remote_gid_nobody) {

	//group->remote.name.len=usermapping->data.name_nonshared.remote_group_nobody.len;
	//if(group->remote.name.ptr) memcpy(group->remote.name.ptr, usermapping->data.name_nonshared.remote_group_nobody.ptr, group->remote.name.len);

    } else {

	group->remote.name.len=usermapping->data.name_nonshared.remote_group.len;
	if (group->remote.name.ptr) memcpy(group->remote.name.ptr, usermapping->data.name_nonshared.remote_group.ptr, group->remote.name.len);

    }

}

void use_sftp_user_v04(struct sftp_subsystem_s *sftp_subsystem, unsigned char mapping)
{
    struct sftp_usermapping_s *usermapping=&sftp_subsystem->usermapping;

    if (mapping==_SFTP_USER_MAPPING_SHARED) {

	usermapping->get_local_uid=get_local_uid_shared_v04;
	usermapping->get_local_gid=get_local_gid_shared_v04;

	usermapping->get_remote_user=get_remote_user_shared_v04;
	usermapping->get_remote_group=get_remote_group_shared_v04;

    } else {

	usermapping->get_local_uid=get_local_uid_nonshared_v04;
	usermapping->get_local_gid=get_local_gid_nonshared_v04;

	usermapping->get_remote_user=get_remote_user_nonshared_v04;
	usermapping->get_remote_group=get_remote_group_nonshared_v04;

    }

}
