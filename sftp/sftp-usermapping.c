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

#include <pwd.h>
#include <grp.h>

#include "logging.h"
#include "main.h"
#include "utils.h"

#include "workerthreads.h"
#include "workspace-interface.h"

#include "ssh-common-protocol.h"
#include "ssh-common.h"
#include "ssh-common-list.h"
#include "ssh-channel.h"

#include "ssh-hostinfo.h"
#include "ssh-utils.h"

#include "sftp-common-protocol.h"
#include "sftp-common.h"
#include "sftp-common-admin.h"
#include "sftp-user-v03.h"
#include "sftp-user-v04.h"

/*
    get the uid and gid of the unknown user and group
    uid and gid of the remote host which are not reckognized
    (== not the connecting user/group, not root and not nobody...)
    get this uid/gid
*/

static void get_local_unknown(struct context_interface_s *interface, struct sftp_usermapping_s *usermapping)
{
    struct passwd *pwd=NULL;
    char *user=NULL;
    struct context_option_s option;

    usermapping->local_unknown_uid=(uid_t) -1;
    usermapping->local_unknown_gid=(gid_t) -1;

    memset(&option, 0, sizeof(struct context_option_s));

    if ((* interface->get_interface_option)(interface, "option:sftp.usermapping.user-unknown", &option)==_INTERFACE_OPTION_PCHAR) {

	user=option.value.ptr;

    }

    if (user) {

	pwd=getpwnam(user);

    } else {

	pwd=getpwnam("unknown");

    }

    if (pwd) {

	usermapping->local_unknown_uid=pwd->pw_uid;
	usermapping->local_unknown_gid=pwd->pw_gid;
	return;

    }

    /* take nobody */

    user=NULL;

    memset(&option, 0, sizeof(struct context_option_s));

    if ((* interface->get_interface_option)(interface, "option:sftp.usermapping.user-nobody", &option)==_INTERFACE_OPTION_PCHAR) {

	user=option.value.ptr;

    }

    if (user) {

	pwd=getpwnam(user);

    } else {

	pwd=getpwnam("nobody");

    }

    if (pwd) {

	usermapping->local_unknown_uid=pwd->pw_uid;
	usermapping->local_unknown_gid=pwd->pw_gid;

    }

}

static void get_remote_sftp_userinfo(struct sftp_subsystem_s *sftp, struct sftp_userinfo_s *sftp_userinfo)
{
    char buffer[1024];
    unsigned int size=1024;
    unsigned int error=0;

    logoutput("get_remote_sftp_userinfo");

    size=get_sftp_userinfo(sftp->channel.session, (void *) sftp_userinfo, buffer, size, &error);

    if (size>0) {
	char *output=buffer;
	char *sep=NULL;
	unsigned int len=0;

	replace_cntrl_char(output, size);

	searchoutput:

	sep=memchr(output, ':', size);
	if (!sep) goto out;
	len=(unsigned int) (sep - output);

	if (strncmp((char *)output, "remotegroup=", 12)==0) {

	    logoutput("get_remote_sftp_userinfo: remotegroup");

	    output+=12;
	    size-=12;
	    len-=12;

	    if (len>0) {

		if (sftp_userinfo->remote_group) {

		    sftp_userinfo->remote_group->ptr=malloc(len);

		    if (sftp_userinfo->remote_group->ptr) {

			memcpy(sftp_userinfo->remote_group->ptr, output, len);
			sftp_userinfo->remote_group->len=len;
			sftp_userinfo->received|=SFTP_USERINFO_REMOTE_GROUP;

		    } else {

			logoutput("get_remote_sftp_userinfo: unable to alloc %i bytes", len);
			goto error;

		    }

		    logoutput("get_remote_sftp_userinfo: found remote group '%.*s'", sftp_userinfo->remote_group->len, sftp_userinfo->remote_group->ptr);

		}

		output+=len+1;
		size-=(unsigned int) (len + 1);

	    } else {

		logoutput("get_remote_sftp_userinfo: error: remotegroup no value");
		goto error;

	    }

	} else if (strncmp((char *)output, "remoteuid=", 10)==0) {

	    output+=10;
	    size-=10;
	    len-=10;

	    logoutput("get_remote_sftp_userinfo: remoteuid");

	    if (len>0) {

		if (sftp_userinfo->remote_uid) {
		    char remote_uid[len+1];

		    memcpy(remote_uid, output, len);
		    remote_uid[len]='\0';

		    *sftp_userinfo->remote_uid=atoi(remote_uid);
		    sftp_userinfo->received|=SFTP_USERINFO_REMOTE_UID;

		}

		output+=len+1;
		size-=(unsigned int) (len + 1);

	    } else {

		logoutput("get_remote_sftp_userinfo: error: remoteuid no value");
		goto error;

	    }

	} else if (strncmp((char *)output, "remotegid=", 10)==0) {

	    output+=10;
	    size-=10;
	    len-=10;

	    logoutput("get_remote_sftp_userinfo: remotegid");

	    if (len>0) {

		if (sftp_userinfo->remote_gid) {
		    char remote_gid[len+1];

		    memcpy(remote_gid, output, len);
		    remote_gid[len]='\0';

		    *sftp_userinfo->remote_gid=atoi(remote_gid);
		    sftp_userinfo->received|=SFTP_USERINFO_REMOTE_GID;

		}

		output+=len+1;
		size-=(unsigned int) (len + 1);

	    } else {

		logoutput("get_remote_sftp_userinfo: error: remotegid no value");
		goto error;

	    }

	} else if (strncmp((char *)output, "remotehome=", 11)==0) {

	    output+=11;
	    size-=11;
	    len-=11;

	    logoutput("get_remote_sftp_userinfo: remotehome");

	    if (len>0) {

		if (sftp_userinfo->remote_home) {

		    sftp_userinfo->remote_home->ptr=malloc(len);

		    if (sftp_userinfo->remote_home->ptr) {

			memcpy(sftp_userinfo->remote_home->ptr, output, len);
			sftp_userinfo->remote_home->len=len;
			sftp_userinfo->received|=SFTP_USERINFO_REMOTE_HOME;

		    } else {

			logoutput("get_remote_sftp_userinfo: unable to alloc %i bytes", len);
			goto error;

		    }

		    logoutput("get_remote_sftp_userinfo: found remote home '%.*s'", sftp_userinfo->remote_home->len, sftp_userinfo->remote_home->ptr);

		}

		output+=len+1;
		size-=(unsigned int) (len + 1);

	    } else {

		logoutput("get_remote_sftp_userinfo: error: remotehome no value");
		goto error;

	    }

	} else {

	    output+=len+1;
	    size-=(len + 1);
	    len=0;

	}

	if (size>0) goto searchoutput;

    } else {

	goto error;

    }

    out:

    return;

    error:

    logoutput("get_remote_sftp_userinfo: error scanning output");

}

static unsigned char get_sftp_user_mapping(struct context_interface_s *interface)
{
    struct context_option_s option;
    unsigned char mapping=_SFTP_USER_MAPPING_SHARED;

    memset(&option, 0, sizeof(struct context_option_s));

    /* TODO: add "sending" of the name of the remote host */

    if ((* interface->get_interface_option)(interface, "option:sftp.usermapping.type", &option)>0) {

	if (strcmp(option.value.ptr, "none")==0) {

	    /* no mapping or translation required, uid and gid are shared via ldap/ad for example  */

	    mapping=_SFTP_USER_MAPPING_SHARED;

	} else if (strcmp(option.value.ptr, "map")==0) {

	    /* simple mapping is used like:
		local user 	<-> remote user
		root		<-> root
		nobody		<-> nobody
		everything else mapped to the unknown user */

	    mapping=_SFTP_USER_MAPPING_NONSHARED;

	} else if (strcmp(option.value.ptr, "file")==0) {

	    /* there is a file with remote users mapped to local users
		for now handle this as simple mapping */

	    mapping=_SFTP_USER_MAPPING_NONSHARED;

	} else {

	    logoutput_warning("get_sftp_user_mapping: option sftp.usermapping.type value %s not reckognized", option.value.ptr);

	}

    } else {

	logoutput_warning("get_sftp_user_mapping: option sftp.usermapping.type not reckognized");

    }

    return mapping;
}

int init_sftp_usermapping(struct context_interface_s *interface, struct sftp_subsystem_s *sftp)
{
    struct ssh_session_s *session=sftp->channel.session;
    struct sftp_usermapping_s *usermapping=&sftp->usermapping;
    unsigned char mapping=_SFTP_USER_MAPPING_NONSHARED;
    gid_t *local_gid=NULL;
    struct ssh_string_s *remote_group=NULL;
    struct ssh_string_s *remote_home=&sftp->remote_home;
    uid_t *remote_uid=NULL;
    gid_t *remote_gid=NULL;

    logoutput("init_sftp_usermapping");

    memset(usermapping, 0, sizeof(struct sftp_usermapping_s));

    get_local_unknown(interface, usermapping);

    /* is the user id db shared with server? (via ldap etc.) */

    mapping=get_sftp_user_mapping(interface);

    if (sftp->server_version==3) {

	/* users and groups via id's */

	use_sftp_user_v03(sftp, mapping);

	if (mapping==_SFTP_USER_MAPPING_NONSHARED) {

	    local_gid=&usermapping->data.id_nonshared.local_gid;
	    remote_uid=&usermapping->data.id_nonshared.remote_uid;
	    remote_gid=&usermapping->data.id_nonshared.remote_gid;

	}

    } else {

	/* users and groups are send from server as strings like
	    user@example.nl and group@example.nl */

	use_sftp_user_v04(sftp, mapping);

	if (mapping==_SFTP_USER_MAPPING_NONSHARED) {

	    local_gid=&usermapping->data.id_nonshared.local_gid;
	    remote_group=&usermapping->data.name_nonshared.remote_group;

	} else {

	    pthread_mutex_init(&usermapping->data.name_shared.pwd_mutex, NULL);
	    pthread_mutex_init(&usermapping->data.name_shared.gr_mutex, NULL);

	}

    }

    /* get data if required */

    if (local_gid) {

	*local_gid=session->identity.pwd.pw_gid;
	logoutput("init_sftp_usermapping: got uid:gid %i:%i for local user", (int) session->identity.pwd.pw_uid, (int) session->identity.pwd.pw_gid);

    }

    if (remote_group || remote_uid || remote_gid || remote_home) {
	struct sftp_userinfo_s sftp_userinfo;

	sftp_userinfo.wanted=0;
	sftp_userinfo.remote_group=remote_group;
	sftp_userinfo.remote_uid=remote_uid;
	sftp_userinfo.remote_gid=remote_gid;
	sftp_userinfo.remote_home=remote_home;

	if (remote_group) sftp_userinfo.wanted|=SFTP_USERINFO_REMOTE_GROUP;
	if (remote_uid) sftp_userinfo.wanted|=SFTP_USERINFO_REMOTE_UID;
	if (remote_gid) sftp_userinfo.wanted|=SFTP_USERINFO_REMOTE_GID;
	if (remote_home) sftp_userinfo.wanted|=SFTP_USERINFO_REMOTE_HOME;

	sftp_userinfo.received=0;
	get_remote_sftp_userinfo(sftp, &sftp_userinfo);

	if (sftp_userinfo.received < sftp_userinfo.wanted) {

	    logoutput("init_sftp_usermapping: not received enough");
	    return -1;

	}

    }

    return 0;

}
