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

#include "logging.h"
#include "main.h"

#include "utils.h"

#include "ssh-common.h"
#include "ssh-mac.h"
#include "ssh-mac-libgcrypt.h"
#include "ssh-utils.h"

#include "ctx-options.h"

static void free_none(struct ssh_hmac_s *hmac)
{
}

static void reset_none(struct ssh_hmac_s *hmac)
{
}

static int verify_mac_none(struct rawdata_s *data)
{
    return 0;
}

static void set_hmac_s2c_none(struct ssh_hmac_s *hmac)
{

    hmac->library_s2c.ptr=NULL;
    hmac->library_s2c.type=_LIBRARY_NONE;

    hmac->reset_s2c=reset_none;
    hmac->verify_mac_pre=verify_mac_none;
    hmac->verify_mac_post=verify_mac_none;
    hmac->free_s2c=free_none;
}

static void write_mac_none(struct ssh_hmac_s *hmac, struct ssh_packet_s *packet)
{
}

static ssize_t send_c2s_none(struct ssh_session_s *session, struct ssh_packet_s *packet)
{
    struct ssh_connection_s *connection=&session->connection;
    ssize_t written=0;

    /* no mac: just send the packet without mac */

    written=write(connection->fd, packet->buffer, packet->len);

    if (written==-1) packet->error=errno;
    return written;

}

static void set_hmac_c2s_none(struct ssh_hmac_s *hmac)
{

    hmac->library_c2s.ptr=NULL;
    hmac->library_c2s.type=_LIBRARY_NONE;

    hmac->reset_c2s=reset_none;
    hmac->write_mac_pre=write_mac_none;
    hmac->write_mac_post=write_mac_none;
    hmac->send_c2s=send_c2s_none;
    hmac->free_c2s=free_none;

}

void init_mac(struct ssh_session_s *session)
{
    struct ssh_hmac_s *hmac=&session->crypto.hmac;

    logoutput_info("init_mac");

    memset(hmac, 0, sizeof(struct ssh_hmac_s));

    set_hmac_s2c_none(hmac);
    set_hmac_c2s_none(hmac);

    hmac->maclen_c2s=0;
    hmac->maclen_s2c=0;

    hmac->key_c2s=&session->crypto.keydata.hmac_key_c2s;
    hmac->key_s2c=&session->crypto.keydata.hmac_key_s2c;

    init_mac_libgcrypt(hmac);

}

int set_hmac_s2c(struct ssh_session_s *session, const char *name, unsigned int *error)
{
    struct ssh_hmac_s *hmac=&session->crypto.hmac;

    if (strcmp(name, "none")==0) {

	set_hmac_s2c_none(hmac);

    } else {

	return (* hmac->set_mac_s2c)(hmac, name, error);

    }

    return 0;

}

int set_hmac_c2s(struct ssh_session_s *session, const char *name, unsigned int *error)
{
    struct ssh_hmac_s *hmac=&session->crypto.hmac;

    if (strcmp(name, "none")==0) {

	set_hmac_c2s_none(hmac);

    } else {

	return (* hmac->set_mac_c2s)(hmac, name, error);

    }

    return 0;

}

/*
    generic functions
*/

void reset_s2c_mac(struct ssh_session_s *session)
{
    struct ssh_hmac_s *hmac=&session->crypto.hmac;
    (* hmac->reset_s2c)(hmac);
}

int verify_mac_pre_decrypt(struct rawdata_s *data)
{
    struct ssh_hmac_s *hmac=&data->session->crypto.hmac;
    return (* hmac->verify_mac_pre)(data);
}

int verify_mac_post_decrypt(struct rawdata_s *data)
{
    struct ssh_hmac_s *hmac=&data->session->crypto.hmac;
    return (* hmac->verify_mac_post)(data);
}

void free_s2c_mac(struct ssh_session_s *session)
{
    struct ssh_hmac_s *hmac=&session->crypto.hmac;
    (* hmac->free_s2c)(hmac);
}

void reset_c2s_mac(struct ssh_session_s *session)
{
    struct ssh_hmac_s *hmac=&session->crypto.hmac;
    (* hmac->reset_c2s)(hmac);
}

void write_mac_pre_encrypt(struct ssh_session_s *session, struct ssh_packet_s *packet)
{
    struct ssh_hmac_s *hmac=&session->crypto.hmac;
    (* hmac->write_mac_pre)(hmac, packet);
}

void write_mac_post_encrypt(struct ssh_session_s *session, struct ssh_packet_s *packet)
{
    struct ssh_hmac_s *hmac=&session->crypto.hmac;
    (* hmac->write_mac_post)(hmac, packet);
}

ssize_t send_c2s(struct ssh_session_s *session, struct ssh_packet_s *packet)
{
    struct ssh_hmac_s *hmac=&session->crypto.hmac;
    return (* hmac->send_c2s) (session, packet);
}

void free_c2s_mac(struct ssh_session_s *session)
{
    struct ssh_hmac_s *hmac=&session->crypto.hmac;
    (* hmac->free_c2s)(hmac);
}

unsigned int get_maclen_c2s(struct ssh_session_s *session)
{
    struct ssh_hmac_s *hmac=&session->crypto.hmac;
    return hmac->maclen_c2s;
}

unsigned int get_maclen_s2c(struct ssh_session_s *session)
{
    struct ssh_hmac_s *hmac=&session->crypto.hmac;
    return hmac->maclen_s2c;
}

int set_mac_key_c2s(struct ssh_session_s *session, char *name, struct ssh_string_s *key)
{
    struct ssh_hmac_s *hmac=&session->crypto.hmac;
    return (* hmac->setkey_c2s)(hmac->key_c2s, name, key);
}

int set_mac_key_s2c(struct ssh_session_s *session, char *name, struct ssh_string_s *key)
{
    struct ssh_hmac_s *hmac=&session->crypto.hmac;
    return (* hmac->setkey_s2c)(hmac->key_s2c, name, key);
}

unsigned int get_mac_keylen(struct ssh_session_s *session, const char *name)
{
    struct ssh_hmac_s *hmac=&session->crypto.hmac;
    return (* hmac->get_mac_keylen)(name);
}

unsigned int check_add_macname(const char *name, struct commalist_s *clist)
{
    return check_add_generic(get_ssh_options("mac"), name, clist);
}

unsigned int ssh_get_mac_list(struct commalist_s *clist)
{
    unsigned int len=0;
    unsigned int error=0;

    //len+=add_name_to_commalist("none", clist, &error);
    len+=ssh_get_mac_list_libgcrypt(clist);

    return len;

}
