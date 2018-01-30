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

void init_ssh_algo(struct ssh_kexinit_algo *algo)
{
    memset(algo, 0, sizeof(struct ssh_kexinit_algo));

    strcpy(algo->encryption_c2s, "none");
    strcpy(algo->encryption_s2c, "none");

    strcpy(algo->hmac_c2s, "none");
    strcpy(algo->hmac_s2c, "none");

    strcpy(algo->compression_c2s, "none");
    strcpy(algo->compression_s2c, "none");
}

static int _store_kexinit_common(struct ssh_string_s *kexinit, struct ssh_payload_s *payload, unsigned int *error)
{

    *error=0;
    kexinit->ptr=realloc(kexinit->ptr, payload->len);

    if (kexinit->ptr) {

	memcpy(kexinit->ptr, payload->buffer, payload->len);
	kexinit->len=payload->len;

    } else {

	*error=ENOMEM;
	kexinit->len=0;

	return -1;

    }

    return 0;

}

int store_kexinit_server(struct ssh_session_s *session, struct ssh_payload_s *payload, unsigned int *error)
{
    if (session->keyexchange) {
	struct ssh_string_s *kexinit=&session->keyexchange->keydata.kexinit_server;

	return _store_kexinit_common(kexinit, payload, error);

    }

    *error=EINVAL;
    return -1;
}

int store_kexinit_client(struct ssh_session_s *session, struct ssh_payload_s *payload, unsigned int *error)
{
    if (session->keyexchange) {
	struct ssh_string_s *kexinit=&session->keyexchange->keydata.kexinit_client;

        return _store_kexinit_common(kexinit, payload, error);

    }

    *error=EINVAL;
    return -1;
}

static void _free_kexinit_common(struct ssh_string_s *kexinit)
{
    if (kexinit->ptr) {

	free(kexinit->ptr);
	kexinit->ptr=NULL;

    }

    kexinit->len=0;
}

void free_kexinit_server(struct ssh_session_s *session)
{
    if (session->keyexchange) {
	struct ssh_string_s *kexinit=&session->keyexchange->keydata.kexinit_server;
	_free_kexinit_common(kexinit);
    }
}

void free_kexinit_client(struct ssh_session_s *session)
{
    if (session->keyexchange) {
	struct ssh_string_s *kexinit=&session->keyexchange->keydata.kexinit_client;
	_free_kexinit_common(kexinit);
    }
}

int store_ssh_session_id(struct ssh_session_s *session, unsigned char *id, unsigned int len)
{

    session->data.sessionid.ptr=realloc(session->data.sessionid.ptr, len);

    if (session->data.sessionid.ptr) {

	memcpy(session->data.sessionid.ptr, id, len);
	session->data.sessionid.len=len;
	session->data.sessionid.flags|=SSH_STRING_FLAG_ALLOCATE;
	return 0;

    }

    session->status.error=ENOMEM;
    return -1;

}

void init_keydata(struct session_keydata_s *keydata)
{
    keydata->status=0;
    init_ssh_string(&keydata->kexinit_server);
    init_ssh_string(&keydata->kexinit_client);
    init_ssh_string(&keydata->iv_s2c);
    init_ssh_string(&keydata->iv_c2s);
    init_ssh_string(&keydata->cipher_key_s2c);
    init_ssh_string(&keydata->cipher_key_c2s);
    init_ssh_string(&keydata->hmac_key_s2c);
    init_ssh_string(&keydata->hmac_key_c2s);

    init_ssh_algo(&keydata->algos);

}

void free_keydata(struct session_keydata_s *keydata)
{
    free_ssh_string(&keydata->kexinit_server);
    free_ssh_string(&keydata->kexinit_client);
    free_ssh_string(&keydata->iv_s2c);
    free_ssh_string(&keydata->iv_c2s);
    free_ssh_string(&keydata->cipher_key_s2c);
    free_ssh_string(&keydata->cipher_key_c2s);
    free_ssh_string(&keydata->hmac_key_s2c);
    free_ssh_string(&keydata->hmac_key_c2s);
}

void init_session_data(struct ssh_session_s *session)
{
    struct session_data_s *data=&session->data;

    logoutput_info("init_session_data");

    memset(data, 0, sizeof(struct session_data_s));

    init_ssh_string(&data->sessionid);
    init_ssh_string(&data->greeter_server);

}

void free_session_data(struct ssh_session_s *session)
{
    struct session_data_s *data=&session->data;

    free_ssh_string(&data->sessionid);
    free_ssh_string(&data->greeter_server);

}
