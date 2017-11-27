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

#include "main.h"
#include "logging.h"
#include "utils.h"

#include "ssh-common.h"
#include "ssh-common-protocol.h"

#include "ssh-pubkey.h"
#include "ssh-compression.h"
#include "ssh-encryption.h"
#include "ssh-mac.h"
#include "ssh-keyx.h"
#include "ssh-language.h"
#include "ssh-data.h"

#include "ssh-utils.h"

/*
    get the best common algo out of the client and server list
    it first compares the first name on both comma seperated lists
    then - if no match - it walks the client list and check the name found is also
    on the server list
*/

static void get_best_guess(unsigned char *pos_client, unsigned int len_client, unsigned char *pos_server, unsigned int len_server, char *name, unsigned int size)
{
    char list_client[len_client+1];
    char list_server[len_server+1];
    char *c_name=NULL, *c_sep=NULL;
    char *s_name=NULL, *s_sep=NULL;

    memset(&list_client[0], '\0', len_client+1);
    memset(&list_server[0], '\0', len_server+1);

    memcpy(&list_client[0], (char *) pos_client, len_client);
    memcpy(&list_server[0], (char *) pos_server, len_server);

    logoutput("get_best_guess: compare %s - %s", list_client, list_server);

    c_name=&list_client[0];
    s_name=&list_server[0];

    c_sep=strchrnul(c_name, ',');
    s_sep=strchrnul(s_name, ',');

    if ((unsigned int)(c_sep-c_name)==(unsigned int)(s_sep-s_name) && memcmp(c_name, s_name, (unsigned int)(c_sep-c_name))==0) {
	unsigned char c_keep=0;

	/* the first are the same */

	c_keep=(unsigned char) *c_sep;
	*c_sep='\0';
	strncpy(name, c_name, size);
	*c_sep=c_keep;

    } else {
	unsigned char c_keep=0;

	findname:

	c_keep=(unsigned char) *c_sep;
	*c_sep='\0';

	if (string_found_commalist(&list_server[0], c_name)==1) {

	    /* test the server hostkey algo? if that is not supported by client or server it would not be on the list */

	    strcpy(name, c_name);
	    *c_sep=c_keep;
	    return;

	}

	*c_sep=c_keep;

	if (c_keep>0) {

	    c_name=c_sep+1;
	    c_sep=strchrnul(c_name, ',');

	    /* jump back and try next name */

	    goto findname;

	}

    }

}


    /*
	compare kex
	- if first kex algo's are the same this must be used
	- iterate over the client kex algo's and take the one that:
	    - server supports it also
	    - if an encryption capable server host key is required the algo for this is supported by the server and the client
	    - if an signature capable server host key is required the algo for this is supported by the server and the client
    */

    /*
	server host key algo's
	- choose the first algo which is supported by the server and client and provides the encryption/signature able key
    */

    /*
	encryption
	- choose the first algo which is supported by client and server
	(none is allowed)
    */

    /*
	mac
	- choose the first algo which is supported by client and server
	(none is allowed)
    */

    /*
	compression
	- choose the first algo which is supported by client and server
	(none is allowed)
    */

int compare_msg_kexinit(struct ssh_session_s *session, unsigned char init, struct ssh_init_algo *algos)
{
    struct session_data_s *data=&session->data;
    struct ssh_string_s *kexinit_client=&session->crypto.keydata.kexinit_client;
    struct ssh_string_s *kexinit_server=&session->crypto.keydata.kexinit_server;
    unsigned char *pos_client=kexinit_client->ptr;
    unsigned char *pos_server=kexinit_server->ptr;
    unsigned int len_client=0, total_len_client=0;
    unsigned int len_server=0, total_len_server=0;

    /* some basic tests */

    if (kexinit_client->ptr==NULL) {

	logoutput("compare_msg_kexinit: no client keyexinit message");
	return -1;

    } else if (kexinit_client->len <= 63) {

	logoutput("compare_msg_kexinit: client keyexinit message too small (%i)", kexinit_client->len);
	return -1;

    }

    if (kexinit_server->ptr==NULL) {

	logoutput("compare_msg_kexinit: no server keyexinit message");
	return -1;

     } else if (kexinit_server->len <= 63) {

	logoutput("compare_msg_kexinit: server keyexinit message too small (%i)", kexinit_server->len);
	return -1;

    }

    /*
	start at where the algo's begin

	for a SSH_MSG_KEXINIT message:
	- 1 byte for the type
	- 16 bytes for cookie

	so start reading after 1 + 16 = 17 bytes

    */

    pos_client+=17;
    pos_server+=17;

    /* kex algorithms like dh
	20171126:
	work on the possibility to accept ext-info-s
	(see: https://tools.ietf.org/html/draft-ssh-ext-info-05)*/

    len_client=get_uint32(pos_client);
    pos_client+=4;

    len_server=get_uint32(pos_server);
    pos_server+=4;

    total_len_client=len_client + (unsigned int)(pos_client - kexinit_client->ptr);
    total_len_server=len_server + (unsigned int)(pos_server - kexinit_server->ptr);

    memset(&algos->keyexchange[0], '\0', sizeof(algos->keyexchange));

    if (len_client>0 && len_server>0 && total_len_client < kexinit_client->len && total_len_server < kexinit_server->len) {

	get_best_guess(pos_client, len_client, pos_server, len_server, &algos->keyexchange[0], sizeof(algos->keyexchange));

    } else {

	logoutput("compare_msg_kexinit: lc %i ls %i tlc %i tls %i", len_client, len_server, total_len_client, total_len_server);

    }

    if (strlen(&algos->keyexchange[0])>0) {

	logoutput("compare_msg_kexinit: found key exchange method %s", &algos->keyexchange[0]);

    } else {

	logoutput("compare_msg_kexinit: no key exchange method found");
	return -1;

    }

    pos_client+=len_client;
    pos_server+=len_server;

    /* host key like ssh-rsa */

    len_client=get_uint32(pos_client);
    pos_client+=4;

    len_server=get_uint32(pos_server);
    pos_server+=4;

    memset(&algos->hostkey[0],'\0', sizeof(algos->hostkey));

    total_len_client+=4+len_client;

    if (len_client>0 && len_server>0 && total_len_client < kexinit_client->len && total_len_server < kexinit_server->len) {

	get_best_guess(pos_client, len_client, pos_server, len_server, &algos->hostkey[0], sizeof(algos->hostkey));

    }

    if (strlen(&algos->hostkey[0])>0) {

	logoutput("compare_msg_kexinit: found hostkey method %s", &algos->hostkey[0]);

    } else {

	logoutput("compare_msg_kexinit: no hostkey method found");
	return -1;

    }

    pos_client+=len_client;
    pos_server+=len_server;

    /* encryption like blowfish and aes from client to server */

    len_client=get_uint32(pos_client);
    pos_client+=4;

    len_server=get_uint32(pos_server);
    pos_server+=4;

    memset(&algos->encryption_c2s[0],'\0', sizeof(algos->encryption_c2s));

    total_len_client+=4+len_client;
    total_len_server+=4+len_server;

    if (len_client>0 && len_server>0 && total_len_client < kexinit_client->len && total_len_server < kexinit_server->len) {

	get_best_guess(pos_client, len_client, pos_server, len_server, &algos->encryption_c2s[0], sizeof(algos->encryption_c2s));

    }

    if (strlen(&algos->encryption_c2s[0])>0) {

	logoutput("compare_msg_kexinit: found encryption c2s method %s", &algos->encryption_c2s[0]);

    } else {

	logoutput("compare_msg_kexinit: no encryption c2s method found");
	return -1;

    }

    pos_client+=len_client;
    pos_server+=len_server;

    /* encryption like blowfish and aes from server to client */

    len_client=get_uint32(pos_client);
    pos_client+=4;

    len_server=get_uint32(pos_server);
    pos_server+=4;

    memset(&algos->encryption_s2c[0],'\0', sizeof(algos->encryption_s2c));

    total_len_client+=4+len_client;
    total_len_server+=4+len_server;

    if (len_client>0 && len_server>0 && total_len_client < kexinit_client->len && total_len_server < kexinit_server->len) {

	get_best_guess(pos_client, len_client, pos_server, len_server, &algos->encryption_s2c[0], sizeof(algos->encryption_s2c));

    }

    if (strlen(&algos->encryption_s2c[0])>0) {

	logoutput("compare_msg_kexinit: found encryption s2c method %s", &algos->encryption_s2c[0]);

    } else {

	logoutput("compare_msg_kexinit: no encryption s2c method found");
	return -1;

    }

    pos_client+=len_client;
    pos_server+=len_server;

    /* hmac like sha1 from client to server */

    len_client=get_uint32(pos_client);
    pos_client+=4;

    len_server=get_uint32(pos_server);
    pos_server+=4;

    memset(&algos->hmac_c2s[0],'\0', sizeof(algos->hmac_c2s));

    total_len_client+=4+len_client;
    total_len_server+=4+len_server;

    if (len_client>0 && len_server>0 && total_len_client < kexinit_client->len && total_len_server < kexinit_server->len) {

	get_best_guess(pos_client, len_client, pos_server, len_server, &algos->hmac_c2s[0], sizeof(algos->hmac_c2s));

    }

    if (strlen(&algos->hmac_c2s[0])>0) {

	logoutput("compare_msg_kexinit: found hmac c2s method %s", &algos->hmac_c2s[0]);

    } else {

	logoutput("compare_msg_kexinit: no hmac c2s method found");
	return -1;

    }

    pos_client+=len_client;
    pos_server+=len_server;

    /* hmac like sha1 from server to client */

    len_client=get_uint32(pos_client);
    pos_client+=4;

    len_server=get_uint32(pos_server);
    pos_server+=4;

    memset(&algos->hmac_s2c[0],'\0', sizeof(algos->hmac_s2c));

    total_len_client+=4+len_client;
    total_len_server+=4+len_server;

    if (len_client>0 && len_server>0 && total_len_client < kexinit_client->len && total_len_server < kexinit_server->len) {

	get_best_guess(pos_client, len_client, pos_server, len_server, &algos->hmac_s2c[0], sizeof(algos->hmac_s2c));

    }

    if (strlen(&algos->hmac_s2c[0])>0) {

	logoutput("compare_msg_kexinit: found hmac s2c method %s", &algos->hmac_s2c[0]);

    } else {

	logoutput("compare_msg_kexinit: no hmac s2c method found");
	return -1;

    }

    pos_client+=len_client;
    pos_server+=len_server;

    /* compression like zlib from client to server */

    len_client=get_uint32(pos_client);
    pos_client+=4;

    len_server=get_uint32(pos_server);
    pos_server+=4;

    memset(&algos->compression_c2s[0],'\0', sizeof(algos->compression_c2s));

    total_len_client+=4+len_client;
    total_len_server+=4+len_server;

    if (len_client>0 && len_server>0 && total_len_client < kexinit_client->len && total_len_server < kexinit_server->len) {

	get_best_guess(pos_client, len_client, pos_server, len_server, &algos->compression_c2s[0], sizeof(algos->compression_c2s));

    }

    if (strlen(&algos->compression_c2s[0])>0) {

	logoutput("compare_msg_kexinit: found compression c2s method %s", &algos->compression_c2s[0]);

    } else {

	logoutput("compare_msg_kexinit: no compression c2s method found");
	return -1;

    }

    pos_client+=len_client;
    pos_server+=len_server;

    /* compression like zlib from server to client */

    len_client=get_uint32(pos_client);
    pos_client+=4;

    len_server=get_uint32(pos_server);
    pos_server+=4;

    memset(&algos->compression_s2c[0],'\0', sizeof(algos->compression_s2c));

    total_len_client+=4+len_client;
    total_len_server+=4+len_server;

    if (len_client>0 && len_server>0 && total_len_client < kexinit_client->len && total_len_server < kexinit_server->len) {

	get_best_guess(pos_client, len_client, pos_server, len_server, &algos->compression_s2c[0], sizeof(algos->compression_s2c));

    }

    if (strlen(&algos->compression_s2c[0])>0) {

	logoutput("compare_msg_kexinit: found compression s2c method %s", &algos->compression_s2c[0]);

    } else {

	logoutput("compare_msg_kexinit: no compression s2c method found");
	return -1;

    }

    pos_client+=len_client;
    pos_server+=len_server;

    /* languages: ignore but test the layout */

    len_client=get_uint32(pos_client);
    pos_client+=4;

    len_server=get_uint32(pos_server);
    pos_server+=4;

    total_len_client+=4+len_client;
    total_len_server+=4+len_server;

    if (total_len_client >= kexinit_client->len) {

	logoutput("compare_msg_kexinit: error format client keyexinit message");
	return -1;

    }

    if (total_len_server >= kexinit_server->len) {

	logoutput("compare_msg_kexinit: error format server keyexinit message");
	return -1;

    }

    return 0;

}
