/*
  2017, 2018 Stef Bon <stefbon@gmail.com>

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
#include "logging.h"
#include "utils.h"

#include "ssh-common.h"
#include "ssh-common-protocol.h"
#include "ssh-utils.h"
#include "ssh-pubkey.h"
#include "ssh-connections.h"

/*
    get the best common algo out of the client and server list
    it first compares the first name on both comma seperated lists
    then - if no match - it walks the client list and check the name found is also
    on the server list
*/

static void get_best_guess(struct ssh_string_s *clist_c, struct ssh_string_s *clist_s, char *name, unsigned int size)
{
    char list_c[clist_c->len+3];
    char list_s[clist_s->len+3];
    char *c_name=NULL, *c_sep=NULL;
    char *s_name=NULL, *s_sep=NULL;

    if (clist_c->len==0 || clist_c->ptr==NULL || clist_s->len==0 || clist_c->ptr==NULL) return;

    list_c[0]=',';
    memcpy(&list_c[1], clist_c->ptr, clist_c->len);
    list_c[clist_c->len+1]=',';
    list_c[clist_c->len+2]='\0';
    list_s[0]=',';
    memcpy(&list_s[1], clist_s->ptr, clist_s->len);
    list_s[clist_s->len+1]=',';
    list_s[clist_s->len+2]='\0';

    logoutput("get_best_guess: compare %s - %s", list_c, list_s);

    c_name=list_c;
    s_name=list_s;
    c_sep=strchr(c_name+1, ',');
    s_sep=strchr(s_name+1, ',');

    if ((unsigned int)(c_sep-c_name)==(unsigned int)(s_sep-s_name) && memcmp(c_name, s_name, (unsigned int)(c_sep-c_name))==0) {
	unsigned int len=(unsigned int)(c_sep - c_name - 1);

	/* the first are the same */

	*c_sep='\0';
	c_name++;
	len=strlen(c_name);
	if (len<size) memcpy(name, c_name, len+1);
	return;

    } else {
	unsigned char c_keep=0;

	/* iterate over the client list and check the name is on the server list */

	findname:

	c_keep=(unsigned char) *(c_sep + 1);
	if (c_keep>0) *(c_sep+1)='\0';

	/* c_name is the algo name with a starting and ending comma like ,ssh-rsa,
	    this makes searching easier */

	if (strstr(list_s, c_name)) {
	    unsigned int len=0;

	    *c_sep='\0';
	    c_name++;
	    len=strlen(c_name);
	    if (len<size) memcpy(name, c_name, len+1);
	    return;

	}

	if (c_keep>0) {

	    *(c_sep+1)=c_keep;
	    c_name=c_sep;
	    c_sep=strchr(c_name+1, ',');

	    /* jump back and try next name */

	    goto findname;

	}

    }

}

/* lookup name in algo list */

static int get_index_algo(struct algo_list_s *algos, char *name, unsigned int type)
{
    unsigned int ctr=0;

    while (algos[ctr].type>=0) {

	if (algos[ctr].type==type && strcmp(algos[ctr].sshname, name)==0) return (int) ctr;
	ctr++;

    }

    return -1;

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

int compare_msg_kexinit(struct ssh_connection_s *connection)
{
    struct ssh_keyexchange_s *kex=&connection->setup.phase.transport.type.kex;
    struct ssh_string_s *kexinit_client=&kex->kexinit_client;
    struct ssh_string_s *kexinit_server=&kex->kexinit_server;
    struct algo_list_s *algos=kex->algos;
    char *pos_client=kexinit_client->ptr;
    char *pos_server=kexinit_server->ptr;
    struct ssh_string_s clist_client[SSH_ALGO_TYPES_COUNT];
    struct ssh_string_s clist_server[SSH_ALGO_TYPES_COUNT];
    unsigned int left_client=kexinit_client->len;
    unsigned int left_server=kexinit_server->len;
    unsigned int len_client=0;
    unsigned int len_server=0;
    char name[65];

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
    left_client-=17;
    left_server-=17;

    /* kex algorithms like dh
	20171126:
	work on the possibility to accept ext-info-s
	(see: https://tools.ietf.org/html/draft-ssh-ext-info-05)*/

    /* according to RFC4253 7.1 Algorithm Negotiation
	the kex may require a encryption and/or signature capable pk algo
	here is assumed this is always the case and no extra check is required .... */

    for (unsigned int i=0; i<SSH_ALGO_TYPES_COUNT; i++) {

	len_client=read_ssh_string(pos_client, left_client, &clist_client[i]);
	len_server=read_ssh_string(pos_server, left_server, &clist_server[i]);

	if (len_client==0 || len_server==0) {

	    logoutput("compare_msg_kexinit: error reading commalist from kexinit message");
	    goto error;

	}

	memset(name, '\0', 65);
	kex->chosen[i]=-1;
	get_best_guess(&clist_client[i], &clist_server[i], name, 65);

	if (strlen(name)>0) {
	    int index=0;

	    /* lookup the name found in the algo list used to build the kexinit */

	    index=get_index_algo(algos, name, i);

	    if (index==-1) {

		logoutput("compare_msg_kexinit: internal error processing method %s", name);
		goto error;

	    } else {

		kex->chosen[i]=index;
		logoutput("compare_msg_kexinit: found method %s", name);

	    }

	} else {

	    if (i==SSH_ALGO_TYPE_LANG_C2S || i==SSH_ALGO_TYPE_LANG_S2C) {

		/* name-lists of language tags may be ignored and should be empty */
		goto next;

	    } else {

		/* all other name-lists should result in a name */
		logoutput("compare_msg_kexinit: no method found");
		goto error;

	    }

	}

	if ((connection->flags & SSH_CONNECTION_FLAG_MAIN) && i==SSH_ALGO_TYPE_HOSTKEY) {
	    struct ssh_session_s *session=get_ssh_connection_session(connection);

	    store_algo_pubkey_negotiation(session, &clist_client[i], &clist_server[i]);

	}

	next:

	pos_client+=len_client;
	pos_server+=len_server;
	left_client-=len_client;
	left_server-=len_server;

    }

    return 0;

    error:

    logoutput("compare_msg_kexinit: finding matching algo's failed, cannot continue");
    return -1;

}
