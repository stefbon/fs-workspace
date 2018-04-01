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
#include <sys/time.h>
#include <time.h>
#include <ctype.h>
#include <inttypes.h>
#include <sys/param.h>
#include <sys/types.h>

#include <logging.h>
#include <utils.h>

#include "ssh-datatypes.h"
#include "pk-types.h"
#include "pk-keys.h"
#include "pk-readwrite-public.h"

/*
    functions to read and write public keys from different formats

    FORMAT SSH
    ----------

    rsa public key:

    string		"ssh-rsa"
    mpint		e
    mpint		n

    dss public key:

    string		"ssh-dss"
    mpint		p
    mpint		q
    mpint		g
    mpint		y

    string and mpint are described at: https://tools.ietf.org/html/rfc4251#section-5

    this format is used by ssh to send public keys over the wire and by openssh to store public keys in files

*/

static int read_pkey_rsa_ssh(struct ssh_key_s *pkey, char *buffer, unsigned int size, unsigned int *error)
{
    int left = (int) size;
    char *pos = buffer;
    struct ssh_pkalgo_s *algo=NULL;
    int result=0;

    algo=read_pkalgo(pos, left, &result);

    if (algo==NULL) {

	logoutput_warning("read_pkey_rsa_ssh: algo not reckognized");
	*error=EINVAL;
	return -1;

    } else if (algo->id != SSH_PKALGO_ID_RSA) {

	logoutput_warning("read_pkey_rsa_ssh: wrong algo (%s)", algo->name);
	*error=EINVAL;
	return -1;

    }

    pos += result;
    left -= result;

    result=read_pk_mpint(&pkey->param.rsa.e, pos, left, error);

    if (result==-1) {

	logoutput_warning("read_pkey_rsa_ssh: error reading e");
	return -1;

    }

    pos += result;
    left -= result;

    result=read_pk_mpint(&pkey->param.rsa.n, pos, left, error);

    if (result==-1) {

	logoutput_warning("read_pkey_rsa_ssh: error reading n");
	return -1;

    }

    pos += result;
    left -= result;

    return (int) (pos - buffer);

}

int read_pkey_rsa(struct ssh_key_s *pkey, char *buffer, unsigned int size, unsigned int format, unsigned int *error)
{

    switch (format) {

    case PK_DATA_FORMAT_SSH:

	return read_pkey_rsa_ssh(pkey, buffer, size, error);

    default:

	*error=EINVAL;
	logoutput("read_pkey_rsa: format %i not supported", format);

    }

    return -1;

}

int write_pkey_rsa_ssh(struct ssh_key_s *pkey, char *buffer, unsigned int size, unsigned char format, unsigned int *error)
{
    int left = (int) size;
    int result = 0;
    char *pos = buffer;

    if (buffer==NULL) {
	unsigned int bytes=0;

	if (format==PK_DATA_FORMAT_SSH_STRING) bytes += 4;

	bytes +=write_pkalgo(NULL, pkey->algo) +
		write_pk_mpint(&pkey->param.rsa.e, NULL, 0, error) +
		write_pk_mpint(&pkey->param.rsa.n, NULL, 0, error);

	return (int) bytes;

    }

    if (format==PK_DATA_FORMAT_SSH_STRING) {

	pos+=4;
	left-=4;

    }

    result = (int) write_pkalgo(pos, pkey->algo);
    pos += result;
    left -= result;

    result = write_pk_mpint(&pkey->param.rsa.e, pos, left, error);

    if (result==-1) {

	logoutput("write_pkey_rsa_ssh: error writing e");
	return -1;

    }

    left -= result;
    pos += result;

    result = write_pk_mpint(&pkey->param.rsa.n, pos, left, error);

    if (result==-1) {

	logoutput("write_pkey_rsa_ssh: error writing n");
	return -1;

    }

    left -= result;
    pos += result;

    if (format==PK_DATA_FORMAT_SSH_STRING) {

	store_uint32(buffer, (unsigned int)(pos - (buffer + 4)));

    }

    return (int) (pos - buffer);

}

int write_pkey_rsa(struct ssh_key_s *pkey, char *buffer, unsigned int size, unsigned int format, unsigned int *error)
{

    switch (format) {

    case PK_DATA_FORMAT_SSH:
    case PK_DATA_FORMAT_SSH_STRING:

	return write_pkey_rsa_ssh(pkey, buffer, size, format, error);

    default:

	*error=EINVAL;
	logoutput("write_pkey_rsa: format %i not supported", format);

    }

    return -1;

}

int read_pkey_dss_ssh(struct ssh_key_s *pkey, char *buffer, unsigned int size, unsigned int *error)
{
    char *pos = buffer;
    int left = (int) size;
    struct ssh_pkalgo_s *algo=NULL;
    int result=0;

    algo=read_pkalgo(pos, left, &result);

    if (algo==NULL) {

	logoutput_warning("read_pkey_dss_ssh: algo not reckognized");
	*error=EINVAL;
	return -1;

    } else if (algo->id != SSH_PKALGO_ID_DSS) {

	logoutput_warning("read_pkey_dss_ssh: wrong algo (%s)", algo->name);
	*error=EINVAL;
	return -1;

    }

    pos += result;
    left -= result;

    result=read_pk_mpint(&pkey->param.dss.p, pos, left, error);

    if (result==-1) {

	logoutput_warning("read_pkey_dss_ssh: error reading p");
	return -1;

    }

    pos += result;
    left -= result;

    result=read_pk_mpint(&pkey->param.dss.q, pos, left, error);

    if (result==-1) {

	logoutput_warning("read_pkey_dss_ssh: error reading q");
	return -1;

    }

    pos += result;
    left -= result;

    result=read_pk_mpint(&pkey->param.dss.g, pos, left, error);

    if (result==-1) {

	logoutput_warning("read_pkey_dss_ssh: error reading g");
	return -1;

    }

    pos += result;
    left -= result;

    result=read_pk_mpint(&pkey->param.dss.y, pos, left, error);

    if (result==-1) {

	logoutput_warning("read_pkey_dss_ssh: error reading y");
	return -1;

    }

    pos += result;
    left -= result;

    return (int) (pos - buffer);

}

int read_pkey_dss(struct ssh_key_s *pkey, char *buffer, unsigned int size, unsigned int format, unsigned int *error)
{

    switch (format) {

    case PK_DATA_FORMAT_SSH:

	return read_pkey_dss_ssh(pkey, buffer, size, error);

    default:

	*error=EINVAL;
	logoutput("read_pkey_dss: format %i not supported", format);

    }

    return -1;

}

int write_pkey_dss_ssh(struct ssh_key_s *pkey, char *buffer, unsigned int size, unsigned int format, unsigned int *error)
{
    int left = (int) size;
    int result = 0;
    char *pos = buffer;

    if (buffer==NULL) {
	unsigned int bytes = 0;

	if (format==PK_DATA_FORMAT_SSH_STRING) bytes=4;

	bytes +=write_pkalgo(NULL, pkey->algo) +
		write_pk_mpint(&pkey->param.dss.p, NULL, 0, error) +
		write_pk_mpint(&pkey->param.dss.q, NULL, 0, error) +
		write_pk_mpint(&pkey->param.dss.g, NULL, 0, error) +
		write_pk_mpint(&pkey->param.dss.y, NULL, 0, error);

	return (int) bytes;

    }

    if (format==PK_DATA_FORMAT_SSH_STRING) {

	pos+=4;
	left-=4;

    }

    result = (int) write_pkalgo(pos, pkey->algo);
    pos += result;
    left -= result;

    result = write_pk_mpint(&pkey->param.dss.p, pos, left, error);

    if (result==-1) {

	logoutput("write_pkey_dss_ssh: error writing p");
	return -1;

    }

    left -= result;
    pos += result;

    result = write_pk_mpint(&pkey->param.dss.q, pos, left, error);

    if (result==-1) {

	logoutput("write_pkey_dss_ssh: error writing q");
	return -1;

    }

    left -= result;
    pos += result;

    result = write_pk_mpint(&pkey->param.dss.g, pos, left, error);

    if (result==-1) {

	logoutput("write_pkey_dss_ssh: error writing g");
	return -1;

    }

    left -= result;
    pos += result;

    result = write_pk_mpint(&pkey->param.dss.y, pos, left, error);

    if (result==-1) {

	logoutput("write_pkey_dss_ssh: error writing y");
	return -1;

    }

    left -= result;
    pos += result;

    if (format==PK_DATA_FORMAT_SSH_STRING) {

	store_uint32(buffer, (unsigned int)(pos - (buffer + 4)));

    }

    return (int) (pos - buffer);

}

int write_pkey_dss(struct ssh_key_s *pkey, char *buffer, unsigned int size, unsigned int format, unsigned int *error)
{

    switch (format) {

    case PK_DATA_FORMAT_SSH:
    case PK_DATA_FORMAT_SSH_STRING:

	return write_pkey_dss_ssh(pkey, buffer, size, format, error);

    default:

	*error=EINVAL;
	logoutput("write_pkey_dss: format not supported");

    }

    return -1;

}
