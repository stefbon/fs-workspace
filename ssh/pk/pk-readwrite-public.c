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

static int read_pkey_rsa_common(struct ssh_key_s *pkey, char *buffer, unsigned int size, unsigned int format, unsigned int *error)
{
    int left = (int) size;
    char *pos = buffer;
    int result=0;

    if (format==PK_DATA_FORMAT_SSH) {
	struct ssh_pkalgo_s *algo=NULL;

	algo=read_pkalgo(pos, left, &result);

	if (algo==NULL) {

	    logoutput_warning("read_pkey_rsa_ssh: algo not reckognized");
	    *error=EINVAL;
	    return -1;

	} else if (algo != pkey->algo) {

	    logoutput_warning("read_pkey_rsa_ssh: wrong algo (%s)", algo->name);
	    *error=EINVAL;
	    return -1;

	}

	pos += result;
	left -= result;

    }

    result=read_ssh_mpint(&pkey->param.rsa.e, pos, left, SSH_MPINT_FORMAT_SSH, error);

    if (result==-1) {

	logoutput_warning("read_pkey_rsa_ssh: error reading e");
	return -1;

    }

    pos += result;
    left -= result;

    result=read_ssh_mpint(&pkey->param.rsa.n, pos, left, SSH_MPINT_FORMAT_SSH, error);

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

    case PK_DATA_FORMAT_PARAM:
    case PK_DATA_FORMAT_SSH:

	return read_pkey_rsa_common(pkey, buffer, size, format, error);

    default:

	*error=EINVAL;
	logoutput("read_pkey_rsa: format %i not supported", format);

    }

    return -1;

}

static void msg_read_pkey_rsa_common(struct msg_buffer_s *mb, struct ssh_key_s *pkey, unsigned int format)
{
    unsigned int len=0;
    unsigned int *plen=NULL;

    if (mb->error>0) return;

    logoutput("msg_read_pkey_rsa_common: 1 pos=%i", mb->pos);

    if (format==PK_DATA_FORMAT_SSH_STRING) {

	plen=&len;
	msg_read_ssh_string_header(mb, plen);

	logoutput("msg_read_pkey_rsa_common: read header (len=%i)", len);

	if ((mb->len > 0) && (mb->len - mb->pos < len)) {

	    /* len is bigger than available space */

	    mb->error=EIO;
	    return;

	}

    }

    logoutput("msg_read_pkey_rsa_common: 2 pos=%i", mb->pos);

    if (format==PK_DATA_FORMAT_SSH || format==PK_DATA_FORMAT_SSH_STRING) {
	struct ssh_string_s algo;
	int read=0;

	init_ssh_string(&algo);
	msg_read_ssh_string(mb, &algo);

	if (read_pkalgo_string(&algo, &read)!=pkey->algo) {

	    if (algo.len < 65) {
		char string[algo.len + 1];

		memcpy(string, algo.ptr, algo.len);
		string[algo.len]='\0';
		logoutput("msg_read_pkey_rsa_common: algo %s found expecting %s", string, pkey->algo->name);

	    } else {

		logoutput("msg_read_pkey_rsa_common: algo too long (%i) found expecting %s", algo.len, pkey->algo->name);

	    }

	    mb->error=EINVAL;
	    return;

	} else {

	    logoutput("msg_read_pkey_rsa_common: found algo %s", pkey->algo->name);

	}

	if (format==PK_DATA_FORMAT_SSH_STRING) len -= read;

    }

    msg_read_ssh_mpint(mb, &pkey->param.rsa.e, plen);
    msg_read_ssh_mpint(mb, &pkey->param.rsa.n, plen);

}

void msg_read_pkey_rsa(struct msg_buffer_s *mb, struct ssh_key_s *pkey, unsigned int format)
{

    switch (format) {

    case PK_DATA_FORMAT_PARAM:
    case PK_DATA_FORMAT_SSH:
    case PK_DATA_FORMAT_SSH_STRING:

	msg_read_pkey_rsa_common(mb, pkey, format);
	break;

    default:

	mb->error=EINVAL;
	logoutput("msg_read_pkey_rsa: format %i not supported", format);

    }

}

static int write_pkey_rsa_common(struct ssh_key_s *pkey, char *buffer, unsigned int size, unsigned char format, unsigned int *error)
{
    int left = (int) size;
    int result = 0;
    char *pos = buffer;

    if (buffer==NULL) {
	unsigned int bytes=0;

	if (format==PK_DATA_FORMAT_SSH_STRING) bytes += 4;
	if (format==PK_DATA_FORMAT_SSH || format==PK_DATA_FORMAT_SSH_STRING) bytes +=write_pkalgo(NULL, pkey->algo);

	bytes +=write_ssh_mpint(&pkey->param.rsa.e, NULL, 0, SSH_MPINT_FORMAT_SSH, error) +
		write_ssh_mpint(&pkey->param.rsa.n, NULL, 0, SSH_MPINT_FORMAT_SSH, error);

	return (int) bytes;

    }

    if (format==PK_DATA_FORMAT_SSH_STRING) {

	pos+=4;
	left-=4;

    }

    if (format==PK_DATA_FORMAT_SSH || format==PK_DATA_FORMAT_SSH_STRING) {

	result = (int) write_pkalgo(pos, pkey->algo);
	pos += result;
	left -= result;

    }

    result = write_ssh_mpint(&pkey->param.rsa.e, pos, left, SSH_MPINT_FORMAT_SSH, error);

    if (result==-1) {

	logoutput("write_pkey_rsa_ssh: error writing e");
	return -1;

    }

    left -= result;
    pos += result;

    result = write_ssh_mpint(&pkey->param.rsa.n, pos, left, SSH_MPINT_FORMAT_SSH, error);

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

static void msg_write_pkey_rsa_common(struct msg_buffer_s *mb, struct ssh_key_s *pkey, unsigned int format)
{
    unsigned int pos = 0;

    if (format==PK_DATA_FORMAT_SSH_STRING) pos=(* mb->start_ssh_string)(mb);
    if (format==PK_DATA_FORMAT_SSH || format==PK_DATA_FORMAT_SSH_STRING) msg_write_pkalgo(mb, pkey->algo);
    msg_write_ssh_mpint(mb, &pkey->param.rsa.e);
    msg_write_ssh_mpint(mb, &pkey->param.rsa.n);
    if (format==PK_DATA_FORMAT_SSH_STRING) (* mb->complete_ssh_string)(mb, pos);

}

int write_pkey_rsa(struct ssh_key_s *pkey, char *buffer, unsigned int size, unsigned int format, unsigned int *error)
{

    switch (format) {

    case PK_DATA_FORMAT_PARAM:
    case PK_DATA_FORMAT_SSH:
    case PK_DATA_FORMAT_SSH_STRING:

	return write_pkey_rsa_common(pkey, buffer, size, format, error);

    default:

	*error=EINVAL;
	logoutput("write_pkey_rsa: format %i not supported", format);

    }

    return -1;

}

void msg_write_pkey_rsa(struct msg_buffer_s *mb, struct ssh_key_s *pkey, unsigned int format)
{

    switch (format) {

    case PK_DATA_FORMAT_PARAM:
    case PK_DATA_FORMAT_SSH:
    case PK_DATA_FORMAT_SSH_STRING:

	msg_write_pkey_rsa_common(mb, pkey, format);
	break;

    default:

	set_msg_buffer_fatal_error(mb, EINVAL);
	logoutput("msg_write_pkey_rsa: format %i not supported", format);

    }

}

static int read_pkey_dss_common(struct ssh_key_s *pkey, char *buffer, unsigned int size, unsigned int format, unsigned int *error)
{
    char *pos = buffer;
    int left = (int) size;
    int result=0;

    if (format==PK_DATA_FORMAT_SSH) {
	struct ssh_pkalgo_s *algo=NULL;

	algo=read_pkalgo(pos, left, &result);

	if (algo==NULL) {

	    logoutput_warning("read_pkey_dss_common: algo not reckognized");
	    *error=EINVAL;
	    return -1;

	} else if (algo != pkey->algo) {

	    logoutput_warning("read_pkey_dss_common: wrong algo (%s)", algo->name);
	    *error=EINVAL;
	    return -1;

	}

	pos += result;
	left -= result;

    }

    result=read_ssh_mpint(&pkey->param.dss.p, pos, left, SSH_MPINT_FORMAT_SSH, error);

    if (result==-1) {

	logoutput_warning("read_pkey_dss_common: error reading p");
	return -1;

    }

    pos += result;
    left -= result;

    result=read_ssh_mpint(&pkey->param.dss.q, pos, left, SSH_MPINT_FORMAT_SSH, error);

    if (result==-1) {

	logoutput_warning("read_pkey_dss_common: error reading q");
	return -1;

    }

    pos += result;
    left -= result;

    result=read_ssh_mpint(&pkey->param.dss.g, pos, left, SSH_MPINT_FORMAT_SSH, error);

    if (result==-1) {

	logoutput_warning("read_pkey_dss_common: error reading g");
	return -1;

    }

    pos += result;
    left -= result;

    result=read_ssh_mpint(&pkey->param.dss.y, pos, left, SSH_MPINT_FORMAT_SSH, error);

    if (result==-1) {

	logoutput_warning("read_pkey_dss_common: error reading y");
	return -1;

    }

    pos += result;
    left -= result;

    return (int) (pos - buffer);

}

int read_pkey_dss(struct ssh_key_s *pkey, char *buffer, unsigned int size, unsigned int format, unsigned int *error)
{

    switch (format) {

    case PK_DATA_FORMAT_PARAM:
    case PK_DATA_FORMAT_SSH:

	return read_pkey_dss_common(pkey, buffer, size, format, error);

    default:

	*error=EINVAL;
	logoutput("read_pkey_dss: format %i not supported", format);

    }

    return -1;

}

static void msg_read_pkey_dss_common(struct msg_buffer_s *mb, struct ssh_key_s *pkey, unsigned int format)
{
    unsigned int len=0;
    unsigned int *plen=NULL;

    if (mb->error>0) return;

    if (format==PK_DATA_FORMAT_SSH_STRING) {

	plen=&len;
	msg_read_ssh_string_header(mb, plen);

	if ((mb->len > 0) && (mb->len - mb->pos < len)) {

	    /* len is bigger than available space */

	    mb->error=EIO;
	    return;

	}

    }

    if (format==PK_DATA_FORMAT_SSH || format==PK_DATA_FORMAT_SSH_STRING) {
	struct ssh_string_s algo;
	int read=0;

	init_ssh_string(&algo);
	msg_read_ssh_string(mb, &algo);

	if (read_pkalgo_string(&algo, &read)!=pkey->algo) {

	    mb->error=EINVAL;
	    return;

	}

	if (format==PK_DATA_FORMAT_SSH_STRING) len -= read;

    }

    msg_read_ssh_mpint(mb, &pkey->param.dss.p, plen);
    msg_read_ssh_mpint(mb, &pkey->param.dss.q, plen);
    msg_read_ssh_mpint(mb, &pkey->param.dss.g, plen);
    msg_read_ssh_mpint(mb, &pkey->param.dss.y, plen);

}

void msg_read_pkey_dss(struct msg_buffer_s *mb, struct ssh_key_s *pkey, unsigned int format)
{

    switch (format) {

    case PK_DATA_FORMAT_PARAM:
    case PK_DATA_FORMAT_SSH:
    case PK_DATA_FORMAT_SSH_STRING:

	msg_read_pkey_dss_common(mb, pkey, format);
	break;

    default:

	mb->error=EINVAL;
	logoutput("msg_read_pkey_dss: format %i not supported", format);

    }

}

static int write_pkey_dss_common(struct ssh_key_s *pkey, char *buffer, unsigned int size, unsigned int format, unsigned int *error)
{
    int left = (int) size;
    int result = 0;
    char *pos = buffer;

    if (buffer==NULL) {
	unsigned int bytes = 0;

	if (format==PK_DATA_FORMAT_SSH_STRING) bytes=4;
	if (format==PK_DATA_FORMAT_SSH || format==PK_DATA_FORMAT_SSH_STRING) bytes += write_pkalgo(NULL, pkey->algo);

	bytes +=write_ssh_mpint(&pkey->param.dss.p, NULL, 0, SSH_MPINT_FORMAT_SSH, error) +
		write_ssh_mpint(&pkey->param.dss.q, NULL, 0, SSH_MPINT_FORMAT_SSH, error) +
		write_ssh_mpint(&pkey->param.dss.g, NULL, 0, SSH_MPINT_FORMAT_SSH, error) +
		write_ssh_mpint(&pkey->param.dss.y, NULL, 0, SSH_MPINT_FORMAT_SSH, error);

	return (int) bytes;

    }

    if (format==PK_DATA_FORMAT_SSH_STRING) {

	pos+=4;
	left-=4;

    }

    if (format==PK_DATA_FORMAT_SSH || format==PK_DATA_FORMAT_SSH_STRING) {

	result = (int) write_pkalgo(pos, pkey->algo);
	pos += result;
	left -= result;

    }

    result = write_ssh_mpint(&pkey->param.dss.p, pos, left, SSH_MPINT_FORMAT_SSH, error);

    if (result==-1) {

	logoutput("write_pkey_dss_ssh: error writing p");
	return -1;

    }

    left -= result;
    pos += result;

    result = write_ssh_mpint(&pkey->param.dss.q, pos, left, SSH_MPINT_FORMAT_SSH, error);

    if (result==-1) {

	logoutput("write_pkey_dss_ssh: error writing q");
	return -1;

    }

    left -= result;
    pos += result;

    result = write_ssh_mpint(&pkey->param.dss.g, pos, left, SSH_MPINT_FORMAT_SSH, error);

    if (result==-1) {

	logoutput("write_pkey_dss_ssh: error writing g");
	return -1;

    }

    left -= result;
    pos += result;

    result = write_ssh_mpint(&pkey->param.dss.y, pos, left, SSH_MPINT_FORMAT_SSH, error);

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

    case PK_DATA_FORMAT_PARAM:
    case PK_DATA_FORMAT_SSH:
    case PK_DATA_FORMAT_SSH_STRING:

	return write_pkey_dss_common(pkey, buffer, size, format, error);

    default:

	*error=EINVAL;
	logoutput("write_pkey_dss: format not supported");

    }

    return -1;

}

static void msg_write_pkey_dss_common(struct msg_buffer_s *mb, struct ssh_key_s *pkey, unsigned int format)
{
    unsigned int pos=0;

    if (format==PK_DATA_FORMAT_SSH_STRING) pos=(* mb->start_ssh_string)(mb);
    if (format==PK_DATA_FORMAT_SSH || format==PK_DATA_FORMAT_SSH_STRING) msg_write_pkalgo(mb, pkey->algo);
    msg_write_ssh_mpint(mb, &pkey->param.dss.p);
    msg_write_ssh_mpint(mb, &pkey->param.dss.q);
    msg_write_ssh_mpint(mb, &pkey->param.dss.g);
    msg_write_ssh_mpint(mb, &pkey->param.dss.y);
    if (format==PK_DATA_FORMAT_SSH_STRING) (* mb->complete_ssh_string)(mb, pos);
}

void msg_write_pkey_dss(struct msg_buffer_s *mb, struct ssh_key_s *pkey, unsigned int format)
{

    switch (format) {

    case PK_DATA_FORMAT_PARAM:
    case PK_DATA_FORMAT_SSH:
    case PK_DATA_FORMAT_SSH_STRING:

	msg_write_pkey_dss_common(mb, pkey, format);
	break;

    default:

	set_msg_buffer_fatal_error(mb, EINVAL);
	logoutput("msg_write_pkey_dss: format not supported");

    }

}

static int read_pkey_ecc_common(struct ssh_key_s *pkey, char *buffer, unsigned int size, unsigned int format, unsigned int *error)
{
    char *pos = buffer;
    int left = (int) size;
    int result=0;

    if (format==PK_DATA_FORMAT_SSH) {
	struct ssh_pkalgo_s *algo=NULL;

	algo=read_pkalgo(pos, left, &result);

	if (algo==NULL) {

	    logoutput_warning("read_pkey_ecc_common: algo not reckognized");
	    *error=EINVAL;
	    return -1;

	} else if (algo->scheme != SSH_PKALGO_SCHEME_ECC) {

	    logoutput_warning("read_pkey_ecc_common: wrong algo (%s)", algo->name);
	    *error=EINVAL;
	    return -1;

	}

	pos += result;
	left -= result;

    }

    result=read_ssh_mpoint(&pkey->param.ecc.q, pos, left, SSH_MPINT_FORMAT_SSH, error);

    if (result==-1) {

	logoutput_warning("read_pkey_ecc_common: error reading q");
	return -1;

    }

    pos += result;
    left -= result;

    return (int) (pos - buffer);

}

int read_pkey_ecc(struct ssh_key_s *pkey, char *buffer, unsigned int size, unsigned int format, unsigned int *error)
{

    switch (format) {

    case PK_DATA_FORMAT_PARAM:
    case PK_DATA_FORMAT_SSH:

	return read_pkey_ecc_common(pkey, buffer, size, format, error);

    default:

	*error=EINVAL;
	logoutput("read_pkey_ecc: format %i not supported", format);

    }

    return -1;

}

static int write_pkey_ecc_common(struct ssh_key_s *pkey, char *buffer, unsigned int size, unsigned int format, unsigned int *error)
{
    int left = (int) size;
    int result = 0;
    char *pos = buffer;

    if (buffer==NULL) {
	unsigned int bytes = 0;

	if (format==PK_DATA_FORMAT_SSH_STRING) bytes+=4;
	if (format==PK_DATA_FORMAT_SSH_STRING || format==PK_DATA_FORMAT_SSH) bytes += write_pkalgo(NULL, pkey->algo);

	bytes += write_ssh_mpoint(&pkey->param.ecc.q, NULL, 0, SSH_MPINT_FORMAT_SSH, error);

	return (int) bytes;

    }

    if (format==PK_DATA_FORMAT_SSH_STRING) {

	pos+=4;
	left-=4;

    }

    if (format==PK_DATA_FORMAT_SSH_STRING || format==PK_DATA_FORMAT_SSH) {

	result = (int) write_pkalgo(pos, pkey->algo);
	pos += result;
	left -= result;

    }

    result = write_ssh_mpoint(&pkey->param.ecc.q, pos, left, SSH_MPINT_FORMAT_SSH, error);

    if (result==-1) {

	logoutput("write_pkey_dss_common: error writing p");
	return -1;

    }

    left -= result;
    pos += result;

    if (format==PK_DATA_FORMAT_SSH_STRING) {

	store_uint32(buffer, (unsigned int)(pos - (buffer + 4)));

    }

    return (int) (pos - buffer);

}

int write_pkey_ecc(struct ssh_key_s *pkey, char *buffer, unsigned int size, unsigned int format, unsigned int *error)
{

    switch (format) {

    case PK_DATA_FORMAT_PARAM:
    case PK_DATA_FORMAT_SSH:
    case PK_DATA_FORMAT_SSH_STRING:

	return write_pkey_ecc_common(pkey, buffer, size, format, error);

    default:

	*error=EINVAL;
	logoutput("write_pkey_ecc: format not supported");

    }

    return -1;

}

static void msg_write_pkey_ecc_common(struct msg_buffer_s *mb, struct ssh_key_s *pkey, unsigned int format)
{
    unsigned int pos=0;

    logoutput("msg_write_pkey_ecc_ssh pos=%i", mb->pos);

    if (format==PK_DATA_FORMAT_SSH_STRING) pos=(* mb->start_ssh_string)(mb);
    if (format==PK_DATA_FORMAT_SSH || format==PK_DATA_FORMAT_SSH_STRING) msg_write_pkalgo(mb, pkey->algo);
    msg_write_ssh_mpoint(mb, &pkey->param.ecc.q);
    if (format==PK_DATA_FORMAT_SSH_STRING) (* mb->complete_ssh_string)(mb, pos);

}

void msg_write_pkey_ecc(struct msg_buffer_s *mb, struct ssh_key_s *pkey, unsigned int format)
{

    switch (format) {

    case PK_DATA_FORMAT_PARAM:
    case PK_DATA_FORMAT_SSH:
    case PK_DATA_FORMAT_SSH_STRING:

	msg_write_pkey_ecc_common(mb, pkey, format);
	break;

    default:

	set_msg_buffer_fatal_error(mb, EINVAL);
	logoutput("msg_write_pkey_ecc: format not supported");

    }

}

static void msg_read_pkey_ecc_common(struct msg_buffer_s *mb, struct ssh_key_s *pkey, unsigned int format)
{
    unsigned int len=0;
    unsigned int *plen=NULL;

    if (mb->error>0) return;

    if (format==PK_DATA_FORMAT_SSH_STRING) {

	plen=&len;
	msg_read_ssh_string_header(mb, plen);

	if ((mb->len > 0) && (mb->len - mb->pos < len)) {

	    /* len is bigger than available space */

	    mb->error=EIO;
	    return;

	}

    }

    if (format==PK_DATA_FORMAT_SSH || format==PK_DATA_FORMAT_SSH_STRING) {
	struct ssh_string_s algo;
	int read=0;

	init_ssh_string(&algo);
	msg_read_ssh_string(mb, &algo);

	if (read_pkalgo_string(&algo, &read)!=pkey->algo) {

	    mb->error=EINVAL;
	    return;

	}

	if (format==PK_DATA_FORMAT_SSH_STRING) len -= read;

    }

    msg_read_ssh_mpoint(mb, &pkey->param.ecc.q, plen);

}

void msg_read_pkey_ecc(struct msg_buffer_s *mb, struct ssh_key_s *pkey, unsigned int format)
{

    switch (format) {

    case PK_DATA_FORMAT_PARAM:
    case PK_DATA_FORMAT_SSH:
    case PK_DATA_FORMAT_SSH_STRING:

	msg_read_pkey_ecc_common(mb, pkey, format);
	break;

    default:

	mb->error=EINVAL;
	logoutput("msg_read_pkey_ecc: format %i not supported", format);

    }

}

int read_pkey_generic(struct ssh_key_s *pkey, char *buffer, unsigned int size, unsigned int format, unsigned int *error)
{
    char *pos = buffer;
    int left = (int) size;
    int result=0;

    if (format==PK_DATA_FORMAT_SSH) {
	struct ssh_pkalgo_s *algo=NULL;

	algo=read_pkalgo(pos, left, &result);

	if (algo==NULL) {

	    logoutput_warning("read_pkey_generic: algo not reckognized");
	    *error=EINVAL;
	    return -1;

	} else if (pkey->algo==NULL) {

	    logoutput_info("read_pkey_generic: found algo %s", algo->name);
	    init_ssh_key(pkey, 0, algo);

	} else if (algo != pkey->algo) {

	    logoutput_warning("read_pkey_generic: wrong algo (%s) (expecting %s)", algo->name, pkey->algo->name);
	    *error=EINVAL;
	    return -1;

	}

	pos += result;
	left -= result;
	format = PK_DATA_FORMAT_PARAM;

    }

    if (pkey->algo) {

	switch (pkey->algo->scheme) {

	case SSH_PKALGO_SCHEME_RSA:

	    return read_pkey_rsa(pkey, pos, left, format, error);

	case SSH_PKALGO_SCHEME_DSS:

	    return read_pkey_dss(pkey, pos, left, format, error);

	case SSH_PKALGO_SCHEME_ECC:

	    return read_pkey_ecc(pkey, pos, left, format, error);

	default:

	    logoutput("read_pkey_generic: algo id %i not reckognized", pkey->algo->id);

	}

    }

    return -1;

}
