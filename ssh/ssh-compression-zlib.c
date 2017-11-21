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
#include <zlib.h>

#include "logging.h"
#include "main.h"

#include "utils.h"

#include "ssh-common.h"

/* c2s: compress (=deflate) */

static int deflate_payload_zlib(struct ssh_compression_s *compression, struct ssh_payload_s *payload)
{
    z_stream *strm=(z_stream *) compression->library_c2s.ptr;
    int result=-1;
    unsigned int len=payload->len;
    unsigned char output[len];

    strm->avail_in = payload->len;
    strm->next_in = (unsigned char *) payload->buffer;

    strm->avail_out = len;
    strm->next_out = output;

    result=deflate(strm, Z_PARTIAL_FLUSH);

    if (result==Z_OK && (strm->avail_out>0)) {

	len-=strm->avail_out;
	memcpy(payload->buffer, &output[0], len);
	payload->len=len;
	return 0;

    }

    return -1;

}

/* s2c: decompress (==inflate) */

static struct ssh_payload_s *inflate_payload_zlib(struct ssh_compression_s *compression, struct ssh_payload_s *payload)
{
    z_stream *strm=(z_stream *) compression->library_s2c.ptr;
    struct ssh_payload_s *new=NULL;
    unsigned int len=payload->len * compression->inflatebound;

    strm->avail_in=(size_t) payload->len;
    strm->next_in=(unsigned char *) payload->buffer;
    strm->total_in=0; 

    new=malloc(sizeof(struct ssh_payload_s) + len);

    if (new==NULL) goto error;

    memcpy(new, payload, sizeof(struct ssh_payload_s));
    memset(new->buffer, 0, len);
    new->len=len;

    strm->avail_out=(size_t) len;
    strm->next_out=(unsigned char *) new->buffer;
    strm->total_out=0;

    for (;;) {
	int result=0;
	unsigned int bytesdone=0;

	result=inflate(strm, Z_PARTIAL_FLUSH);

	if (result==Z_OK) {

	    if (strm->avail_out>0) break;

	} else if (result==Z_BUF_ERROR) {

	    /* get more output space */

	} else {

	    goto error;

	}

	/* number of bytes read */
	bytesdone=len - (unsigned int) strm->avail_out;

	/* increase the inflatebound parameter */
	compression->inflatebound++; /* some protection here? */
	len=payload->len * compression->inflatebound;

	new=realloc(new, sizeof(struct ssh_payload_s) + len);
	if (new==NULL) goto error;

	/* continue where left */
	strm->next_out=(unsigned char *)new->buffer + bytesdone;
	strm->avail_out=len - bytesdone;

    }

    /* new->len represents the number of inflated bytes, not the size of the new->buffer */
    new->len=len - strm->avail_out;
    return new;

    error:

    if (new) free(new);
    return NULL;

}

static void close_deflate_zlib(struct ssh_compression_s *compression)
{
    struct library_s *library=&compression->library_s2c;
    z_stream *strm=(z_stream *) library->ptr;

    if (strm) {

	deflateEnd(strm);
	free(strm);
	library->ptr=NULL;

    }

}

static void close_inflate_zlib(struct ssh_compression_s *compression)
{
    struct library_s *library=&compression->library_c2s;
    z_stream *strm=(z_stream *) library->ptr;

    if (strm) {

	inflateEnd(strm);
	free(strm);
	library->ptr=NULL;

    }

}

static int set_inflate_zlib(struct ssh_compression_s *compression, const char *name, unsigned int *error)
{

    if (strcmp(name, "zlib")==0) {
	struct library_s *library=&compression->library_s2c;
	z_stream *strm=NULL;

	strm=malloc(sizeof(z_stream));

	if (strm==NULL) {

	    *error=ENOMEM;
	    return -1;

	}

	memset(strm, 0, sizeof(z_stream));

	strm->total_in = strm->avail_in = NULL;
	strm->next_in = NULL;

	strm->zalloc = Z_NULL;
	strm->zfree = Z_NULL;
	strm->opaque = Z_NULL;

	if (inflateInit(strm)==Z_OK) {

	    library->ptr=(void *)strm;
	    library->type=_COMPRESSION_LIBRARY_ZLIB;
	    compression->inflate=inflate_payload_zlib;
	    compression->close_inflate=close_inflate_zlib;
	    return 0;

	} else {

	    free(strm);
	    *error=EIO;
	    return -1;

	}

    }

    return -1;

}

static int set_deflate_zlib(struct ssh_compression_s *compression, const char *name, unsigned int *error)
{

    if (strcmp(name, "zlib")==0) {
	struct library_s *library=&compression->library_c2s;
	z_stream *strm=NULL;

	strm=malloc(sizeof(z_stream));

	if (strm==NULL) {

	    *error=ENOMEM;
	    return -1;

	}

	memset(strm, 0, sizeof(z_stream));

	strm->total_in = strm->avail_in = NULL;
	strm->next_in = NULL;

	strm->zalloc = Z_NULL;
	strm->zfree = Z_NULL;
	strm->opaque = Z_NULL;

	if (deflateInit(strm, Z_DEFAULT_COMPRESSION)==Z_OK) {

	    library->ptr=(void *)strm;
	    library->type=_COMPRESSION_LIBRARY_ZLIB;
	    compression->deflate=deflate_payload_zlib;
	    compression->close_deflate=close_deflate_zlib;
	    return 0;

	} else {

	    free(strm);
	    *error=EIO;
	    return -1;

	}

    }

    return -1;

}

int init_compression_zlib(struct ssh_compression_s *compression)
{
    compression->set_deflate=set_deflate_zlib;
    compression->set_inflate=set_inflate_zlib;
}
