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

#include <stdio.h>
#include <stdlib.h>
#include <stddef.h>
#include <stdbool.h>
#include <string.h>
#include <unistd.h>
#include <ctype.h>
#include <inttypes.h>

#include <sys/param.h>
#include <sys/types.h>

#include "asn1.h"

/* functions to read a TAG LENGTH VALUE
    this looks like:
    tlvvvvvvvvvvvvvv
    for example
*/

size_t asn1_read_length(char *pos, unsigned int *length, int left)
{
    unsigned char value=(unsigned char) *pos;
    unsigned char bit8=(value >> 7);

    if (bit8==1) {
	unsigned int result=0;

	/* value minus the eight byte is the number of fields reserved for the integer */

	value -= (bit8 << 7);
	if (value + 1 >= left) return 0;
	pos++;

	for (unsigned int i=0; i<value; i++) {

	    result = (result << 8) + (unsigned char) *pos;
	    pos++;

	}

	*length=result;
	return (size_t) (1 + value); /* number of bytes for integer plus 1 */

    }

    *length=value;
    return 1;

}

/* read the tlv (tag - length -value) from buffer, store the begin position and length of value in *pos and length */

int asn1_read_tlv(char *buffer, int size, struct asn1_tlv_s *tlv)
{
    int left=(int) size;
    size_t count=0;

    memset(tlv, 0, sizeof(struct asn1_tlv_s));

    /* expecting tag */

    if (left<=2) return -1;

    tlv->tag = (unsigned char) *buffer;
    buffer++;
    left--;
    tlv->bytes=1;

    /* read length; field length has count bytes */

    count = asn1_read_length(buffer, &tlv->len, left);
    if (count==0) return -1;
    buffer += count;

    /* store the position where the value starts */

    tlv->pos = buffer;

    /* total number of bytes the tlv takes */

    if (tlv->tag == _ASN1_TAG_INTEGER) {

	tlv->bytes += count + tlv->len;

    } else {

	tlv->bytes += count;

    }

    return 0;

}
