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

#include <linux/fs.h>

#include "main.h"
#include "logging.h"
#include "utils.h"

#include "workspace-interface.h"

#include "ssh-common-protocol.h"
#include "ssh-common.h"
#include "ssh-utils.h"
#include "ssh-hostinfo.h"

#include "common-protocol.h"
#include "common.h"

#include <glib.h>

/*
    function to read and write sftp attributes when only a pointer to sftp subsystem is available (=context)
    these functions calls the version specific attributes handler

    the read and write functions give the required size when buffer is NULL
*/

unsigned int read_attributes_ctx(void *ptr, char *buffer, unsigned int size, struct fuse_sftp_attr_s *fuse_attr)
{
    struct sftp_subsystem_s *sftp=(struct sftp_subsystem_s *) ptr;
    // gchar *encoded;

    /* required to encode ?*/
    // encoded=g_base64_encode(buffer, size);
    // logoutput("read_attributes_ctx: buffer %s", encoded);
    // g_free(encoded);

    return (*sftp->attr_ops->read_attributes)(sftp, buffer, size, fuse_attr);
}

unsigned int write_attributes_ctx(void *ptr, char *buffer, unsigned int size, struct fuse_sftp_attr_s *fuse_attr)
{
    struct sftp_subsystem_s *sftp=(struct sftp_subsystem_s *) ptr;
    return (*sftp->attr_ops->write_attributes)(sftp, buffer, size, fuse_attr);
}
void read_name_response_ctx(void *ptr, struct name_response_s *response, char **name, unsigned int *len)
{
    struct sftp_subsystem_s *sftp=(struct sftp_subsystem_s *) ptr;
    (*sftp->attr_ops->read_name_response)(sftp, response, name, len);
}
unsigned int read_attr_response_ctx(void *ptr, struct name_response_s *response, struct fuse_sftp_attr_s *fuse_attr)
{
    struct sftp_subsystem_s *sftp=(struct sftp_subsystem_s *) ptr;
    return (*sftp->attr_ops->read_attr_response)(sftp, response, fuse_attr);
}
int get_attribute_info_ctx(void *ptr, unsigned int valid, const char *what)
{
    struct sftp_subsystem_s *sftp=(struct sftp_subsystem_s *) ptr;
    return (* sftp->attr_ops->get_attribute_info)(sftp, valid, what);
}
