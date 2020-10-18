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

#include "common-protocol.h"
#include "common.h"
#include "send-common.h"

int send_sftp_open_ctx(void *ptr, struct sftp_request_s *sftp_r)
{
    struct sftp_subsystem_s *sftp_subsystem=(struct sftp_subsystem_s *) ptr;
    return (*sftp_subsystem->send_ops->open)(sftp_subsystem, sftp_r);
}

int send_sftp_create_ctx(void *ptr, struct sftp_request_s *sftp_r)
{
    struct sftp_subsystem_s *sftp_subsystem=(struct sftp_subsystem_s *) ptr;
    return (*sftp_subsystem->send_ops->create)(sftp_subsystem, sftp_r);
}

int send_sftp_opendir_ctx(void *ptr, struct sftp_request_s *sftp_r)
{
    struct sftp_subsystem_s *sftp_subsystem=(struct sftp_subsystem_s *) ptr;
    return (*sftp_subsystem->send_ops->opendir)(sftp_subsystem, sftp_r);
}

int send_sftp_read_ctx(void *ptr, struct sftp_request_s *sftp_r)
{
    struct sftp_subsystem_s *sftp_subsystem=(struct sftp_subsystem_s *) ptr;
    return (*sftp_subsystem->send_ops->read)(sftp_subsystem, sftp_r);
}

int send_sftp_write_ctx(void *ptr, struct sftp_request_s *sftp_r)
{
    struct sftp_subsystem_s *sftp_subsystem=(struct sftp_subsystem_s *) ptr;
    return (*sftp_subsystem->send_ops->write)(sftp_subsystem, sftp_r);
}

int send_sftp_readdir_ctx(void *ptr, struct sftp_request_s *sftp_r)
{
    struct sftp_subsystem_s *sftp_subsystem=(struct sftp_subsystem_s *) ptr;
    return (*sftp_subsystem->send_ops->readdir)(sftp_subsystem, sftp_r);
}

int send_sftp_close_ctx(void *ptr, struct sftp_request_s *sftp_r)
{
    struct sftp_subsystem_s *sftp_subsystem=(struct sftp_subsystem_s *) ptr;
    return (*sftp_subsystem->send_ops->close)(sftp_subsystem, sftp_r);
}

int send_sftp_remove_ctx(void *ptr, struct sftp_request_s *sftp_r)
{
    struct sftp_subsystem_s *sftp_subsystem=(struct sftp_subsystem_s *) ptr;
    return (*sftp_subsystem->send_ops->remove)(sftp_subsystem, sftp_r);
}

int send_sftp_rename_ctx(void *ptr, struct sftp_request_s *sftp_r)
{
    struct sftp_subsystem_s *sftp_subsystem=(struct sftp_subsystem_s *) ptr;
    return (*sftp_subsystem->send_ops->rename)(sftp_subsystem, sftp_r);
}

int send_sftp_mkdir_ctx(void *ptr, struct sftp_request_s *sftp_r)
{
    struct sftp_subsystem_s *sftp_subsystem=(struct sftp_subsystem_s *) ptr;
    return (*sftp_subsystem->send_ops->mkdir)(sftp_subsystem, sftp_r);
}

int send_sftp_rmdir_ctx(void *ptr, struct sftp_request_s *sftp_r)
{
    struct sftp_subsystem_s *sftp_subsystem=(struct sftp_subsystem_s *) ptr;
    return (*sftp_subsystem->send_ops->rmdir)(sftp_subsystem, sftp_r);
}

int send_sftp_stat_ctx(void *ptr, struct sftp_request_s *sftp_r)
{
    struct sftp_subsystem_s *sftp_subsystem=(struct sftp_subsystem_s *) ptr;
    return (*sftp_subsystem->send_ops->stat)(sftp_subsystem, sftp_r);
}

int send_sftp_lstat_ctx(void *ptr, struct sftp_request_s *sftp_r)
{
    struct sftp_subsystem_s *sftp_subsystem=(struct sftp_subsystem_s *) ptr;
    return (*sftp_subsystem->send_ops->lstat)(sftp_subsystem, sftp_r);
}

int send_sftp_fstat_ctx(void *ptr, struct sftp_request_s *sftp_r)
{
    struct sftp_subsystem_s *sftp_subsystem=(struct sftp_subsystem_s *) ptr;
    return (*sftp_subsystem->send_ops->fstat)(sftp_subsystem, sftp_r);
}

int send_sftp_setstat_ctx(void *ptr, struct sftp_request_s *sftp_r)
{
    struct sftp_subsystem_s *sftp_subsystem=(struct sftp_subsystem_s *) ptr;
    return (*sftp_subsystem->send_ops->setstat)(sftp_subsystem, sftp_r);
}

int send_sftp_fsetstat_ctx(void *ptr, struct sftp_request_s *sftp_r)
{
    struct sftp_subsystem_s *sftp_subsystem=(struct sftp_subsystem_s *) ptr;
    return (*sftp_subsystem->send_ops->fsetstat)(sftp_subsystem, sftp_r);
}

int send_sftp_readlink_ctx(void *ptr, struct sftp_request_s *sftp_r)
{
    struct sftp_subsystem_s *sftp_subsystem=(struct sftp_subsystem_s *) ptr;
    return (*sftp_subsystem->send_ops->readlink)(sftp_subsystem, sftp_r);
}

int send_sftp_symlink_ctx(void *ptr, struct sftp_request_s *sftp_r)
{
    struct sftp_subsystem_s *sftp_subsystem=(struct sftp_subsystem_s *) ptr;
    return (*sftp_subsystem->send_ops->symlink)(sftp_subsystem, sftp_r);
}

int send_sftp_block_ctx(void *ptr, struct sftp_request_s *sftp_r)
{
    struct sftp_subsystem_s *sftp_subsystem=(struct sftp_subsystem_s *) ptr;
    return (*sftp_subsystem->send_ops->block)(sftp_subsystem, sftp_r);
}

int send_sftp_unblock_ctx(void *ptr, struct sftp_request_s *sftp_r)
{
    struct sftp_subsystem_s *sftp_subsystem=(struct sftp_subsystem_s *) ptr;
    return (*sftp_subsystem->send_ops->unblock)(sftp_subsystem, sftp_r);
}

int send_sftp_realpath_ctx(void *ptr, struct sftp_request_s *sftp_r)
{
    struct sftp_subsystem_s *sftp_subsystem=(struct sftp_subsystem_s *) ptr;
    return (*sftp_subsystem->send_ops->realpath)(sftp_subsystem, sftp_r);
}