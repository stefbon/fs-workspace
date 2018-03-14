/*

  2010, 2011, 2012, 2013, 2014, 2015, 2016 Stef Bon <stefbon@gmail.com>

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

#include <inttypes.h>
#include <ctype.h>

#include <sys/stat.h>
#include <sys/param.h>
#include <sys/types.h>
#include <grp.h>
#include <getopt.h>
#include <sys/socket.h>
#include <sys/un.h>

#include "main.h"
#include "pathinfo.h"
#include "entry-management.h"
#include "directory-management.h"
#include "entry-utils.h"
#include "options.h"
#include "utils.h"

#include "logging.h"

extern struct fs_options_struct fs_options;

static void print_help(const char *progname) {

    fprintf(stdout, "General options:\n");
    fprintf(stdout, "    --help                print help\n");
    fprintf(stdout, "    --version             print version\n");
    fprintf(stdout, "    --configfile=PATH     (default: %s)\n" , FS_WORKSPACE_CONFIGFILE);

    fprintf(stdout, "\n");
    fprintf(stdout, "\n");

}

static void print_version()
{
    printf("fs-workspace version %s\n", PACKAGE_VERSION);
}

static int read_config(char *path)
{
    FILE *fp;
    int result=0;

    fp=fopen(path, "r");

    if ( fp ) {
        char line[512];
        char *sep;

	while( ! feof(fp)) {

	    if ( ! fgets(line, 512, fp)) continue;

	    sep=strchr(line, '\n');
	    if (sep) *sep='\0';

	    sep=strchr(line, '=');
	    if ( sep ) {
		char *option=line;
		char *value=sep+1;

		*sep='\0';

		convert_to(option, UTILS_CONVERT_SKIPSPACE | UTILS_CONVERT_TOLOWER);

		logoutput("read_config: read option %s value %s", option, value);

		if (strcmp(option, "fuse.attr_timeout")==0) {

		    if (strlen(value)>0) {

			fs_options.attr_timeout=strtod(value, NULL);

		    }

		} else if (strcmp(option, "fuse.entry_timeout")==0) {

		    if (strlen(value)>0) {

			fs_options.entry_timeout=strtod(value, NULL);

		    }

		} else if (strcmp(option, "fuse.negative_timeout")==0) {

		    if (strlen(value)>0) {

			fs_options.negative_timeout=strtod(value, NULL);

		    }

		} else if ( strcmp(option, "server.socket")==0 ) {

		    if ( strlen(value)>0 ) {

			fs_options.socket.path=strdup(value); /* check it does exist is later */

			if ( ! fs_options.socket.path) {

			    result=-1;
			    fprintf(stderr, "read_config: option %s with value %s cannot be parsed (error %i). Cannot continue.\n", option, value, errno);
			    goto out;

			} else {

			    fs_options.socket.len=strlen(fs_options.socket.path);
			    fs_options.socket.flags=PATHINFO_FLAGS_ALLOCATED;

			}

		    } else {

			fprintf(stderr, "read_config: option %s requires an argument. Cannot continue.\n", option);
			result=-1;
			goto out;

		    }

		} else if ( strcmp(option, "ssh.ciphers")==0 ) {

		    if ( strlen(value)>0 ) {

			fs_options.ssh_ciphers=strdup(value);

			if ( ! fs_options.ssh_ciphers) {

			    result=-1;
			    fprintf(stderr, "read_config: option %s with value %s cannot be parsed (error %i). Cannot continue.\n", option, value, errno);
			    goto out;

			}

		    } else {

			fprintf(stderr, "read_config: option %s requires an argument. Cannot continue.\n", option);
			result=-1;
			goto out;

		    }

		} else if ( strcmp(option, "ssh.usermapping")==0 ) {

		    if ( strlen(value)>0 ) {
			unsigned int mapping=0;

			mapping=atoi(value);

			if (mapping==FS_WORKSPACE_SSH_USERMAPPING_MAP || mapping==FS_WORKSPACE_SSH_USERMAPPING_NONE) {

			    fs_options.ssh_usermapping=mapping;

			}

		    } else {

			fprintf(stderr, "read_config: option %s requires an argument. Cannot continue.\n", option);
			result=-1;
			goto out;

		    }

		} else if ( strcmp(option, "ssh.init.timeout")==0 ) {

		    if ( strlen(value)>0 ) {
			unsigned int timeout=0;

			timeout=atoi(value);

			/* only allow sane values */

			if (timeout>0 && timeout<20) fs_options.ssh_init_timeout=timeout;

		    } else {

			fprintf(stderr, "read_config: option %s requires an argument. Cannot continue.\n");
			result=-1;
			goto out;

		    }

		} else if ( strcmp(option, "ssh.session.timeout")==0 ) {

		    if ( strlen(value)>0 ) {
			unsigned int timeout=0;

			timeout=atoi(value);

			/* only allow sane values */

			if (timeout>0 && timeout<20) fs_options.ssh_session_timeout=timeout;

		    } else {

			fprintf(stderr, "read_config: option %s requires an argument. Cannot continue.\n", option);
			result=-1;
			goto out;

		    }

		} else if ( strcmp(option, "ssh.exec.timeout")==0 ) {

		    if ( strlen(value)>0 ) {
			unsigned int timeout=0;

			timeout=atoi(value);

			/* only allow sane values */

			if (timeout>0 && timeout<20) fs_options.ssh_exec_timeout=timeout;

		    } else {

			fprintf(stderr, "read_config: option %s requires an argument. Cannot continue.\n", option);
			result=-1;
			goto out;

		    }

		}

	    }

	}

	out:

	fclose(fp);

    }

    return result;

}

int parse_arguments(int argc, char *argv[], unsigned int *error)
{
    static struct option long_options[] = {
	{"help", 		optional_argument, 		0, 0},
	{"version", 		optional_argument, 		0, 0},
	{"configfile", 		optional_argument,		0, 0},
	{0,0,0,0}
	};
    int res, long_options_index=0, result=0;
    struct stat st;

    memset(&fs_options, 0, sizeof(struct fs_options_struct));

    /* set defaults */

    fs_options.configfile.path=NULL;
    fs_options.configfile.len=0;
    fs_options.configfile.flags=0;

    fs_options.basemap.path=NULL;
    fs_options.basemap.len=0;
    fs_options.basemap.flags=0;

    fs_options.discovermap.path=NULL;
    fs_options.discovermap.len=0;
    fs_options.discovermap.flags=0;

    fs_options.attr_timeout=1.0;
    fs_options.entry_timeout=1.0;
    fs_options.negative_timeout=1.0;

    fs_options.ssh_ciphers=NULL;
    fs_options.ssh_compression=NULL;
    fs_options.ssh_pubkeys=NULL;
    fs_options.ssh_keyx=NULL;
    fs_options.ssh_mac=NULL;

    fs_options.user_unknown=NULL;
    fs_options.user_nobody=NULL;

    fs_options.ssh_usermapping=FS_WORKSPACE_SSH_USERMAPPING_DEFAULT;

    while(1) {

	res = getopt_long(argc, argv, "", long_options, &long_options_index);

	if (res==-1) break;

	switch (res) {

	    case 0:

		/* a long option */

		if ( strcmp(long_options[long_options_index].name, "help")==0 ) {

		    print_help(argv[0]);
		    result=1;
		    *error=0;
		    goto finish;


		} else if ( strcmp(long_options[long_options_index].name, "version")==0 ) {

		    print_version(argv[0]);
		    result=1;
		    *error=0;
		    goto finish;


		} else if ( strcmp(long_options[long_options_index].name, "configfile")==0 ) {

		    if ( optarg ) {

			fs_options.configfile.path=realpath(optarg, NULL);

			if ( ! fs_options.configfile.path) {

			    result=-1;
			    *error=ENOMEM;
			    fprintf(stderr, "Error:(%i) option --configfile=%s cannot be parsed. Cannot continue.\n", errno, optarg);
			    goto out;

			} else {

			    fs_options.configfile.len=strlen(fs_options.configfile.path);
			    fs_options.configfile.flags=PATHINFO_FLAGS_ALLOCATED | PATHINFO_FLAGS_INUSE;

			}

		    } else {

			fprintf(stderr, "Error: option --configfile requires an argument. Cannot continue.\n");
			result=-1;
			*error=EINVAL;
			goto out;

		    }

		}

	    case '?':

		fprintf(stderr, "Error: option %s not reckognized.\n", optarg);
		result=-1;
		*error=EINVAL;
		goto finish;

	    default:

		fprintf(stdout,"Warning: getoption returned character code 0%o!\n", res);

	}

    }

    out:

    if (fs_options.configfile.path) {

	result=read_config(fs_options.configfile.path);

    } else {

	result=read_config(FS_WORKSPACE_CONFIGFILE);

    }

    if (! fs_options.socket.path) {

	fs_options.socket.path=strdup(FS_WORKSPACE_SOCKET);

	if ( ! fs_options.socket.path) {

	    result=-1;
	    fprintf(stderr, "parse_arguments: socket path %s cannot be parsed (error %i). Cannot continue.\n", FS_WORKSPACE_SOCKET, errno);

	} else {

	    fs_options.socket.len=strlen(fs_options.socket.path);
	    fs_options.socket.flags=PATHINFO_FLAGS_ALLOCATED;

	}

    }

    finish:

    return result;

}

void free_options()
{
    free_path_pathinfo(&fs_options.configfile);
    free_path_pathinfo(&fs_options.basemap);
    free_path_pathinfo(&fs_options.discovermap);
    free_path_pathinfo(&fs_options.socket);
}
