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
#include "utils.h"
#include "fuse-dentry.h"
#include "fuse-directory.h"
#include "fuse-utils.h"
#include "options.h"
#include "logging.h"

extern struct fs_options_s fs_options;

static void print_help(const char *progname) {

    fprintf(stdout, "General options:\n");
    fprintf(stdout, "    --help                print help\n");
    fprintf(stdout, "    --version             print version\n");
    fprintf(stdout, "    --configfile=PATH     (default: %s)\n" , _OPTIONS_MAIN_CONFIGFILE);

    fprintf(stdout, "\n");
    fprintf(stdout, "\n");

}

static void print_version()
{
    printf("fs-workspace version %s\n", PACKAGE_VERSION);
}

static void parse_network_discover_option(struct network_options_s *network, char *value)
{
    char *sep=NULL;
    char *start=value;

    findmethod:

    sep=strchr(value, ',');
    if (sep) *sep='\0';

    if (strcmp(start, "avahi")==0) {

	network->flags |= _OPTIONS_NETWORK_DISCOVER_METHOD_AVAHI;

    } else if (strcmp(start, "static-file")==0) {

	network->flags |= _OPTIONS_NETWORK_DISCOVER_METHOD_FILE;

    } else {

	fprintf(stderr, "parse_network_discover_option: %s not reckognized\n", start);

    }

    if (sep) {

	*sep=',';
	start=sep+1;
	goto findmethod;

    }

}

static void convert_double_to_timespec(struct timespec *timeout, double tmp)
{
    timeout->tv_sec=(uint64_t) tmp;
    timeout->tv_nsec=(uint64_t) ((tmp - timeout->tv_sec) * 1000000000);
}

static void parse_fuse_timeout_option(struct timespec *timeout, char *value)
{
    double tmp=strtod(value, NULL);
    convert_double_to_timespec(timeout, tmp);
}

static int read_config(char *path)
{
    FILE *fp;
    int result=0;
    char *line=NULL;
    char *sep;
    size_t size=0;
    unsigned int len=0;

    fprintf(stdout, "read_config: open %s\n", path);

    fp=fopen(path, "r");
    if ( fp ==NULL ) return 0;

    while (getline(&line, &size, fp)>0) {

	sep=memchr(line, '\n', size);
	if (sep) *sep='\0';
	len=strlen(line);
	if (len==0) continue;

	sep=memchr(line, '=', len);

	if (sep) {
	    char option[sep - line + 1];
	    char *value=sep + 1;

	    memcpy(option, line, (unsigned int)(sep - line));
	    option[(unsigned int)(sep - line + 1)]='\0';
	    convert_to(option, UTILS_CONVERT_SKIPSPACE | UTILS_CONVERT_TOLOWER);

	    if (strlen(option)==0 || option[0]== '#') continue;

	    if (strcmp(option, "fuse.fuse_attr_timeout")==0) {

		if (strlen(value)>0) parse_fuse_timeout_option(&fs_options.fuse.attr_timeout, value);

	    } else if (strcmp(option, "fuse.fuse_entry_timeout")==0) {

		if (strlen(value)>0) parse_fuse_timeout_option(&fs_options.fuse.entry_timeout, value);

	    } else if (strcmp(option, "fuse.fuse_negative_timeout")==0) {

		if (strlen(value)>0) parse_fuse_timeout_option(&fs_options.fuse.negative_timeout, value);

	    } else if ( strcmp(option, "main.server.socket")==0 ) {

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

	    } else if (strcmp(option, "network.discover_methods")==0) {

		if ( strlen(value)>0 ) {

		    parse_network_discover_option(&fs_options.network, value);

		} else {

		    fprintf(stderr, "read_config: option %s requires an argument. Cannot continue.\n", option);
		    result=-1;
		    goto out;

		}

	    } else if ( strcmp(option, "network.discover_static_file")==0 ) {

		if ( strlen(value)>0 ) {

		    fs_options.network.discover_static_file=strdup(value); /* check it does exist is later */

		    if ( ! fs_options.network.discover_static_file) {

			result=-1;
			fprintf(stderr, "read_config: option %s with value %s cannot be parsed (error %i). Cannot continue.\n", option, value, errno);
			goto out;

		    }

		} else {

		    fprintf(stderr, "read_config: option %s requires an argument. Cannot continue.\n", option);
		    result=-1;
		    goto out;

		}

	    } else if (strcmp(option, "ssh.support.ext-info")==0) {

		if ( strlen(value)>0 ) {

		    if (strcmp(value, "1")==0 || strcmp(value, "yes")==0) {

			fs_options.ssh.flags |= _OPTIONS_SSH_FLAG_SUPPORT_EXT_INFO;

		    }

		} else {

		    fprintf(stderr, "read_config: option %s requires an argument. Cannot continue.\n", option);
		    result=-1;
		    goto out;

		}

	    } else if (strcmp(option, "ssh.extensions")==0) {

		/* if extensions are defined in config that overrides the default
		    note that these extensions are only used when ext-info is enabled */

		if (strlen(value)>0) {
		    char *start=value;
		    char *sep=NULL;

		    fs_options.ssh.extensions=0;

		    searchextension:

		    sep=strchr(start, ',');
		    if (sep) *sep='\0';

		    if (strcmp(start, "server-sig-algs")==0) {

			fs_options.ssh.extensions|=(1 << (_OPTIONS_SSH_EXTENSION_SERVER_SIG_ALGS - 1));

		    } else if (strcmp(start, "delay-compression")==0) {

			fs_options.ssh.extensions|=(1 << (_OPTIONS_SSH_EXTENSION_DELAY_COMPRESSION - 1));

		    } else if (strcmp(start, "no-flow-control")==0) {

			fs_options.ssh.extensions|=(1 << (_OPTIONS_SSH_EXTENSION_NO_FLOW_CONTROL - 1));

		    } else if (strcmp(start, "elevation")==0) {

			fs_options.ssh.extensions|=(1 << (_OPTIONS_SSH_EXTENSION_ELEVATION - 1));

		    }

		    if (sep) {

			*sep=',';
			start=sep+1;
			goto searchextension;

		    }

		}

	    } else if (strcmp(option, "ssh.crypto_cipher_algos")==0 || strcmp(option, "ssh.crypto_mac_algos")==0 ||
			strcmp(option, "ssh.pubkey_algos")==0 || strcmp(option, "ssh.compression_algos")==0 || strcmp(option, "ssh.keyx_algos")==0) {

		if ( strlen(value)>0 ) {
		    char *tmp=strdup(value);

		    if ( ! tmp) {

			result=-1;
			fprintf(stderr, "read_config: option %s with value %s cannot be parsed (error %i). Cannot continue.\n", option, value, errno);
			goto out;

		    }

		    if (strcmp(option, "ssh.crypto_cipher_algos")==0) {

			fs_options.ssh.crypto_cipher_algos=tmp;

		    } else if (strcmp(option, "ssh.crypto_mac_algos")==0) {

			fs_options.ssh.crypto_mac_algos=tmp;

		    } else if (strcmp(option, "ssh.pubkey_algos")==0) {

			fs_options.ssh.pubkey_algos=tmp;

		    } else if (strcmp(option, "ssh.compression_algos")==0) {

			fs_options.ssh.compression_algos=tmp;

		    } else if (strcmp(option, "ssh.keyx_algos")==0) {

			fs_options.ssh.keyx_algos=tmp;

		    }

		} else {

		    fprintf(stderr, "read_config: option %s requires an argument. Cannot continue.\n", option);
		    result=-1;
		    goto out;

		}

	    } else if ( strcmp(option, "ssh.init.timeout")==0 ) {

		if ( strlen(value)>0 ) {

		    fs_options.ssh.init_timeout=atoi(value);

		} else {

		    fprintf(stderr, "read_config: option %s requires an argument. Cannot continue.\n", option);
		    result=-1;
		    goto out;

		}

	    } else if ( strcmp(option, "ssh.session.timeout")==0 ) {

		if ( strlen(value)>0 ) {

		    fs_options.ssh.session_timeout=atoi(value);

		} else {

		    fprintf(stderr, "read_config: option %s requires an argument. Cannot continue.\n", option);
		    result=-1;
		    goto out;

		}

	    } else if ( strcmp(option, "ssh.exec.timeout")==0 ) {

		if ( strlen(value)>0 ) {

		    fs_options.ssh.exec_timeout=atoi(value);

		} else {

		    fprintf(stderr, "read_config: option %s requires an argument. Cannot continue.\n", option);
		    result=-1;
		    goto out;

		}

	    } else if ( strcmp(option, "sftp.usermapping.type")==0 ) {

		if ( strlen(value)>0 ) {

		    if (strcmp(value, "file")==0) {

			fs_options.sftp.usermapping_type=_OPTIONS_SFTP_USERMAPPING_FILE;

		    } else if (strcmp(value, "none")==0) {

			fs_options.sftp.usermapping_type=_OPTIONS_SFTP_USERMAPPING_NONE;

		    } else if (strcmp(value, "map")==0) {

			fs_options.sftp.usermapping_type=_OPTIONS_SFTP_USERMAPPING_MAP;

		    } else {

			fprintf(stderr, "read_config: value %s for options %s not reckognized. Cannot continue.\n", value, option);
			result=-1;
			goto out;

		    }

		} else {

		    fprintf(stderr, "read_config: option %s requires an argument. Cannot continue.\n", option);
		    result=-1;
		    goto out;

		}

	    } else if (strcmp(option, "sftp.usermapping.user.unknown")==0 || strcmp(option, "sftp.usermapping.user.nobody")==0) {

		if ( strlen(value)>0 ) {
		    char *tmp=strdup(value);

		    if (! tmp) {

			result=-1;
			fprintf(stderr, "read_config: option %s with value %s cannot be parsed (error %i). Cannot continue.\n", option, value, errno);
			goto out;

		    }

		    if (strcmp(option, "sftp.usermapping.user.unknown")==0) {

			fs_options.sftp.usermapping_user_unknown=tmp;

		    } else if (strcmp(option, "sftp.usermapping.user.nobody")==0) {

			fs_options.sftp.usermapping_user_nobody=tmp;

		    }

		} else {

		    fprintf(stderr, "read_config: option %s requires an argument. Cannot continue.\n", option);
		    result=-1;
		    goto out;

		}

	    } else if (strcmp(option, "sftp.network.name")==0) {

		if ( strlen(value)>0 ) {

		    fs_options.sftp.network_name=strdup(value);

		    if (fs_options.sftp.network_name==NULL) {

			result=-1;
			fprintf(stderr, "read_config: option %s with value %s cannot be parsed (error %i). Cannot continue.\n", option, value, errno);
			goto out;

		    }

		} else {

		    fprintf(stderr, "read_config: option %s requires an argument. Cannot continue.\n", option);
		    result=-1;
		    goto out;

		}

	    } else if (strcmp(option, "sftp.network.show_domainname")==0) {

		if ( strlen(value)>0 ) {

		    if (strcmp(value, "1")==0 || strcmp(value, "yes")==0) {

			fs_options.sftp.flags |= _OPTIONS_SFTP_FLAG_SHOW_DOMAINNAME;

		    }

		} else {

		    fprintf(stderr, "read_config: option %s requires an argument. Cannot continue.\n", option);
		    result=-1;
		    goto out;

		}

	    } else if (strcmp(option, "sftp.network.home_use_remotename")==0) {

		if ( strlen(value)>0 ) {

		    if (strcmp(value, "1")==0 || strcmp(value, "yes")==0) {

			fs_options.sftp.flags |= _OPTIONS_SFTP_FLAG_HOME_USE_REMOTENAME;

		    }

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
    if (line) free(line);

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

    memset(&fs_options, 0, sizeof(struct fs_options_s));

    /* set defaults */

    init_pathinfo(&fs_options.configfile);
    init_pathinfo(&fs_options.basemap);
    init_pathinfo(&fs_options.socket);

    /* fuse */

    convert_double_to_timespec(&fs_options.fuse.attr_timeout, _OPTIONS_FUSE_ATTR_TIMEOUT);
    convert_double_to_timespec(&fs_options.fuse.entry_timeout, _OPTIONS_FUSE_ENTRY_TIMEOUT);
    convert_double_to_timespec(&fs_options.fuse.negative_timeout, _OPTIONS_FUSE_NEGATIVE_TIMEOUT);

    /* create or not the service specific network name like SMB, NFS and SFTP */

    fs_options.fuse.flags=_OPTIONS_FUSE_FLAG_NETWORK_IGNORE_SERVICE;

    /* network */

    fs_options.network.flags=0;
    fs_options.network.discover_static_file=NULL;
    fs_options.network.path_icon_network=NULL;
    fs_options.network.path_icon_domain=NULL;
    fs_options.network.path_icon_server=NULL;
    fs_options.network.path_icon_share=NULL;
    fs_options.network.network_icon=_OPTIONS_NETWORK_ICON_OVERRULE;
    fs_options.network.domain_icon=_OPTIONS_NETWORK_ICON_OVERRULE;
    fs_options.network.server_icon=_OPTIONS_NETWORK_ICON_OVERRULE;
    fs_options.network.share_icon=_OPTIONS_NETWORK_ICON_OVERRULE;

    /* ssh */

    fs_options.ssh.flags=_OPTIONS_SSH_FLAG_SUPPORT_EXT_INFO;

    /* default support all extensions mentioned in RFC 8308
	are there more ? */

    fs_options.ssh.extensions=(1 << (_OPTIONS_SSH_EXTENSION_SERVER_SIG_ALGS - 1)) | (1 << (_OPTIONS_SSH_EXTENSION_DELAY_COMPRESSION - 1)) |
				(1 << (_OPTIONS_SSH_EXTENSION_NO_FLOW_CONTROL - 1)) | (1 << (_OPTIONS_SSH_EXTENSION_ELEVATION - 1));

    fs_options.ssh.crypto_cipher_algos=NULL;
    fs_options.ssh.compression_algos=NULL;
    fs_options.ssh.pubkey_algos=NULL;
    fs_options.ssh.keyx_algos=NULL;
    fs_options.ssh.crypto_mac_algos=NULL;
    fs_options.ssh.init_timeout=_OPTIONS_SSH_INIT_TIMEOUT_DEFAULT;
    fs_options.ssh.session_timeout=_OPTIONS_SSH_SESSION_TIMEOUT_DEFAULT;
    fs_options.ssh.exec_timeout=_OPTIONS_SSH_EXEC_TIMEOUT_DEFAULT;
    fs_options.ssh.backend=_OPTIONS_SSH_BACKEND_OPENSSH;
    fs_options.ssh.trustdb=_OPTIONS_SSH_TRUSTDB_OPENSSH;

    /* sftp */

    fs_options.sftp.usermapping_user_unknown=NULL;
    fs_options.sftp.usermapping_user_nobody=NULL;
    fs_options.sftp.usermapping_type=_OPTIONS_SFTP_USERMAPPING_DEFAULT;
    fs_options.sftp.usermapping_file=NULL;
    fs_options.sftp.flags=_OPTIONS_SFTP_FLAG_SHOW_DOMAINNAME | _OPTIONS_SFTP_FLAG_HOME_USE_REMOTENAME | _OPTIONS_SFTP_FLAG_SYMLINK_ALLOW_PREFIX;
    fs_options.sftp.packet_maxsize=_OPTIONS_SFTP_PACKET_MAXSIZE;
    fs_options.sftp.network_name=_OPTIONS_SFTP_NETWORK_NAME_DEFAULT;

    /* nfs */

    fs_options.nfs.flags=_OPTIONS_NFS_FLAG_SHOW_DOMAINNAME;
    fs_options.nfs.packet_maxsize=_OPTIONS_NFS_PACKET_MAXSIZE;
    fs_options.nfs.network_name=NULL;

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

	result=read_config(_OPTIONS_MAIN_CONFIGFILE);

    }

    if (result==-1) goto finish;

    if (! fs_options.socket.path) {

	fs_options.socket.path=strdup(_OPTIONS_MAIN_SOCKET);

	if ( ! fs_options.socket.path) {

	    result=-1;
	    fprintf(stderr, "parse_arguments: socket path %s cannot be parsed (error %i). Cannot continue.\n", _OPTIONS_MAIN_SOCKET, errno);
	    goto finish;

	} else {

	    fs_options.socket.len=strlen(fs_options.socket.path);
	    fs_options.socket.flags=PATHINFO_FLAGS_ALLOCATED;

	}

    }

    if (fs_options.network.flags & _OPTIONS_NETWORK_DISCOVER_METHOD_FILE) {

	if (! fs_options.network.discover_static_file) {

	    /* take default */

	    fs_options.network.discover_static_file=strdup(_OPTIONS_NETWORK_DISCOVER_STATIC_FILE_DEFAULT);
	    if (fs_options.network.discover_static_file==NULL) {

		result=-1;
		fprintf(stderr, "parse_arguments: error %i allocating memory. Cannot continue.\n", errno);
		goto finish;

	    }

	}

    } else {

	if (fs_options.network.discover_static_file) {

	    /* not used */

	    free(fs_options.network.discover_static_file);
	    fs_options.network.discover_static_file=NULL;

	}

    }

    if (fs_options.sftp.flags==0) fs_options.sftp.flags|=_OPTIONS_SFTP_FLAG_HOME_USE_REMOTENAME;

    finish:

    return result;

}

void free_options()
{

    free_path_pathinfo(&fs_options.configfile);
    free_path_pathinfo(&fs_options.basemap);
    free_path_pathinfo(&fs_options.socket);

    if (fs_options.ssh.crypto_cipher_algos) free(fs_options.ssh.crypto_cipher_algos);
    if (fs_options.ssh.crypto_mac_algos) free(fs_options.ssh.crypto_mac_algos);
    if (fs_options.ssh.pubkey_algos) free(fs_options.ssh.pubkey_algos);
    if (fs_options.ssh.compression_algos) free(fs_options.ssh.compression_algos);
    if (fs_options.ssh.keyx_algos) free(fs_options.ssh.keyx_algos);

    // if (fs_options.sftp.network_name) free(fs_options.sftp.network_name);
    if (fs_options.sftp.usermapping_file) free(fs_options.sftp.usermapping_file);
    if (fs_options.sftp.usermapping_user_nobody) free(fs_options.sftp.usermapping_user_nobody);
    if (fs_options.sftp.usermapping_user_unknown) free(fs_options.sftp.usermapping_user_unknown);

    if (fs_options.network.discover_static_file) free(fs_options.network.discover_static_file);

}
