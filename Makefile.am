sbin_PROGRAMS = fs-workspace

fs_workspace_CFLAGS = $(GLIB_CFLAGS) $(LIBGCRYPT_CFLAGS) $(SYSTEMD_CFLAGS) $(AVAHI_CORE_CFLAGS) $(AVAHI_CLIENT_CFLAGS) -g -D_FILE_OFFSET_BITS=64 -lz -fPIC -lm -I common-utils -I ssh -O -Wall -Wno-unused-but-set-variable -Wno-uninitialized -Wno-unused-variable -Wno-unused-label -Wunused-function
fs_workspace_CPPFLAGS = $(GLIB_CFLAGS) $(LIBGCRYPT_CFLAGS) $(SYSTEMD_CFLAGS) $(AVAHI_CORE_CFLAGS) $(AVAHI_CLIENT_CFLAGS) -g -D_FILE_OFFSET_BITS=64 -lz -fPIC -lm -I common-utils -I ssh -O -Wall -Wno-unused-but-set-variable -Wno-uninitialized -Wno-unused-variable -Wno-unused-label -Wunused-function
fs_workspace_LDADD = $(GLIB_LIBS) $(LIBGCRYPT_LIBS) $(SYSTEMD_LIBS) $(AVAHI_CORE_LIBS) $(AVAHI_CLIENT_LIBS) $(LDFLAGS)

fs_workspace_SOURCES =  common-utils/directory-management.c common-utils/entry-management.c common-utils/entry-utils.c common-utils/path-caching.c \
			common-utils/fuse-interface.c common-utils/fuse-fs.c \
			common-utils/fuse-fs-common.c common-utils/fuse-fs-virtual.c common-utils/fuse-fs-special.c \
			common-utils/fuse-context-fs-common.c common-utils/fuse-context-fs-root.c common-utils/fuse-context-fs.c \
			monitormounts.c \
			common-utils/beventloop.c common-utils/beventloop-signal.c common-utils/beventloop-timer.c common-utils/beventloop-xdata.c \
			common-utils/pidfile.c \
			options.c \
			main.c \
			common-utils/localsocket.c \
			discover.c discover/discover-avahi.c \
			common-utils/workspaces.c common-utils/workspace-utils.c common-utils/workspace-session.c common-utils/workspace-context.c \
			common-utils/utils.c common-utils/pathinfo.c \
			common-utils/workerthreads.c \
			common-utils/simple-hash.c common-utils/simple-list.c \
			common-utils/skiplist.c common-utils/skiplist-delete.c common-utils/skiplist-find.c common-utils/skiplist-insert.c common-utils/skiplist-seek.c \
			common-utils/mountinfo-monitor.c common-utils/mountinfo-utils.c common-utils/mountinfo.c \
			common-utils/monitorsessions.c \
			common-utils/fschangenotify.c \
			fuse-sftp.c fuse-backup.c fuse-network.c \
			sftp/fuse-sftp-common.c \
			sftp/fuse-sftp-fs-init.c sftp/fuse-sftp-lock.c  sftp/fuse-sftp-mk.c sftp/fuse-sftp-fsnotify.c \
			sftp/fuse-sftp-getattr.c sftp/fuse-sftp-lookup.c sftp/fuse-sftp-open.c sftp/fuse-sftp-opendir.c sftp/fuse-sftp-symlink.c \
			sftp/fuse-sftp-rm.c sftp/fuse-sftp-setattr.c sftp/fuse-sftp-statfs.c sftp/fuse-sftp-realpath.c \
			sftp/sftp-attr-common.c sftp/sftp-attr-v03.c sftp/sftp-attr-v04.c sftp/sftp-attr-v05.c sftp/sftp-attr-v06.c \
			sftp/sftp-common.c sftp/sftp-request-hash.c sftp/sftp-common-admin.c sftp/sftp-common-utils.c \
			sftp/sftp-recv-common.c sftp/sftp-recv-v03.c sftp/sftp-recv-v04.c sftp/sftp-recv-v05.c sftp/sftp-recv-v06.c \
			sftp/sftp-send-common.c sftp/sftp-send-v03.c sftp/sftp-send-v04.c sftp/sftp-send-v05.c sftp/sftp-send-v06.c \
			sftp/sftp-user-v03.c sftp/sftp-user-v04.c sftp/sftp-usermapping.c \
			ssh/fuse-ssh-fs-init.c \
			ssh/ctx-keystore-openssh.c ssh/ctx-keystore-openssh-generic.c ssh/ctx-keystore-openssh-config.c ssh/ctx-keystore-openssh-utils.c ssh/ctx-keystore.c \
			ssh/ctx-keystore-openssh-knownhosts.c ssh/ctx-options.c \
			ssh/ssh-channel.c ssh/ssh-admin-channel.c ssh/ssh-channel-table.c ssh/ssh-channel-utils.c\
			ssh/ssh-common-protocol.c ssh/ssh-common.c ssh/ssh-common-list.c \
			ssh/ssh-compression.c \
			ssh/ssh-connection.c \
			ssh/ssh-data.c \
			ssh/ssh-encryption-libgcrypt.c ssh/ssh-encryption.c ssh/ssh-encryption-chacha20-poly1305-libgcrypt.c\
			ssh/ssh-hostinfo.c \
			ssh/ssh-kexinit.c ssh/ssh-kex.c \
			ssh/ssh-keyx-dh-libgcrypt.c ssh/ssh-keyx-dh.c ssh/ssh-keyx.c \
			ssh/ssh-language.c \
			ssh/ssh-mac-libgcrypt.c ssh/ssh-mac.c ssh/ssh-mac-chacha20-poly1305-libgcrypt.c \
			ssh/ssh-pubkey.c ssh/ssh-pubkey-layout.c ssh/ssh-pubkey-utils.c \
			ssh/ssh-pubkey-libgcrypt.c ssh/ssh-pubkey-utils-libgcrypt.c ssh/ssh-pubkey-format-libgcrypt.c \
			ssh/ssh-receive-channel.c \
			ssh/ssh-receive-greeter.c \
			ssh/ssh-queue-payload.c \
			ssh/ssh-queue-rawdata.c \
			ssh/ssh-receive-transport.c \
			ssh/ssh-receive-userauth.c \
			ssh/ssh-receive-waitreply.c \
			ssh/ssh-receive.c \
			ssh/ssh-send-channel.c \
			ssh/ssh-send-greeter.c \
			ssh/ssh-send-kexinit.c \
			ssh/ssh-send-transport.c \
			ssh/ssh-send-userauth.c \
			ssh/ssh-send.c \
			ssh/ssh-userauth.c ssh/ssh-userauth-pubkey.c ssh/ssh-userauth-hostbased.c ssh/ssh-userauth-utils.c \
			ssh/ssh-utils-libgcrypt.c ssh/ssh-utils.c

