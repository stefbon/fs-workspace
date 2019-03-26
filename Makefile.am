sbin_PROGRAMS = fs-workspace

fs_workspace_CFLAGS = $(GLIB_CFLAGS) $(LIBGCRYPT_CFLAGS) $(SYSTEMD_CFLAGS) $(QT5_CFLAGS) $(AVAHI_CORE_CFLAGS) $(AVAHI_CLIENT_CFLAGS) -g -D_FILE_OFFSET_BITS=64 -lz -lpthread -fPIC -lm -I . -I common-utils -I ssh -O2 -Wall -Wno-unused-but-set-variable -Wno-uninitialized -Wno-unused-variable -Wno-unused-label -Wno-unused-function
fs_workspace_CPPFLAGS = $(GLIB_CFLAGS) $(LIBGCRYPT_CFLAGS) $(SYSTEMD_CFLAGS) $(QT5_CFLAGS) $(AVAHI_CORE_CFLAGS) $(AVAHI_CLIENT_CFLAGS) -g -D_FILE_OFFSET_BITS=64 -lz -lpthread -fPIC -lm -I . -I common-utils -I ssh -O2 -Wall -Wno-unused-but-set-variable -Wno-uninitialized -Wno-unused-variable -Wno-unused-label -Wno-unused-function
fs_workspace_LDADD = $(GLIB_LIBS) $(LIBGCRYPT_LIBS) $(SYSTEMD_LIBS) $(QT5_LIBS) $(AVAHI_CORE_LIBS) $(AVAHI_CLIENT_LIBS) $(LDFLAGS)

fs_workspace_SOURCES =  common-utils/fuse-directory.c common-utils/fuse-dentry.c common-utils/fuse-utils.c common-utils/path-caching.c \
			common-utils/fuse-interface.c common-utils/fuse-fs.c \
			common-utils/fuse-fs-common.c common-utils/fuse-fs-virtual.c common-utils/fuse-fs-special.c \
			common-utils/fuse-context-fs-common.c common-utils/fuse-context-fs-root.c common-utils/fuse-context-fs.c \
			monitormounts.c \
			common-utils/beventloop.c common-utils/beventloop-signal.c common-utils/beventloop-timer.c common-utils/beventloop-xdata.c \
			common-utils/pidfile.c \
			options.c \
			main.c \
			common-utils/localsocket.c \
			discover.c discover/discover-staticfile.c discover/discover-avahi.c \
			common-utils/workspaces.c common-utils/workspace-utils.c common-utils/workspace-session.c common-utils/workspace-context.c \
			common-utils/workspace-address.c \
			common-utils/utils.c common-utils/network-utils.c common-utils/pathinfo.c \
			common-utils/workerthreads.c \
			common-utils/simple-hash.c common-utils/simple-list.c common-utils/simple-locking.c \
			common-utils/skiplist.c common-utils/skiplist-delete.c common-utils/skiplist-find.c common-utils/skiplist-insert.c common-utils/skiplist-seek.c \
			common-utils/mountinfo-monitor.c common-utils/mountinfo-utils.c common-utils/mountinfo.c \
			common-utils/monitorsessions.c \
			common-utils/fschangenotify.c \
			common-utils/logging.c \
			handlemime.c \
			mimetype.cpp \
			backup/backup-common.c backup/send.c \
			fuse-sftp.c fuse-backup.c fuse-network.c \
			sftp/fuse-sftp-common.c sftp/fuse-sftp-extensions.c \
			sftp/fuse-sftp-fs-init.c sftp/fuse-sftp-lock.c  sftp/fuse-sftp-mk.c \
			sftp/fuse-sftp-getattr.c sftp/fuse-sftp-lookup.c sftp/fuse-sftp-fsnotify.c sftp/fuse-sftp-open.c sftp/fuse-sftp-opendir.c sftp/fuse-sftp-symlink.c \
			sftp/fuse-sftp-rm.c sftp/fuse-sftp-setattr.c sftp/fuse-sftp-statfs.c sftp/fuse-sftp-realpath.c sftp/fuse-sftp-xattr.c \
			sftp/attr-common.c sftp/attr-v03.c sftp/attr-v04.c sftp/attr-v05.c sftp/attr-v06.c \
			sftp/common.c sftp/extensions.c sftp/request-hash.c sftp/common-admin.c sftp/common-utils.c \
			sftp/recv-common.c sftp/recv-v03.c sftp/recv-v04.c sftp/recv-v05.c sftp/recv-v06.c \
			sftp/send-common.c sftp/send-v03.c sftp/send-v04.c sftp/send-v05.c sftp/send-v06.c \
			sftp/user-v03.c sftp/user-v04.c sftp/usermapping.c sftp/time.c \
			ssh/fuse-ssh-fs-init.c \
			ssh/channel/command.c ssh/channel/exec.c ssh/channel/init.c ssh/channel/payload.c ssh/channel/shell.c ssh/channel/startclose.c \
			ssh/channel/table.c ssh/channel/uri.c ssh/channel/utils.c \
			ssh/ssh-common-protocol.c ssh/ssh-common.c ssh/ssh-common-list.c \
			ssh/ssh-connection.c \
			ssh/ssh-data.c \
			ssh/datatypes/ssh-namelist.c ssh/datatypes/ssh-payload.c ssh/datatypes/ssh-string.c ssh/datatypes/ssh-mpint.c ssh/datatypes/ssh-uint.c ssh/datatypes/ssh-msg-buffer.c \
			ssh/extensions/extension.c \
			ssh/ssh-hostinfo.c \
			ssh/keyexchange/algo-exchange.c ssh/keyexchange/compare.c ssh/keyexchange/createkeys.c ssh/keyexchange/dh.c ssh/keyexchange/ecdh.c ssh/keyexchange/key-exchange.c ssh/keyexchange/keyx.c \
			ssh/ssh-language.c \
			ssh/ssh-pubkey.c \
			ssh/pk/asn1.c ssh/pk/openssh-localdb.c ssh/pk/openssh-utils.c ssh/pk/openssh-cert.c ssh/pk/pk-create.c \
			ssh/pk/pk-types.c ssh/pk/pk-keys.c ssh/pk/pk-compare.c ssh/pk/pk-keystore.c ssh/pk/pk-keystore-openssh.c \
			ssh/pk/pk-layout.c ssh/pk/pk-read-private.c ssh/pk/pk-readwrite-public.c ssh/pk/pk-sign.c ssh/pk/pk-utils.c ssh/pk/pk-verify.c \
			ssh/ssh-utils.c \
			ssh/ssh-userauth.c ssh/userauth/pubkey.c ssh/userauth/utils.c ssh/userauth/hostbased.c ssh/userauth/none.c ssh/userauth/password.c \
			ssh/receive/decompress.c ssh/receive/decompress-none.c ssh/receive/decompressors.c ssh/receive/decrypt.c ssh/receive/decrypt-chacha20-poly1305.c \
			ssh/receive/decrypt-generic.c ssh/receive/decryptors.c ssh/receive/greeter.c ssh/receive/init.c ssh/receive/msg-channel.c ssh/receive/msg-transport.c ssh/receive/msg-userauth.c \
			ssh/receive/payload.c ssh/receive/read-buffer.c ssh/receive/read-socket.c \
			ssh/send/compress.c ssh/send/compress-none.c ssh/send/compressors.c ssh/send/encrypt.c ssh/send/encrypt-chacha20-poly1305.c ssh/send/encrypt-generic.c \
			ssh/send/encryptors.c ssh/send/greeter.c ssh/send/init.c ssh/send/msg-channel.c ssh/send/msg-transport.c ssh/send/msg-userauth.c ssh/send/send.c ssh/send/write-socket.c 
