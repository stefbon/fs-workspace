/*
  2010, 2011, 2012, 2013, 2014, 2015, 2016, 2017 Stef Bon <stefbon@gmail.com>

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

#ifndef FS_WORKSPACE_SSH_COMMON_H
#define FS_WORKSPACE_SSH_COMMON_H

#include <sys/socket.h>
#include <sys/un.h>
#include <arpa/inet.h>
#include <pwd.h>

#include "workspace-interface.h"
#include "simple-list.h"
#include "simple-locking.h"
#include "ssh-datatypes.h"
#include "ssh-pk.h"

struct ssh_packet_s {
    unsigned int 			len;
    unsigned int 			size;
    unsigned char			padding;
    unsigned int 			error;
    unsigned int			sequence;
    unsigned char			type;
    unsigned int			decrypted;
    char 				*buffer;
};

struct ssh_session_s;
typedef void (* receive_msg_cb_t)(struct ssh_session_s *session, struct ssh_payload_s *p);

struct server_reply_s {
    unsigned char 			reply;
    unsigned int			sequence;
    unsigned int			error;
    union {
	struct common_buffer_s		data;
	unsigned int			code;
    } response;
};

#define SESSION_PHASE_SETUP					1
#define SESSION_PHASE_CONNECTION				2
#define SESSION_PHASE_DISCONNECT				99

#define SESSION_SUBPHASE_INIT					1
#define SESSION_SUBPHASE_GREETER				2
#define SESSION_SUBPHASE_KEYEXCHANGE				3
#define SESSION_SUBPHASE_USERAUTH				4

#define SESSION_STATUS_GENERIC_SUCCESS				(1 << 0)
#define SESSION_STATUS_GENERIC_FAILED				(1 << 1)

#define SESSION_STATUS_GREETER_S2C				(1 << 2)
#define SESSION_STATUS_GREETER_C2S				(1 << 3)

#define SESSION_STATUS_KEYEXCHANGE_KEYINIT_S2C			(1 << 2)
#define SESSION_STATUS_KEYEXCHANGE_KEYINIT_C2S			(1 << 3)
#define SESSION_STATUS_KEYEXCHANGE_KEYX_S2C			(1 << 4)
#define SESSION_STATUS_KEYEXCHANGE_KEYX_C2S			(1 << 5)
#define SESSION_STATUS_KEYEXCHANGE_NEWKEYS_S2C			(1 << 6)
#define SESSION_STATUS_KEYEXCHANGE_NEWKEYS_C2S			(1 << 7)

#define SESSION_STATUS_USERAUTH_REQUEST				(1 << 2)
#define SESSION_STATUS_USERAUTH_NONE				(1 << 3)
#define SESSION_STATUS_USERAUTH_PK				(1 << 4)
#define SESSION_STATUS_USERAUTH_PASSWORD			(1 << 5)
#define SESSION_STATUS_USERAUTH_HOSTBASED			(1 << 6)
#define SESSION_STATUS_USERAUTH_UNKNOWN				(1 << 7)

#define SESSION_STATUS_DISCONNECTING				(1 << 10)

#define SESSION_LEVEL_SYSTEM					0
#define SESSION_LEVEL_TRANSPORT					1
#define SESSION_LEVEL_AUTH					2
#define SESSION_LEVEL_CONNECTION				3

#define CHANNEL_FLAG_INIT				(1 << 0)
#define CHANNEL_FLAG_TABLE				(1 << 1)
#define CHANNEL_FLAG_OPEN				(1 << 2)
#define CHANNEL_FLAG_OPENFAILURE			(1 << 3)
#define CHANNEL_FLAG_SERVER_EOF				(1 << 4)
#define CHANNEL_FLAG_SERVER_CLOSE			(1 << 5)
#define CHANNEL_FLAG_CLIENT_EOF				(1 << 6)
#define CHANNEL_FLAG_CLIENT_CLOSE			(1 << 7)
#define CHANNEL_FLAG_NODATA				( CHANNEL_FLAG_CLIENT_CLOSE | CHANNEL_FLAG_CLIENT_EOF | CHANNEL_FLAG_SERVER_CLOSE | CHANNEL_FLAG_SERVER_EOF )

#define TABLE_LOCK_OPENCHANNEL				1
#define TABLE_LOCK_CLOSECHANNEL				2
#define TABLE_LOCK_LOCKED				( TABLE_LOCK_OPENCHANNEL | TABLE_LOCK_CLOSECHANNEL )

#define CHANNELS_TABLE_SIZE				8

struct subsys_status_s {
    unsigned int			level;
    unsigned int			status;
    unsigned int			substatus;
    unsigned int			error;
};

struct sessionphase_s {
    unsigned int			phase;
    unsigned int			sub;
    unsigned int			status;
    unsigned int			error;
};

struct ssh_status_s {
    uint64_t				unique;
    unsigned int 			remote_version_major;
    unsigned int 			remote_version_minor;
    struct sessionphase_s		sessionphase;
    pthread_mutex_t			mutex;
    pthread_cond_t			cond;
    unsigned char			thread;
    unsigned int 			error;
    unsigned int			max_packet_size;
};

struct ssh_channel_s;

struct channellist_head_s {
    struct ssh_channel_s		*head;
    struct ssh_channel_s		*tail;
};

struct channellist_element_s {
    struct ssh_channel_s		*next;
    struct ssh_channel_s		*prev;
};

struct channel_table_s {
    unsigned int			latest_channel;
    unsigned int 			count;
    unsigned int			table_size;
    struct ssh_channel_s		*shell;
    struct channellist_head_s		hash[CHANNELS_TABLE_SIZE];
    struct simple_locking_s		locking;
    unsigned int			lock;
};

#define SSH_SIGNAL_FLAG_ALLOCATED	1
#define SSH_SIGNAL_FLAG_MUTEX_INIT	2
#define SSH_SIGNAL_FLAG_COND_INIT	4

struct ssh_signal_s {
    unsigned char			flags;
    pthread_mutex_t			*mutex;
    pthread_cond_t			*cond;
    unsigned int			sequence_number_error;
    unsigned int			error;
};

struct payload_queue_s {
    struct ssh_session_s		*session;
    struct payload_list_s 		list;
    struct ssh_signal_s			*signal;
    void				(* process_payload_queue)(struct payload_queue_s *queue);
    void				*ptr;
};

#define _CHANNEL_TYPE_SHELL					1
#define _CHANNEL_TYPE_EXEC					2
#define _CHANNEL_TYPE_SFTP_SUBSYSTEM				3
#define _CHANNEL_TYPE_DIRECT_STREAMLOCAL			4
#define _CHANNEL_TYPE_DIRECT_TCPIP				5

struct ssh_channel_s {
    struct ssh_session_s 		*session;
    unsigned char			type;
    unsigned int 			local_channel;
    unsigned int			remote_channel;
    uint32_t				flags;
    unsigned int			max_packet_size;
    unsigned int			actors;
    uint32_t				local_window;
    void				(* process_incoming_bytes)(struct ssh_channel_s *c, unsigned int size);
    uint32_t				remote_window;
    void				(* process_outgoing_bytes)(struct ssh_channel_s *c, unsigned int size);
    pthread_mutex_t			mutex;
    struct channellist_element_s	list;
    struct payload_queue_s		payload_queue;
    int					(* start)(struct ssh_channel_s *c, unsigned int *error);
    void				(* receive_msg_channel_data)(struct ssh_channel_s *c, struct ssh_payload_s **payload);
    int 				(* send_data_message)(struct ssh_channel_s *c, unsigned int len, char *data, unsigned int *seq);
    void				(* close)(struct ssh_channel_s *c, unsigned int flags);
    void				(* free)(struct ssh_channel_s *c);
    union {
	struct serversocket_s {
	    char			*path;
	    unsigned int		protocol;
	} socket;
	struct tcpip_s {
	    char			*host;
	    unsigned int		port;
	    unsigned int		protocol;
	} tcpip;
    } target;
};

#define SSH_ALGO_TYPE_KEX				0
#define SSH_ALGO_TYPE_HOSTKEY				1
#define SSH_ALGO_TYPE_CIPHER_C2S			2
#define SSH_ALGO_TYPE_CIPHER_S2C			3
#define SSH_ALGO_TYPE_HMAC_C2S				4
#define SSH_ALGO_TYPE_HMAC_S2C				5
#define SSH_ALGO_TYPE_COMPRESS_C2S			6
#define SSH_ALGO_TYPE_COMPRESS_S2C			7
#define SSH_ALGO_TYPE_LANG_C2S				8
#define SSH_ALGO_TYPE_LANG_S2C				9

#define SSH_ALGO_TYPES_COUNT				10

/* for most algos's some are recommended (high order), some required (medium) and some optional (low) */

#define SSH_ALGO_ORDER_LOW				1
#define SSH_ALGO_ORDER_MEDIUM				2
#define SSH_ALGO_ORDER_HIGH				3

struct algo_list_s {
    int					type;
    unsigned int			order;
    char				*sshname;
    char				*libname;
    void				*ptr;
};

#define SSH_ALGO_HASH_SHA1_160				1
#define SSH_ALGO_HASH_SHA2_256				2
#define SSH_ALGO_HASH_SHA2_512				3

/*
    struct for key exchange
    for now (201608) only dh (static simple diffie-hellman) is supported
*/

struct ssh_dh_s {
    unsigned char			status;
    void				(* free)(struct ssh_dh_s *dh);
    unsigned int			(* get_size_modgroup)(struct ssh_dh_s *dh);
    struct ssh_mpint_s			p;
    struct ssh_mpint_s			g;
    struct ssh_mpint_s			x;
    struct ssh_mpint_s			e;
    struct ssh_mpint_s			f;
    struct ssh_mpint_s			K;
};

struct ssh_ecdh_s {
    unsigned int			status;
    void				(* free)(struct ssh_ecdh_s *ecdh);
    struct ssh_key_s			skey_c;
    struct ssh_key_s			pkey_s;
};

struct ssh_keyx_s {
    struct ssh_pkauth_s			pkauth;
    char 				digestname[32];
    int					(* create_client_key)(struct ssh_keyx_s *keyx);
    void				(* msg_write_client_key)(struct msg_buffer_s *mb, struct ssh_keyx_s *keyx);
    void				(* msg_read_server_key)(struct msg_buffer_s *mb, struct ssh_keyx_s *keyx);
    void				(* msg_write_server_key)(struct msg_buffer_s *mb, struct ssh_keyx_s *keyx);
    int					(* calc_shared_K)(struct ssh_keyx_s *keyx);
    void				(* msg_write_shared_K)(struct msg_buffer_s *mb, struct ssh_keyx_s *keyx);
    void				(* free)(struct ssh_keyx_s *keyx);
    union {
	struct ssh_dh_s			dh;
	struct ssh_ecdh_s		ecdh;
    } method;
};

struct ssh_utils_s {
    uint64_t 				(* ntohll)(uint64_t value);
};

#define _SSH_CONNECTION_TYPE_IPV4		1
#define _SSH_CONNECTION_TYPE_IPV6		2

#define SSH_CONNECTION_STATUS_INIT		1
#define SSH_CONNECTION_STATUS_CONNECTING	2
#define SSH_CONNECTION_STATUS_CONNECTED		3
#define SSH_CONNECTION_STATUS_DISCONNECTING	4
#define SSH_CONNECTION_STATUS_DISCONNECTED	5

struct ssh_connection_s {
    unsigned char			type;
    unsigned int			status;
    unsigned int			expire;
    unsigned int			error;
    union {
	struct sockaddr_in 		inet;
	struct sockaddr_in6 		inet6;
    } socket;
    unsigned int 			fd;
    struct bevent_xdata_s 		*xdata;
};

struct ssh_decompressor_s {
    struct ssh_decompress_s		*decompress;
    struct timespec			created;
    int					(* decompress_packet)(struct ssh_decompressor_s *d, struct ssh_packet_s *packet, struct ssh_payload_s **payload, unsigned int *error);
    void				(* clear)(struct ssh_decompressor_s *d);
    void				(* queue)(struct ssh_decompressor_s *d);
    struct list_element_s		list;
    unsigned int			size;
    char				buffer[];
};

struct decompress_ops_s {
    char				*name;
    unsigned int			(* populate)(struct ssh_session_s *s, struct decompress_ops_s *ops, struct algo_list_s *alist, unsigned int start);
    unsigned int			(* get_handle_size)(struct ssh_decompress_s *decompress);
    int					(* init_decompressor)(struct ssh_decompressor_s *d);
    struct list_element_s		list;
};

struct ssh_decompress_s {
    unsigned int			flags;
    char				name[64];
    struct list_header_s		decompressors;
    unsigned int			count;
    unsigned int			max_count;
    struct list_header_s		waiters;
    unsigned int			waiting;
    struct decompress_ops_s		*ops;
};

struct ssh_decryptor_s {
    struct ssh_decrypt_s		*decrypt;
    struct timespec			created;
    unsigned int			nr;
    int					(* verify_hmac_pre)(struct ssh_decryptor_s *d, struct ssh_packet_s *packet);
    int					(* decrypt_length)(struct ssh_decryptor_s *d, struct ssh_packet_s *packet, char *buffer, unsigned int len);
    int					(* decrypt_packet)(struct ssh_decryptor_s *d, struct ssh_packet_s *packet);
    int					(* verify_hmac_post)(struct ssh_decryptor_s *d, struct ssh_packet_s *packet);
    void				(* clear)(struct ssh_decryptor_s *d);
    void				(* queue)(struct ssh_decryptor_s *d);
    unsigned int			cipher_blocksize;
    unsigned int			cipher_headersize;
    unsigned int			hmac_maclen;
    struct list_element_s		list;
    unsigned int			size;
    char				buffer[];
};

struct decrypt_ops_s {
    char				*name;
    unsigned int			(* populate_cipher)(struct ssh_session_s *s, struct decrypt_ops_s *ops, struct algo_list_s *alist, unsigned int start);
    unsigned int			(* populate_hmac)(struct ssh_session_s *s, struct decrypt_ops_s *ops, struct algo_list_s *alist, unsigned int start);
    unsigned int			(* get_handle_size)(struct ssh_decrypt_s *d);
    int					(* init_decryptor)(struct ssh_decryptor_s *decryptor);
    unsigned int			(* get_cipher_blocksize)(const char *name);
    unsigned int			(* get_cipher_keysize)(const char *name);
    unsigned int			(* get_cipher_ivsize)(const char *name);
    unsigned int			(* get_hmac_keysize)(const char *name);
    unsigned int			(* get_decrypt_flag)(const char *ciphername, const char *hmacname, const char *what);
    struct list_element_s		list;
};

#define SSH_DECRYPT_FLAG_PARALLEL			(1 << 1)

struct ssh_decrypt_s {
    unsigned int			flags;
    char 				ciphername[64];
    char				hmacname[64];
    struct list_header_s		decryptors;		/* linked list of available decrypt handles, maybe more than one when parallel is possible */
    unsigned int			count;			/* number of decryptors */
    unsigned int			max_count;		/* maximum number of decryptors, when set to 1 parallel is disabled */
    struct list_header_s		waiters;		/* linked list for threads waiting to get a decryptor to ensure fifo behaviour */
    unsigned int 			waiting;		/* number of threads waiting */
    struct decrypt_ops_s		*ops;			/* decrypt ops used */
    struct ssh_string_s			cipher_key;
    struct ssh_string_s			cipher_iv;
    struct ssh_string_s			hmac_key;
};

#define SSH_RECEIVE_FLAG_GREETER			(1 << 0)
#define SSH_RECEIVE_FLAG_SESSION			(1 << 1)
#define SSH_RECEIVE_FLAG_KEXINIT			(1 << 2)
#define SSH_RECEIVE_FLAG_NEWKEYS			(1 << 3)
#define SSH_RECEIVE_FLAG_ERROR				(1 << 4)
#define SSH_RECEIVE_FLAG_DISCONNECT			(1 << 5)

struct ssh_receive_s {
    unsigned int			flags;
    struct ssh_signal_s			signal;
    struct ssh_decrypt_s		decrypt;
    struct ssh_decompress_s		decompress;
    struct timespec			newkeys;		/* time when newkeys are used */
    pthread_mutex_t			mutex;
    pthread_cond_t			cond;
    pthread_t				threadid;
    unsigned int 			sequence_number;
    void				(* process_ssh_packet)(struct ssh_session_s *session, struct ssh_packet_s *packet);
    void				(* read_ssh_buffer)(void *ptr);
    void				(* release_read_buffer_early)(struct ssh_receive_s *r);
    void				(* release_read_buffer_late)(struct ssh_receive_s *r);
    unsigned int			read;
    unsigned int 			size;
    char				*buffer;
};

struct ssh_compressor_s {
    struct ssh_compress_s		*compress;
    struct timespec			created;
    int					(* compress_payload)(struct ssh_compressor_s *c, struct ssh_payload_s **payload, unsigned int *error);
    void				(* clear)(struct ssh_compressor_s *c);
    void				(* queue)(struct ssh_compressor_s *c);
    struct list_element_s		list;
    unsigned int			size;
    char				buffer[];
};

struct compress_ops_s {
    char				*name;
    unsigned int			(* populate)(struct ssh_session_s *s, struct compress_ops_s *ops, struct algo_list_s *alist, unsigned int start);
    unsigned int			(* get_handle_size)(struct ssh_compress_s *compress);
    int					(* init_compressor)(struct ssh_compressor_s *d);
    struct list_element_s		list;
};

struct ssh_compress_s {
    unsigned int			flags;
    char				name[64];
    struct list_header_s		compressors;
    unsigned int			count;
    unsigned int			max_count;
    struct list_header_s		waiters;
    unsigned int			waiting;
    struct compress_ops_s		*ops;
};

struct ssh_encryptor_s {
    struct ssh_encrypt_s		*encrypt;
    struct timespec			created;
    unsigned int			nr;
    int					(* write_hmac_pre)(struct ssh_encryptor_s *e, struct ssh_packet_s *packet);
    int					(* encrypt_packet)(struct ssh_encryptor_s *e, struct ssh_packet_s *packet);
    int					(* write_hmac_post)(struct ssh_encryptor_s *e, struct ssh_packet_s *packet);
    unsigned char			(* get_message_padding)(struct ssh_encryptor_s *e, unsigned int len);
    void				(* clear)(struct ssh_encryptor_s *e);
    void				(* queue)(struct ssh_encryptor_s *e);
    unsigned int			cipher_blocksize;
    unsigned int			cipher_headersize;
    unsigned int			hmac_maclen;
    struct list_element_s		list;
    unsigned int			size;
    char				buffer[];
};

struct ssh_encrypt_s;

struct encrypt_ops_s {
    char				*name;
    unsigned int			(* populate_cipher)(struct ssh_session_s *s, struct encrypt_ops_s *ops, struct algo_list_s *alist, unsigned int start);
    unsigned int			(* populate_hmac)(struct ssh_session_s *s, struct encrypt_ops_s *ops, struct algo_list_s *alist, unsigned int start);
    unsigned int			(* get_handle_size)(struct ssh_encrypt_s *encrypt);
    int					(* init_encryptor)(struct ssh_encryptor_s *encryptor);
    unsigned int			(* get_cipher_blocksize)(const char *name);
    unsigned int			(* get_cipher_keysize)(const char *name);
    unsigned int			(* get_cipher_ivsize)(const char *name);
    unsigned int			(* get_hmac_keysize)(const char *name);
    unsigned int			(* get_encrypt_flag)(const char *ciphername, const char *hmacname, const char *what);
    struct list_element_s		list;
};

struct ssh_encrypt_s {
    unsigned int			flags;
    char				ciphername[64];
    char				hmacname[64];
    struct list_header_s		encryptors;
    unsigned int			count;
    unsigned int			max_count;
    struct list_header_s		waiters;		/* linked list for threads waiting to get a decryptor to ensure fifo behaviour */
    unsigned int 			waiting;		/* number of threads waiting */
    struct encrypt_ops_s		*ops;			/* encrypt ops used */
    struct ssh_string_s			cipher_key;
    struct ssh_string_s			cipher_iv;
    struct ssh_string_s			hmac_key;
};

struct ssh_sender_s {
    unsigned char			listed;
    struct list_element_s		list;
    unsigned int			sequence;
};

#define SSH_SEND_FLAG_SESSION				(1 << 0)
#define SSH_SEND_FLAG_KEXINIT				(1 << 1)
#define SSH_SEND_FLAG_NEWKEYS				(1 << 2)
#define SSH_SEND_FLAG_ERROR				(1 << 3)
#define SSH_SEND_FLAG_DISCONNECT			(1 << 4)

struct ssh_send_s {
    unsigned int			flags;
    pthread_mutex_t			mutex;
    pthread_cond_t			cond;
    struct list_header_s		senders;
    unsigned int			sending;
    struct timespec			newkeys;
    int					(* queue_sender)(struct ssh_send_s *send, struct ssh_sender_s *sender, unsigned int *error);
    unsigned int 			sequence_number;
    struct ssh_encrypt_s		encrypt;
    struct ssh_compress_s		compress;
};

struct ssh_pubkey_s {
    unsigned int 			ids_pkalgo;
    unsigned int			ids_pksign;
};

#define SSH_HOSTINFO_FLAG_TIMEINIT	1
#define SSH_HOSTINFO_FLAG_TIMESET	2

struct ssh_hostinfo_s {
    unsigned int			flags;
    struct timespec			delta;
    void				(* correct_time_s2c)(struct ssh_session_s *session, struct timespec *time);
    void				(* correct_time_c2s)(struct ssh_session_s *session, struct timespec *time);
};

struct ssh_identity_s {
    struct passwd			pwd;
    char				*buffer;
    unsigned int			size;
    struct ssh_string_s			remote_user;
    char				*identity_file;
};

/*	data per session:
	- greeters send by server and client
	- sessionid (H) calculated during kexinit in setup phase
*/

struct session_data_s {
    struct ssh_string_s			sessionid;
    struct ssh_string_s			greeter_server;
    struct ssh_string_s			greeter_client;
};

/*	data per keyexchange
	- algos available
	- kexinit messages server and client
	- algos chosen
	- keys and iv generated
*/

struct exchange_data_s {
    struct ssh_string_s			kexinit_server;
    struct ssh_string_s			kexinit_client;
    struct algo_list_s			*algos;
    int					chosen[SSH_ALGO_TYPES_COUNT];
    struct ssh_string_s			cipher_key_c2s;
    struct ssh_string_s			cipher_iv_c2s;
    struct ssh_string_s			hmac_key_c2s;
    struct ssh_string_s			cipher_key_s2c;
    struct ssh_string_s			cipher_iv_s2c;
    struct ssh_string_s			hmac_key_s2c;
};

struct keyexchange_s {
    struct exchange_data_s		data;
    struct payload_queue_s 		*queue;
};

#define SSH_USERAUTH_METHOD_NONE				1
#define SSH_USERAUTH_METHOD_PUBLICKEY				2
#define SSH_USERAUTH_METHOD_PASSWORD				4
#define SSH_USERAUTH_METHOD_HOSTBASED				8
#define SSH_USERAUTH_METHOD_UNKNOWN				16

struct ssh_userauth_s {
    unsigned int			required_methods;
    unsigned int			methods_done;
    char				*l_hostname;
    char				*l_ipv4;
    char				*r_hostname;
    char				*r_ipv4;
    struct payload_queue_s 		*queue;
};

#define SSH_EXTENSION_SOURCE_EXT_INFO				1

#define SSH_EXTENSION_SERVER_SIG_ALGS				1
#define SSH_EXTENSION_DELAY_COMPRESSION				2
#define SSH_EXTENSION_NO_FLOW_CONTROL				3
#define SSH_EXTENSION_ELEVATION					4

#define SSH_EXTENSIONS_COUNT					4

#define SSH_EXTENSION_SUPPORTED_UNKNOWN				1
#define SSH_EXTENSION_SUPPORTED_TRUE				2
#define SSH_EXTENSION_SUPPORTED_FALSE				3

struct ssh_extension_s {
    char				*name;
    unsigned int			code;
};

struct ssh_extensions_s {
    unsigned int			supported;
    unsigned int			received;
    
};

struct session_list_s {
    struct ssh_session_s		*next;
    struct ssh_session_s		*prev;
};

/* main session per user */

struct ssh_session_s {
    struct context_interface_s 		*interface;
    struct ssh_status_s			status;
    struct ssh_identity_s		identity;
    struct channel_table_s		channel_table;
    struct session_data_s		data;
    struct ssh_pubkey_s			pubkey;
    struct payload_queue_s		*queue;
    struct keyexchange_s		*keyexchange;
    struct ssh_userauth_s		*userauth;
    struct ssh_connection_s		connection;
    struct ssh_receive_s		receive;
    struct ssh_send_s			send;
    struct ssh_hostinfo_s		hostinfo;
    struct ssh_extensions_s		extensions;
    struct session_list_s		list;
};

/* prototypes */

int change_sessionphase(struct ssh_session_s *session, struct sessionphase_s *sessionphase);
int compare_sessionphase(struct ssh_session_s *session, struct sessionphase_s *sessionphase);
int change_status_sessionphase(struct ssh_session_s *session, struct sessionphase_s *sessionphase);
void set_sessionphase_failed(struct sessionphase_s *sessionphase);
void set_sessionphase_success(struct sessionphase_s *sessionphase);
void copy_sessionphase(struct ssh_session_s *session, struct sessionphase_s *sessionphase);
int wait_status_sessionphase(struct ssh_session_s *session, struct sessionphase_s *sessionphase, unsigned int status);

struct ssh_session_s *get_full_session(uid_t uid, struct context_interface_s *interface, char *address, unsigned int port);
void remove_full_session(struct ssh_session_s *session);
void umount_ssh_session(struct context_interface_s *interface);

unsigned int get_window_size(struct ssh_session_s *session);
unsigned int get_max_packet_size(struct ssh_session_s *session);
void set_max_packet_size(struct ssh_session_s *session, unsigned int size);

void get_session_expire_init(struct ssh_session_s *session, struct timespec *expire);
void get_session_expire_session(struct ssh_session_s *session, struct timespec *expire);

void disconnect_ssh_session(struct ssh_session_s *session, unsigned char server, unsigned int reason);
void start_thread_connection_problem(struct ssh_session_s *session, unsigned int level);

#endif
