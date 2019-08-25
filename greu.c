#include <string.h>
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <ctype.h> 
#include <fcntl.h>
#include <errno.h>
#include <err.h>
#include <stdbool.h>
#include <limits.h>

#include <event.h>

#include <sys/socket.h>
#include <sys/ioctl.h>
#include <netdb.h>
#include <netinet/ip.h>
#include <netinet/in.h>
#include <net/if.h>
#include <net/if_gre.h>
#include <net/ethertypes.h>

#define DEFAULT_PORT "4754" 
#define MAX_PACKET_SIZE 65536
#define DEVICE_TO_STR(dt) (dt == TUN ? "TUN" : "TAP")

/*
 * Represents type of device
 */
enum device_type {
	TUN,
	TAP
};

/*
 * Stores information about a TUN/TAP device/interface
 */
struct device {
	/* List entry for device_list */
	TAILQ_ENTRY(device) entry;

	enum device_type type; // TUN or TAP
	int fd; // file descriptor to read/write from device
	bool has_key; // true if this tunnel is using a GRE key
	uint32_t key; // GRE key if set
};

/* Use a list to store devices */
TAILQ_HEAD(device_list, device);

/*
 * Argument for device read callback
 */
struct device_arg {
	struct device *dev;
	int socket;
};

/*
 * Prints usage information and exits with status 1
 */
__dead void
usage(void)
{
	extern char *__progname;
	int pad;

	/* Pad lines dynamically */
	pad = strlen("usage: ") + strlen(__progname) + 1;

	fprintf(stderr, "usage: %s [-46d] [-l address] [-p port]\n" 
	    "%*s[-e /dev/tapX[@key]] [-i /dev/tunX[@key]]\n"
	    "%*sserver [port]\n", 
	    __progname,
	    pad, "", pad, "");
	
	exit(1);
}

/*
 * Resolves address with given hostname, port and af family using
 * getaddrinfo.
 *
 * Exits on failure.
 */
struct addrinfo*
resolve_addr(const char *hostname, const char *port, sa_family_t family)
{
	int err;
	struct addrinfo hints, *res;

	/* use UDP */
	memset(&hints, 0, sizeof(hints));
	hints.ai_family = family;
	hints.ai_socktype = SOCK_DGRAM;
	hints.ai_protocol = IPPROTO_UDP;
	hints.ai_flags = AI_PASSIVE;

	err = getaddrinfo(hostname, port, &hints, &res);
	if (err)
		errx(1, "%s", gai_strerror(err));

	return res;
}

/*
 * Opens and binds a socket to the given local address.
 * 
 * Returns -1 on failure. Otherwise returns socket file descriptor.
 */
int
bind_to_addr(struct addrinfo *local_addr) 
{
	struct addrinfo *res;
	int sock;

	for (res = local_addr; res != NULL; res = res->ai_next) {
		sock = socket(res->ai_family, res->ai_socktype, res->ai_protocol);

		if (sock == -1) {
			continue; /* Try again */
		}

		if (bind(sock, res->ai_addr, res->ai_addrlen) == -1) {
			close(sock);
			sock = -1;
			continue; /* Try again */
		}

		/* We got one */
		break;
	}

	return sock;
}

/*
 * Sets up a UDP tunnel between the local address and the remote address.
 * and returns the socket file descriptor.
 *
 * Exits on failure.
 */
int
connect_tunnel(struct addrinfo *src_addr, struct addrinfo *dest_addr) 
{
	struct addrinfo *res;
	int sock;

	if ((sock = bind_to_addr(src_addr)) == -1) 
		err(1, "%s", strerror(errno));

	// Connect socket to external host
	for (res = dest_addr; res != NULL; res = res->ai_next) {
		if (connect(sock, res->ai_addr, res->ai_addrlen) == -1) {
			if (res->ai_next == NULL)
				sock = -1; /* No more to try */
			else
				continue; /* Try again */
		}

		break; /* Got one */
	}

	if (sock == -1)
		err(1, "%s", strerror(errno));

	return sock;
}

/*
 * Opens a TUN/TAP device at location dev and appends it to the device list.
 *
 * Succeeds or exits on error.
 */
void 
open_device(struct device_list *devices, char *dev, enum device_type type) 
{
	int fd;
	char *location;
	uint32_t key;
	bool has_key = false;
	const char *err_str;

	/* find key in device name */
	location = strsep(&dev, "@");
	if (dev != NULL) {
		has_key = true;
		key = (uint32_t)strtonum(dev, 0, UINT_MAX, &err_str);

		/* check if invalid key */
		if (err_str != NULL) {
			errx(1, "Bad key for %s device %s: %s",
			    DEVICE_TO_STR(type), 
			    location,
			    dev);
		}
	}

	/* Check key hasn't been used for another tunnel of this type */
	struct device *d;
	TAILQ_FOREACH(d, devices, entry) {
		if ((d->key == key || (!has_key && !d->has_key)) 
		    && d->type == type) {
			errx(1, "More than one %s device with the same key",
			   DEVICE_TO_STR(type)); 
		} 
	}

	if ((fd = open(location, O_RDWR)) == -1)
		errx(1, "Couldn't open device %s. Error: %s", 
		    location, strerror(errno));

	if (ioctl(fd, FIONBIO, &(int) { 1 }) == -1)
		err(1, "Error setting non blocking file descriptor");

	struct device *new_dev = malloc(sizeof(struct device));
	new_dev->type = type;
	new_dev->has_key = has_key;
	new_dev->key = key;
	new_dev->fd = fd;

	TAILQ_INSERT_TAIL(devices, new_dev, entry);	
}

/*
 * Event callback for reading from a device file descriptor.
 * conn is a pointer to a device_arg representing the device corresponding
 * to this file descriptor.
 *
 * Exits on read error.
 */
void
device_read(int fd, short events, void *conn)
{
	struct device_arg *darg = (struct device_arg *)conn;
	struct device *dev = darg->dev;
	struct gre_h header = {0};
	uint8_t *buffer;
	int bytes_read;
	int write_index = 0;
	int key_len = (dev->has_key ? sizeof(uint32_t) : 0);

	buffer = malloc(sizeof(header) + key_len + MAX_PACKET_SIZE); 

	/* Read from socket, but leave room for GRE header/key in buffer to
	   write back to a device */
	bytes_read = read(fd, buffer + sizeof(header) + key_len, MAX_PACKET_SIZE);
	switch (bytes_read) {
	case -1:
		switch (errno) {
		case EINTR:
		case EAGAIN:
			break;
		default:
			warn("Device read error");
		}
		
		free(buffer);
		return; /* Nothing more to do */
	case 0:
		errx(1, "Device closed");
		/* EXITS */
	default:
		break;
	}

	/* write GRE key */
	write_index += sizeof(header);
	if (dev->has_key) {
		uint32_t key = htonl(dev->key);
		memcpy(buffer + write_index, &key, key_len);
		write_index += key_len;
	}

	/* Set protocol type in GRE header */
	if (dev->type == TAP) {
		header.ptype = htons(ETHERTYPE_TRANSETHER);
	} else { /* TUN */
		/* Extract 4 byte af header */
		uint32_t tun_type = 0;
		memcpy(&tun_type, buffer + write_index, 4);

		switch (ntohl(tun_type)) {
		case AF_INET:
			header.ptype = htons(ETHERTYPE_IP);
			break;
		case AF_INET6:
			header.ptype = htons(ETHERTYPE_IPV6);
			break;
		default:
			warnx("Unsupported protocol type read from TUN device");
			free(buffer);
			return;
		}

		/* Remove from buffer as we don't want to send this to socket */
		bytes_read -= 4;
		memmove(buffer + write_index, buffer + write_index + 4, bytes_read);
	}
	write_index += bytes_read;

	/* set key bit in GRE header if necessary and write to start of buffer */
	header.flags = htons(dev->has_key ? GRE_KP : 0);
	memcpy(buffer, &header, sizeof(header));
	
	write(darg->socket, buffer, write_index);
	free(buffer);
}

/*
 * Event callback for reading from the UDP socket file descriptor connected
 * to the remote tunnel address.
 * conn is a pointer to the list of connected TUN/TAP devices
 *
 * Exits on read error.
 */
void
socket_read(int fd, short events, void *conn)
{
	struct device_list *devices = (struct device_list*)conn;
	struct gre_h *header;
	uint8_t *buffer, *orig_buffer;
	int bytes_read = 0;
	bool has_key = false;
	uint32_t key;
	enum device_type type;

	// +4 bytes of room for TUN header if needed
       	orig_buffer = buffer = malloc(MAX_PACKET_SIZE + 4);

	bytes_read = read(fd, buffer, MAX_PACKET_SIZE);
	switch (bytes_read) {
	case -1:
		switch (errno) {
		case EINTR:
		case EAGAIN:
			break;
		default:
			warn("Socket read error");
		}
		
		free(buffer);
		return; /* Nothing more to do */
	case 0:
		errx(1, "Socket closed");
		/* EXITS */
	default:
		break;
	}

	// Extract GRE header from payload
	header = (struct gre_h *)buffer;
	buffer += sizeof(struct gre_h);
	bytes_read -= sizeof(struct gre_h);

	header->flags = ntohs(header->flags);
	header->ptype = ntohs(header->ptype);

	// If any bits other than key bit are set, throw away.
	if ((header->flags & ~GRE_KP) != 0) {
		free(orig_buffer);
		return; /* Not a GRE packet */
	}

	// parse key if needed
	if (header->flags & GRE_KP) {
		has_key = true;
		memcpy(&key, buffer, sizeof(uint32_t));
		key = ntohl(key);
		buffer += sizeof(uint32_t);
		bytes_read -= sizeof(uint32_t);
	}

	if (header->ptype == ETHERTYPE_TRANSETHER) {
		type = TAP;
	} else if (header->ptype == ETHERTYPE_IP 
	    || header->ptype == ETHERTYPE_IPV6) {
		type = TUN;
		
		uint32_t tunh;
	        if (header->ptype == ETHERTYPE_IP)
			tunh = htonl(AF_INET);
		else 
			tunh = htonl(AF_INET6);
		    
		// write 4 byte network type header
		memmove(buffer + 4, buffer, bytes_read);
		memcpy(buffer, &tunh, 4);
		bytes_read += 4;
	} else {
		/* Unknown protocol */
		free(orig_buffer);
		return;
	}

	/* Find right device with right key to send packet to */
	struct device *d;
	TAILQ_FOREACH(d, devices, entry) {
		if (((!d->has_key && !has_key) || (has_key && d->key == key))
		    && d->type == type) {
			write(d->fd, buffer, bytes_read); 
			free(orig_buffer);
			return;
		}
	}

	/* Unknown key sent? */
	free(orig_buffer);
}

/*
 * Sets up event listeners on socket and device file descriptors
 */
void 
setup_events(int sock, struct device_list *devices)
{
	/* Setup UDP socket read event */
	struct event *sock_ev = malloc(sizeof(struct event)); 
	event_set(sock_ev, sock, EV_READ | EV_PERSIST, socket_read, devices);	
	event_add(sock_ev, NULL);

	/* Setup each device read event */
	struct device *d;
	TAILQ_FOREACH(d, devices, entry) {
		struct event *dev_ev;
	       	struct device_arg *darg; 
		
		darg = malloc(sizeof(struct device_arg));
		darg->dev = d;
		darg->socket = sock;

		/* register event */
		dev_ev = malloc(sizeof(struct event));
		event_set(dev_ev, d->fd, EV_READ | EV_PERSIST, device_read, darg);
		event_add(dev_ev, NULL);
	}
}

/*
 * Runs a GRE over UDP server
 */
int
main(int argc, char *argv[]) 
{
	const char *remote_hostname = NULL;
	const char *local_hostname = NULL;
	const char *remote_port = DEFAULT_PORT;
	const char *local_port = NULL;
	sa_family_t af = AF_UNSPEC;
	bool daemonise = true;
	int num_devices = 0;
	struct device_list devices = TAILQ_HEAD_INITIALIZER(devices);
	struct addrinfo *src_addr, *dest_addr;
	int sock = -1;

	int ch;
	while ((ch = getopt(argc, argv, "46dl:p:e:i:")) != -1) {
		switch (ch) {
		case '4':
			af = AF_INET;
			break;
		case '6':
			af = AF_INET6;
			break;
		case 'd':
			daemonise = false;
			break;
		case 'l':
			local_hostname = 
			    (strcmp(optarg, "*") == 0) ?  NULL : optarg;
			break;
		case 'p':
			local_port = optarg;
			break;
		case 'e':
			open_device(&devices, optarg, TAP);
			num_devices++;
			break;
		case 'i':
			open_device(&devices, optarg, TUN);
			num_devices++;
			break;
		default:
			usage();
			/* NOTREACHED */
		}
	}	
	argc -= optind;
	argv += optind;

	switch (argc) {
	case 2:
		remote_port = argv[1];
		/* FALLTHROUGH */
	case 1:
		remote_hostname = argv[0];
		break;
	default:
		usage();
		/* NOT REACHED */
	}

	if (num_devices == 0)
		errx(1, "At least one IP or Ethernet tunnel must be configured.");

	/* Use destination port as source port if none provided */	
	if (local_port == NULL)
		local_port = remote_port;

	/* Resolve addresses. Exits on failure */
	src_addr = resolve_addr(local_hostname, local_port, af);
	dest_addr = resolve_addr(remote_hostname, remote_port, af);

	sock = connect_tunnel(src_addr, dest_addr);

	free(src_addr);
	free(dest_addr);

	if (daemonise)
		daemon(0, 0);

	event_init();

	setup_events(sock, &devices);

	event_dispatch(); /* BLOCKING CALL */
}

