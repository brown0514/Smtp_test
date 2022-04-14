/////////////////////////////////////////////////////////////////////////////////////////
//
// NAME: MD3_NET
// DESCRIPTION: A Cross Plateform Networking Library
// AUTHOR: Soufiane El Moudaa
//
// Both TCP and UDP sockets are supported in this implemetation.
//
// LICENSE
//
//    Copyright © 2022 <Soufiane El Moudaa>
//    Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the “Software”), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:
//    The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.
//    THE SOFTWARE IS PROVIDED “AS IS”, WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
//
// USAGE
//
//    Define MD3_NET_IMPLEMENTATION to use the code and call the API in that file.
//    Define the symbol MD3_NET_STATIC to make the implementation private to that file.
//    The upcoming section includes documentation for each API function.
//

#ifndef INCLUDE_MD3_NET_H
#define INCLUDE_MD3_NET_H

#ifdef MD3_NET_STATIC
#define MD3_NET_DEF static
#else
#define MD3_NET_DEF extern
#endif

#ifdef __cplusplus
extern "C" {
#endif

/////////////////////////////////////////////////////////////////////////////////////////
//
// INITIALIZATION AND SHUTDOWN
//

// Get a reason for an error
MD3_NET_DEF const char *md3_net_get_error(void);

// Initializes the socket library (socket init code)
// *required* Call this before doing anything with sockets 
//
// Returns 0 if success else -1 if error
MD3_NET_DEF int md3_net_init(void);

// Destroys ressources allocated during socket initialization (socket shutdown code)
// *required* Call this a once finshed using the library
MD3_NET_DEF void md3_net_shutdown(void);

/////////////////////////////////////////////////////////////////////////////////////////
//
// INTERNET ADDRESS
//

// Represnt a structure to be used with sockets
typedef struct {
    unsigned int host;
    unsigned short port;
} md3_net_address_t;

// Obtain an address from a host name and a port
//
// 'host' may contain a decimal formatted IP (such as "127.0.0.1"), a human readable
// name (such as "localhost"), or NULL for the default address
//
// Returns 0 on success, -1 otherwise (call 'md3_net_get_error' for more info)
MD3_NET_DEF int md3_net_get_address(md3_net_address_t *address, const char *host, unsigned short port);

// Converts an address's host name into a decimal formatted string
//
// Returns NULL on failure (call 'md3_net_get_error' for more info)
MD3_NET_DEF const char *md3_net_host_to_str(unsigned int host);

/////////////////////////////////////////////////////////////////////////////////////////
//
// SOCKET HANDLE API
//

// Wraps the system handle for a UDP/TCP socket
typedef struct {
    int handle;
    unsigned long non_blocking;
    int ready;
} md3_net_socket_t;

// Closes a previously opened socket
MD3_NET_DEF void md3_net_socket_close(md3_net_socket_t *socket);

/////////////////////////////////////////////////////////////////////////////////////////
//
// UDP SOCKETS
//

// Opens a UDP socket and binds it to a specified port
// (use 0 to select a random open port)
//
// Socket will not block if 'non-blocking' is non-zero
//
// Returns 0 on success
// Returns -1 on failure (call 'md3_net_get_error' for more info)
MD3_NET_DEF int md3_net_udp_socket_open(md3_net_socket_t *socket, unsigned int port, unsigned long non_blocking);

// Sends a specific amount of data to 'destination'
//
// Returns 0 on success, -1 otherwise (call 'md3_net_get_error' for more info)
MD3_NET_DEF int md3_net_udp_socket_send(md3_net_socket_t *socket, md3_net_address_t destination, const void *data, int size);

// Receives a specific amount of data from 'sender'
//
// Returns the number of bytes received, -1 otherwise (call 'md3_net_get_error' for more info)
MD3_NET_DEF int md3_net_udp_socket_receive(md3_net_socket_t *socket, md3_net_address_t *sender, void *data, int size);

/////////////////////////////////////////////////////////////////////////////////////////
//
// TCP SOCKETS
//

// Opens a TCP socket and binds it to a specified port
// (use 0 to select a random open port)
//
// Socket will not block if 'non-blocking' is non-zero
//
// Returns NULL on failure (call 'md3_net_get_error' for more info)
// Socket will listen for incoming connections if 'listen_socket' is non-zero
// Returns 0 on success
// Returns -1 on failure (call 'md3_net_get_error' for more info)
MD3_NET_DEF int md3_net_tcp_socket_open(md3_net_socket_t *socket, unsigned int port, unsigned long non_blocking, int listen_socket);

// Connect to a remote endpoint
// Returns 0 on success.
//  if the socket is non-blocking, then this can return 1 if the socket isn't ready
//  returns -1 otherwise. (call 'md3_net_get_error' for more info)
MD3_NET_DEF int md3_net_tcp_connect(md3_net_socket_t *socket, md3_net_address_t remote_addr);

// Accept connection
// New remote_socket inherits non-blocking from listening_socket
// Returns 0 on success.
//  if the socket is non-blocking, then this can return 1 if the socket isn't ready
//  if the socket is non_blocking and there was no connection to accept, returns 2
//  returns -1 otherwise. (call 'md3_net_get_error' for more info)
MD3_NET_DEF int md3_net_tcp_accept(md3_net_socket_t *listening_socket, md3_net_socket_t *remote_socket, md3_net_address_t *remote_addr);

// Returns 0 on success.
//  if the socket is non-blocking, then this can return 1 if the socket isn't ready
//  returns -1 otherwise. (call 'md3_net_get_error' for more info)
MD3_NET_DEF int md3_net_tcp_socket_send(md3_net_socket_t *remote_socket, const void *data, int size);

// Returns 0 on success.
//  if the socket is non-blocking, then this can return 1 if the socket isn't ready
//  returns -1 otherwise. (call 'md3_net_get_error' for more info)
MD3_NET_DEF int md3_net_tcp_socket_receive(md3_net_socket_t *remote_socket, void *data, int size);

// Blocks until the TCP socket is ready. Only makes sense for non-blocking socket.
// Returns 0 on success.
//  returns -1 otherwise. (call 'md3_net_get_error' for more info)
MD3_NET_DEF int md3_net_tcp_make_socket_ready(md3_net_socket_t *socket);

#ifdef __cplusplus
}
#endif

#endif // INCLUDE_MD3_NET_H

// END of Documentation
//
/////////////////////////////////////////////////////////////////////////////////////////
//
// IMPLEMENTATION
//

#ifdef MD3_NET_IMPLEMENTATION

#include <stdlib.h>
#include <string.h>
#include <time.h>

#ifdef _WIN32
#define _WINSOCK_DEPRECATED_NO_WARNINGS
#include <WinSock2.h>
#pragma comment(lib, "wsock32.lib")
#define MD3_NET_SOCKET_ERROR SOCKET_ERROR
#define MD3_NET_INVALID_SOCKET INVALID_SOCKET
#else
#include <sys/socket.h>
#include <unistd.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <fcntl.h>
#define MD3_NET_SOCKET_ERROR -1
#define MD3_NET_INVALID_SOCKET -1
#endif

static const char *md3_net__g_error;

static int md3_net__error(const char *message) {
    md3_net__g_error = message;

    return -1;
}

MD3_NET_DEF const char *md3_net_get_error(void) {
    return md3_net__g_error;
}

MD3_NET_DEF int md3_net_init(void) {
#ifdef _WIN32
    WSADATA wsa_data;
    if (WSAStartup(MAKEWORD(2, 2), &wsa_data) != 0)
    {
        return md3_net__error("Windows Sockets failed to start");
    }

    return 0;
#else
    return 0;
#endif
}

MD3_NET_DEF void md3_net_shutdown(void) {
#ifdef _WIN32
    WSACleanup();
#endif
}

MD3_NET_DEF int md3_net_get_address(md3_net_address_t *address, const char *host, unsigned short port) {
    if (host == NULL) {
        address->host = INADDR_ANY;
    } else {
        address->host = inet_addr(host);
        if (address->host == INADDR_NONE) {
            struct hostent *hostent = gethostbyname(host);
            if (hostent) {
                memcpy(&address->host, hostent->h_addr, hostent->h_length);
            } else {
                return md3_net__error("Invalid host name");
            }
        }
    }

    address->port = port;
    
    return 0;
}

MD3_NET_DEF const char *md3_net_host_to_str(unsigned int host) {
    struct in_addr in;
    in.s_addr = host;

    return inet_ntoa(in);
}

MD3_NET_DEF int md3_net_udp_socket_open(md3_net_socket_t *sock, unsigned int port, unsigned long non_blocking) {
    if (!sock)
        return md3_net__error("Socket is NULL");

    // Create the socket
    sock->handle = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (sock->handle <= 0) {
        md3_net_socket_close(sock);
        return md3_net__error("Failed to create socket");
    }

    // Bind the socket to the port
    struct sockaddr_in address;
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = INADDR_ANY;
    address.sin_port = htons(port);

    if (bind(sock->handle, (const struct sockaddr *) &address, sizeof(struct sockaddr_in)) != 0) {
        md3_net_socket_close(sock);
        return md3_net__error("Failed to bind socket");
    }

    // Set the socket to non-blocking if neccessary
    if (non_blocking) {
#ifdef _WIN32
        if (ioctlsocket(sock->handle, FIONBIO, &non_blocking) != 0) {
            md3_net_socket_close(sock);
            return md3_net__error("Failed to set socket to non-blocking");
        }
#else
        if (fcntl(sock->handle, F_SETFL, O_NONBLOCK, non_blocking) != 0) {
            md3_net_socket_close(sock);
            return md3_net__error("Failed to set socket to non-blocking");
        }
#endif
    }

    sock->non_blocking = non_blocking;

    return 0;
}

MD3_NET_DEF int md3_net_tcp_socket_open(md3_net_socket_t *sock, unsigned int port, unsigned long non_blocking, int listen_socket) {
    if (!sock)
        return md3_net__error("Socket is NULL");

    // Create the socket
    sock->handle = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (sock->handle <= 0) {
        md3_net_socket_close(sock);
        return md3_net__error("Failed to create socket");
    }

    // Bind the socket to the port
    struct sockaddr_in address;
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = INADDR_ANY;
    address.sin_port = htons(port);

    if (bind(sock->handle, (const struct sockaddr *) &address, sizeof(struct sockaddr_in)) != 0) {
        md3_net_socket_close(sock);
        return md3_net__error("Failed to bind socket");
    }

    // Set the socket to non-blocking if neccessary
    if (non_blocking) {
#ifdef _WIN32
        if (ioctlsocket(sock->handle, FIONBIO, &non_blocking) != 0) {
            md3_net_socket_close(sock);
            return md3_net__error("Failed to set socket to non-blocking");
        }
#else
        if (fcntl(sock->handle, F_SETFL, O_NONBLOCK, non_blocking) != 0) {
            md3_net_socket_close(sock);
            return md3_net__error("Failed to set socket to non-blocking");
        }
#endif
	sock->ready = 0;
    }

    if (listen_socket) {
#ifndef SOMAXCONN
#define SOMAXCONN 10
#endif
		if (listen(sock->handle, SOMAXCONN) != 0) {
            md3_net_socket_close(sock);
            return md3_net__error("Failed make socket listen");
        }
    }
    sock->non_blocking = non_blocking;

    return 0;
}

// Returns 1 if it would block, <0 if there's an error.
MD3_NET_DEF int md3_net_check_would_block(md3_net_socket_t *socket) {
    struct timeval timer;
    fd_set writefd;
    int retval;

    if (socket->non_blocking && !socket->ready) {
        FD_ZERO(&writefd);
        FD_SET(socket->handle, &writefd);
        timer.tv_sec = 0;
        timer.tv_usec = 0;
		retval = select(0, NULL, &writefd, NULL, &timer);
        if (retval == 0)
			return 1;
		else if (retval == MD3_NET_SOCKET_ERROR) {
			md3_net_socket_close(socket);
			return md3_net__error("Got socket error from select()");
		}
		socket->ready = 1;
    }

	return 0;
}

MD3_NET_DEF int md3_net_tcp_make_socket_ready(md3_net_socket_t *socket) {
	if (!socket->non_blocking)
		return 0;
	if (socket->ready)
		return 0;

    fd_set writefd;
    int retval;

    FD_ZERO(&writefd);
    FD_SET(socket->handle, &writefd);
	retval = select(0, NULL, &writefd, NULL, NULL);
	if (retval != 1)
		return md3_net__error("Failed to make non-blocking socket ready");

	socket->ready = 1;

	return 0;
}

MD3_NET_DEF int md3_net_tcp_connect(md3_net_socket_t *socket, md3_net_address_t remote_addr) {
    struct sockaddr_in address;
    int retval;

    if (!socket)
        return md3_net__error("Socket is NULL");

	retval = md3_net_check_would_block(socket);
	if (retval == 1)
		return 1;
	else if (retval)
		return -1;

    address.sin_family = AF_INET;
    address.sin_addr.s_addr = remote_addr.host;
    address.sin_port = htons(remote_addr.port);

    retval = connect(socket->handle, (const struct sockaddr *) &address, sizeof(address));
	if (retval == MD3_NET_SOCKET_ERROR) {
        md3_net_socket_close(socket);
        return md3_net__error("Failed to connect socket");
    }

    return 0;
}

MD3_NET_DEF int md3_net_tcp_accept(md3_net_socket_t *listening_socket, md3_net_socket_t *remote_socket, md3_net_address_t *remote_addr) {
    struct sockaddr_in address;
	int retval, handle;

    if (!listening_socket)
        return md3_net__error("Listening socket is NULL");
    if (!remote_socket)
        return md3_net__error("Remote socket is NULL");
    if (!remote_addr)
        return md3_net__error("Address pointer is NULL");

	retval = md3_net_check_would_block(listening_socket);
	if (retval == 1)
		return 1;
	else if (retval)
		return -1;
#ifdef _WIN32
    typedef int socklen_t;
#endif
	socklen_t addrlen = sizeof(address);
	handle = accept(listening_socket->handle, (struct sockaddr *)&address, &addrlen);

	if (handle == MD3_NET_INVALID_SOCKET)
		return 2;

    remote_addr->host = address.sin_addr.s_addr;
    remote_addr->port = ntohs(address.sin_port);
	remote_socket->non_blocking = listening_socket->non_blocking;
	remote_socket->ready = 0;
	remote_socket->handle = handle;

	return 0;
}

MD3_NET_DEF void md3_net_socket_close(md3_net_socket_t *socket) {
    if (!socket) {
        return;
    }

    if (socket->handle) {
#ifdef _WIN32
        closesocket(socket->handle);
#else
        close(socket->handle);
#endif
    }
}

MD3_NET_DEF int md3_net_udp_socket_send(md3_net_socket_t *socket, md3_net_address_t destination, const void *data, int size) {
    if (!socket) {
        return md3_net__error("Socket is NULL");
    }

    struct sockaddr_in address;
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = destination.host;
    address.sin_port = htons(destination.port);

    int sent_bytes = sendto(socket->handle, (const char *) data, size, 0, (const struct sockaddr *) &address, sizeof(struct sockaddr_in));
    if (sent_bytes != size) {
        return md3_net__error("Failed to send data");
    }

    return 0;
}

MD3_NET_DEF int md3_net_udp_socket_receive(md3_net_socket_t *socket, md3_net_address_t *sender, void *data, int size) {
    if (!socket) {
        return md3_net__error("Socket is NULL");
    }

#ifdef _WIN32
    typedef int socklen_t;
#endif

    struct sockaddr_in from;
    socklen_t from_length = sizeof(from);

    int received_bytes = recvfrom(socket->handle, (char *) data, size, 0, (struct sockaddr *) &from, &from_length);
    if (received_bytes <= 0) {
        return 0;
    }

    sender->host = from.sin_addr.s_addr;
    sender->port = ntohs(from.sin_port);

    return received_bytes;
}

MD3_NET_DEF int md3_net_tcp_socket_send(md3_net_socket_t *remote_socket, const void *data, int size) {
	int retval;

    if (!remote_socket) {
        return md3_net__error("Socket is NULL");
    }

	retval = md3_net_check_would_block(remote_socket);
	if (retval == 1)
		return 1;
	else if (retval)
		return -1;

    int sent_bytes = send(remote_socket->handle, (const char *) data, size, 0);
    if (sent_bytes != size) {
        return md3_net__error("Failed to send data");
    }

    return 0;
}

MD3_NET_DEF int md3_net_tcp_socket_receive(md3_net_socket_t *remote_socket, void *data, int size) {
	int retval;

    if (!remote_socket) {
        return md3_net__error("Socket is NULL");
    }

	retval = md3_net_check_would_block(remote_socket);
	if (retval == 1)
		return 1;
	else if (retval)
		return -1;

#ifdef _WIN32
    typedef int socklen_t;
#endif

    int received_bytes = recv(remote_socket->handle, (char *) data, size, 0);
    if (received_bytes <= 0) {
        return 0;
    }
    return received_bytes;
}

#endif

