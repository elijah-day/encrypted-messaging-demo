/* Copyright (C) 2023 Elijah Day

This software is distributed under the MIT license.  See LICENSE for more
information. */

#include "SDL2/SDL.h"
#include "SDL2/SDL_net.h"
#include "sodium.h"
#include "stdbool.h"
#include "stdio.h"
#include "string.h"
#include "time.h"

/* Error messages */
#define PRINT_SDL_ERR(str) printf(str " error: %s\n", SDL_GetError())
#define PRINT_SODIUM_ERROR(str) printf(str " error\n")
#define PRINT_ARG_CNT_ERR printf("Not enough arguments!\n")

/* Arg definitions */
#define CLIENT_ARG 1
#define SERVER_IP_CLIENT_ARG 2
#define PORT_CLIENT_ARG 3

#define SERVER_ARG 1
#define PORT_SERVER_ARG 2

#define CLIENT_ARG_CNT 4
#define SERVER_ARG_CNT 3

/* Max definitions */
#define MAX_CLIENT_CNT 4
#define MAX_MSG_LEN 256
#define MAX_CLIENT_NAME_LEN 16

/* Misc. definitions */
#define SOCKET_CHECK_TIMEOUT 1 /* In milliseconds */
#define MOTD "Welcome to the server!\n"
#define INPUT_NOTE "NOTE: YOU MUST HAVE THE SDL WINDOW FOCUSED WHEN \
PERFORMING ANY KEYBOARD INPUT\n"
#define CIPHER_TEXT_LEN (MAX_MSG_LEN + crypto_box_MACBYTES)

/* Window definitions */
#define WINDOW_NAME "Encrypted Messenger Demo"
#define WINDOW_WIDTH 640
#define WINDOW_HEIGHT 360

/* Size definitions */
#define PUBLIC_KEY_SIZE (crypto_box_PUBLICKEYBYTES * sizeof(unsigned char))

/* Struct type definitions */
typedef struct client_t
{
	TCPsocket socket;
	bool is_connected;
	char name[MAX_CLIENT_NAME_LEN];
	unsigned char public_key[crypto_box_PUBLICKEYBYTES];
}
client_t;

typedef struct msg_data_t
{
	unsigned char public_key[crypto_box_PUBLICKEYBYTES];
	unsigned char nonce[crypto_box_NONCEBYTES];
	unsigned char cipher_text[CIPHER_TEXT_LEN];
}
msg_data_t;

/* Variables */
static bool is_running;
static char recv_msg_buf[MAX_MSG_LEN];
static char cat_msg_buf[MAX_MSG_LEN + MAX_CLIENT_NAME_LEN];
static int rv; /* Generic return value integer */
static int port;
static int connected_client_cnt;
static int ready_socket_cnt;
static IPaddress server_ip;
static msg_data_t msg_data;
static SDL_Event event;
static SDLNet_SocketSet socket_set;
static TCPsocket server_socket;
static unsigned char client_public_key[crypto_box_PUBLICKEYBYTES]; /* Unused when running a server */
static unsigned char server_public_key[crypto_box_PUBLICKEYBYTES];
static unsigned char client_private_key[crypto_box_SECRETKEYBYTES];
static unsigned char server_private_key[crypto_box_SECRETKEYBYTES];
static char dummy_buf[MAX_MSG_LEN];

/* TODO: The private key variable can probably be shared between client and
server */

bool init_sodium(void)
{
	bool init_success = true;

	if(sodium_init() == -1)
	{
		PRINT_SODIUM_ERROR("sodium_init");
		init_success = false;
	}
	
	return init_success;
}

bool init_sdl(void)
{
	bool init_success = true;
	
	if(SDL_Init(SDL_INIT_VIDEO) != 0)
	{
		PRINT_SDL_ERR("SDL_Init");
		init_success = false;
	}
}

bool init_sdl_net(void)
{
	bool init_success = true;

	if(SDLNet_Init() != 0)
	{
		PRINT_SDL_ERR("SDLNet_Init");
		init_success = false;
	}
	
	return init_success;
}

void quit_sdl(void)
{
	SDL_Quit();
}

void quit_sdl_net(void)
{
	SDLNet_Quit();
}

void print_ts(void)
{
	printf("[%d]", time(NULL));
}

void run_server(int argc, char *argv[])
{
	/* Variables */
	client_t clients[MAX_CLIENT_CNT];
	
	/* Init SDL and Sodium */
	is_running = init_sdl();
	is_running = init_sdl_net();
	is_running = init_sodium();
	
	/* Setup if init was successful */
	if(is_running)
	{
		/* Allocate the socket set for the maximum number of clients
		allowed.  Add +1 for the server socket. */
		socket_set = SDLNet_AllocSocketSet(MAX_CLIENT_CNT + 1);
		
		/* Get the server port, resolve the host, and add the server
		socket to the socket set. */
		port = atoi(argv[PORT_SERVER_ARG]);	
		SDLNet_ResolveHost(&server_ip, NULL, port);
		server_socket = SDLNet_TCP_Open(&server_ip);
		SDLNet_TCP_AddSocket(socket_set, server_socket);
		
		/* NOTE: In a more serious application each of these functions
		should have their return values checked to trace any errors. */
		
		/* Make sure all clients are set to be disconnected */
		for(int i = 0; i < MAX_CLIENT_CNT; i++)
		{
			clients[i].socket = NULL;
			clients[i].is_connected = false;
			strcpy(clients[i].name, "user");
		}
	}
	
	/* Generate server's key pair */
	crypto_box_keypair(server_public_key, server_private_key);
	
	/* Zero the connected client count */
	connected_client_cnt = 0;
	
	/* Begin main loop */
	while(is_running)
	{
		/* Handle SDL events */
		while(SDL_PollEvent(&event))
			switch(event.type)
			{
				case SDL_QUIT:
					is_running = false;
					break;
			}
		
		/* Check for ready sockets */
		ready_socket_cnt = SDLNet_CheckSockets(socket_set, SOCKET_CHECK_TIMEOUT);
		
		if(ready_socket_cnt > 0)
			for(int i = 0; i < MAX_CLIENT_CNT; i++)
			{
				printf("Client ID: %d...\n", i);
			
				/* Check the client socket first and we avoid unnecessary
				calls to SDLNet_SocketReady */
			
				if(SDLNet_SocketReady(clients[i].socket))
				{
					/* Clear the strings so we don't have fragments of
					previous messages left in them */
					memset(recv_msg_buf, 0, MAX_MSG_LEN);
					memset(cat_msg_buf, 0, MAX_MSG_LEN + MAX_CLIENT_NAME_LEN);
					
					/* Receive the client's dummy data */
					SDLNet_TCP_Recv
					(
						clients[i].socket,
						dummy_buf,
						MAX_MSG_LEN
					);
					
					/* Send the server public key to the client */
					memcpy
					(
						msg_data.public_key,
						server_public_key,
						PUBLIC_KEY_SIZE
					);
					
					SDLNet_TCP_Send
					(
						clients[i].socket,
						&msg_data,
						1 * sizeof(msg_data)
					);
					
					/* Receive and copy message data */
					SDLNet_TCP_Recv(clients[i].socket, &msg_data, 1 * sizeof(msg_data_t));
					
					/* Open the cipher text */
					rv = crypto_box_open_easy
					(
						recv_msg_buf,
						msg_data.cipher_text,
						CIPHER_TEXT_LEN,
						msg_data.nonce,
						msg_data.public_key,
						server_private_key
					);
					
					if(rv != 0)
						printf("crypto_box_open_easy error\n");
					
					/* Append the received message to the client's name to
					send to everyone else on the server */
					strcpy(cat_msg_buf, clients[i].name);
					strcat(cat_msg_buf, ": ");
					strcat(cat_msg_buf, recv_msg_buf);
					
					for(int j = 0; j < MAX_CLIENT_CNT; j++)
						if(j != i && clients[j].socket)
						{
							/* Send dummy data to the client */
							SDLNet_TCP_Send
							(
								clients[j].socket,
								dummy_buf,
								MAX_MSG_LEN
							);
							
							/* Get the client's public key */
							SDLNet_TCP_Recv
							(
								clients[j].socket,
								&msg_data,
								1 * sizeof(msg_data)
							);
							
							/* Generate nonce and encrypt message.  Put it in
							msg_data */
							randombytes_buf
							(
								msg_data.nonce,
								sizeof(msg_data.nonce)
							);
							
							rv = crypto_box_easy
							(
								msg_data.cipher_text,
								cat_msg_buf,
								MAX_MSG_LEN,
								msg_data.nonce,
								msg_data.public_key,
								server_private_key
							);
							
							/* Copy the server's public key to the msg_data */
							memcpy
							(
								msg_data.public_key,
								server_public_key,
								PUBLIC_KEY_SIZE
							);
							
							if(rv != 0)
								printf("crypto_box_easy error\n");
							
							/* Send the message data and clear the strings */
							SDLNet_TCP_Send(clients[j].socket, &msg_data, 1 * sizeof(msg_data));
						}
					
					/* Print client message to stdout */
					print_ts();
					printf("%s", cat_msg_buf);
					
					/* Remove a client on empty message (client disconnect) */
					if(strcmp(recv_msg_buf, "") == 0)
					{
						/* Remove the socket from the set and close the
						connection */
						SDLNet_TCP_DelSocket(socket_set, clients[i].socket);
						SDLNet_TCP_Close(clients[i].socket);
						connected_client_cnt -= 1;
						
						/* For some reason the sockets aren't set to NULL upon
						closing them.  Do it manually */
						clients[i].socket = NULL;
						
						print_ts();
						printf("Disconnected\n");
					}
				}
				else if(SDLNet_SocketReady(socket_set) && !clients[i].socket)
				{
					/* Reject connection if max number of clients is
					reached.  It will simply make the client wait until
					another person leaves then autoconnect them */
					if(connected_client_cnt >= MAX_CLIENT_CNT) break;
				
					/* Open connection */
					clients[i].socket = SDLNet_TCP_Accept(server_socket);
					
					/* If the client socket isn't NULL add it to the socket
					set */
					if(clients[i].socket)
					{
						SDLNet_TCP_AddSocket(socket_set, clients[i].socket);
						connected_client_cnt += 1;
						
						print_ts();
						printf("Connected\n");
					}
					else
					{
						SDLNet_TCP_Close(clients[i].socket);
					}
				}
				
				print_ts();
				printf("End\n\n");
			}
	}
	
	/* Remove the server socket from the set */
	SDLNet_TCP_DelSocket(socket_set, server_socket);
	if(server_socket)
		SDLNet_TCP_Close(server_socket);
	
	/* Free the socket set if it isn't NULL */
	if(socket_set)
		SDLNet_FreeSocketSet(socket_set);
	
	/* Quit SDL */
	quit_sdl_net();
	quit_sdl();
}

void run_client(int argc, char *argv[])
{
	/* Init SDL */
	is_running = init_sdl();
	is_running = init_sdl_net();
	
	/* Setup window and renderer */
	SDL_Window *window = SDL_CreateWindow
	(
		WINDOW_NAME,
		SDL_WINDOWPOS_UNDEFINED,
		SDL_WINDOWPOS_UNDEFINED,
		WINDOW_WIDTH,
		WINDOW_HEIGHT,
		SDL_WINDOW_RESIZABLE
	);
	
	if(window == NULL)
	{
		PRINT_SDL_ERR("SDL_CreateWindow");
		is_running = false;
	}
	
	/* So it seems that we can only read keyboard input from SDL if the key
	are being pressed in a focused window.  For now, we'll just use an
	empty window for this */
	
	SDL_Renderer *renderer = SDL_CreateRenderer
	(
		window,
		-1,
		SDL_RENDERER_ACCELERATED
	);
	
	if(renderer == NULL)
	{
		PRINT_SDL_ERR("SDL_CreateRenderer");
		is_running = false;
	}
	else
	{
		SDL_SetRenderDrawColor(renderer, 0, 0, 0, 255);
	}
	
	/* Connect to the server */
	if(is_running)
	{
		port = atoi(argv[PORT_CLIENT_ARG]);
		
		SDLNet_ResolveHost(&server_ip, argv[SERVER_IP_CLIENT_ARG], port);
		server_socket = SDLNet_TCP_Open(&server_ip);
		
		if(server_socket == NULL)
		{
			printf("Could not open server socket\n");
			is_running = false;
		}
		else
		{
			socket_set = SDLNet_AllocSocketSet(1);
			SDLNet_TCP_AddSocket(socket_set, server_socket);
		}
	}
	
	if(is_running)
	{
		/* Generate client's key pair */
		crypto_box_keypair(client_public_key, client_private_key);
	}
	
	/* Run main loop */
	while(is_running)
	{
		/* Handle SDL events */
		while(SDL_PollEvent(&event))
			switch(event.type)
			{
				case SDL_QUIT:
					is_running = false;
					break;
					
				case SDL_TEXTINPUT:
					strcat(cat_msg_buf, event.text.text);
					break;
					
				case SDL_KEYDOWN:
					SDL_SetRenderDrawColor(renderer, 31, 31, 63, 255);
					
					switch(event.key.keysym.scancode)
					{
						case SDL_SCANCODE_RETURN:
							/* Break on sending an empty message.  It spams
							this loop for some reason */
							if(strcmp(cat_msg_buf, "") == 0)
								break;
						
							/* Send dummy data to the server so that it sees
							socket activity and sends back its public key */
							SDLNet_TCP_Send
							(
								server_socket,
								dummy_buf,
								MAX_MSG_LEN
							);
							
							/* Get the server's public key */
							SDLNet_TCP_Recv
							(
								server_socket,
								&msg_data,
								1 * sizeof(msg_data)
							);
							
							/* Generate nonce and encrypt message.  Put it in
							msg_data */
							randombytes_buf
							(
								msg_data.nonce,
								sizeof(msg_data.nonce)
							);
							
							rv = crypto_box_easy
							(
								msg_data.cipher_text,
								cat_msg_buf,
								MAX_MSG_LEN,
								msg_data.nonce,
								msg_data.public_key,
								client_private_key
							);
							
							/* Copy the client's public key to the msg_data */
							memcpy
							(
								msg_data.public_key,
								client_public_key,
								PUBLIC_KEY_SIZE
							);
							
							if(rv != 0)
								printf("crypto_box_easy error\n");
							
							/* Send the message data and clear the strings */
							SDLNet_TCP_Send(server_socket, &msg_data, 1 * sizeof(msg_data));
							
							/* Print typed message to client */
							strcat(cat_msg_buf, "\n");
							printf("> %s", cat_msg_buf);
							memset(cat_msg_buf, 0, MAX_MSG_LEN);
							memset(cat_msg_buf, 0, MAX_MSG_LEN);
							
							/* Change the render draw color back to black */
							SDL_SetRenderDrawColor(renderer, 0, 0, 0, 255);
							break;
						
						case SDL_SCANCODE_BACKSPACE:
							cat_msg_buf[strlen(cat_msg_buf) - 1] = '\0';
							break;
					}
					
					break;
			}
		
		/* Check for ready sockets */
		ready_socket_cnt = SDLNet_CheckSockets(socket_set, SOCKET_CHECK_TIMEOUT);
		
		if(ready_socket_cnt > 0)
			if(SDLNet_SocketReady(server_socket))
			{
				/* Clear the message string */
				memset(recv_msg_buf, 0, MAX_MSG_LEN);
				
				/* Receive the server's dummy data */
				SDLNet_TCP_Recv
				(
					server_socket,
					dummy_buf,
					MAX_MSG_LEN
				);
				
				/* Send the client public key to the server */
				memcpy
				(
					msg_data.public_key,
					client_public_key,
					PUBLIC_KEY_SIZE
				);
				
				SDLNet_TCP_Send
				(
					server_socket,
					&msg_data,
					1 * sizeof(msg_data)
				);
				
				/* Receive and copy message data */
				SDLNet_TCP_Recv(server_socket, &msg_data, 1 * sizeof(msg_data_t));
				
				/* Open the cipher text */
				rv = crypto_box_open_easy
				(
					recv_msg_buf,
					msg_data.cipher_text,
					CIPHER_TEXT_LEN,
					msg_data.nonce,
					msg_data.public_key,
					client_private_key
				);
							
				if(rv != 0)
					printf("crypto_box_open_easy error\n");
				
				/* Print the message */
				printf("%s\n", recv_msg_buf);
			}
			
		/* Clear the renderer */
		SDL_RenderClear(renderer);
		SDL_RenderPresent(renderer);
	}
	
	/* Remove the server socket from the set */
	if(server_socket)
		SDLNet_TCP_DelSocket(socket_set, server_socket);
		SDLNet_TCP_Close(server_socket);
	
	/* Free the socket set if it isn't NULL */
	if(socket_set)
		SDLNet_FreeSocketSet(socket_set);
	
	/* Get rid of the window and renderer and quit SDL */
	SDL_DestroyRenderer(renderer);
	SDL_DestroyWindow(window);
	
	quit_sdl_net();
	quit_sdl();
}

int main(int argc, char *argv[])
{
	/* TODO */
	printf(INPUT_NOTE);

	if(argc < 2)
	{
		printf("Not enough arguments!!\n");
	}
	else if(strcmp(argv[CLIENT_ARG], "client") == 0)
	{
		run_client(argc, argv);
	}
	else if(strcmp(argv[SERVER_ARG], "server") == 0)
	{
		run_server(argc, argv);
	}
	else
	{
		printf("Usage: `main client [server ip] [port]` OR `main server [port]`\n");
	}
	
	return 0;
}
