#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <errno.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <arpa/inet.h>

#define HANDSHAKE_MSG "READY"
#define PORT 7777

void start_dsm_server(void)
{
	int server_fd, client_fd;
	struct sockaddr_in addr;
	socklen_t addrlen = sizeof(addr);
	char buffer[64] = {0};
	int restored_pid;
	int n, opt = 1;
	FILE *f = fopen("/tmp/criu-restored.pid", "r");

	// 1. Set up TCP server socket
	server_fd = socket(AF_INET, SOCK_STREAM, 0);
	if (server_fd < 0) {
		perror("socket");
		exit(EXIT_FAILURE);
	}

	setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

	memset(&addr, 0, sizeof(addr));
	addr.sin_family = AF_INET;
	addr.sin_addr.s_addr = INADDR_ANY;
	addr.sin_port = htons(PORT);

	if (bind(server_fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
		perror("bind");
		close(server_fd);
		exit(EXIT_FAILURE);
	}

	if (listen(server_fd, 1) < 0) {
		perror("listen");
		close(server_fd);
		exit(EXIT_FAILURE);
	}

	printf("[DSM Server] Waiting for client on port %d...\n", PORT);

	client_fd = accept(server_fd, (struct sockaddr *)&addr, &addrlen);
	if (client_fd < 0) {
		perror("accept");
		close(server_fd);
		exit(EXIT_FAILURE);
	}

	// 2. Receive handshake
	n = read(client_fd, buffer, sizeof(buffer) - 1);
	if (n <= 0) {
		perror("read");
		close(client_fd);
		close(server_fd);
		exit(EXIT_FAILURE);
	}

	buffer[n] = '\0';
	if (strcmp(buffer, HANDSHAKE_MSG) != 0) {
		fprintf(stderr, "[DSM Server] Invalid handshake: %s\n", buffer);
		close(client_fd);
		close(server_fd);
		exit(EXIT_FAILURE);
	}

	printf("[DSM Server] Handshake received. Resuming process.\n");

	// 3. Read PID from file
	if (!f || fscanf(f, "%d", &restored_pid) != 1) {
		perror("fscanf");
		close(client_fd);
		close(server_fd);
		exit(EXIT_FAILURE);
	}
	fclose(f);

	// 4. Resume the stopped process
	if (kill(restored_pid, SIGCONT) != 0) {
		perror("kill(SIGCONT)");
		close(client_fd);
		close(server_fd);
		exit(EXIT_FAILURE);
	}

	printf("[DSM Server] Sent SIGCONT to PID %d.\n", restored_pid);

	close(client_fd);
	close(server_fd);
}
