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

void start_dsm_client(const char *server_ip)
{
	int sockfd;
	struct sockaddr_in serv_addr;
	int restored_pid;
	FILE *f = fopen("/tmp/criu-restored.pid", "r");

	// 1. Create socket
	sockfd = socket(AF_INET, SOCK_STREAM, 0);
	if (sockfd < 0) {
		perror("socket");
		exit(EXIT_FAILURE);
	}

	memset(&serv_addr, 0, sizeof(serv_addr));
	serv_addr.sin_family = AF_INET;
	serv_addr.sin_port = htons(PORT);

	if (inet_pton(AF_INET, server_ip, &serv_addr.sin_addr) <= 0) {
		fprintf(stderr, "[DSM Client] Invalid IP: %s\n", server_ip);
		close(sockfd);
		exit(EXIT_FAILURE);
	}

	// 2. Connect to server
	printf("[DSM Client] Connecting to DSM server at %s:%d...\n", server_ip, PORT);
	if (connect(sockfd, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0) {
		perror("connect");
		close(sockfd);
		exit(EXIT_FAILURE);
	}

	// 3. Send handshake
	if (write(sockfd, HANDSHAKE_MSG, strlen(HANDSHAKE_MSG)) != strlen(HANDSHAKE_MSG)) {
		perror("write");
		close(sockfd);
		exit(EXIT_FAILURE);
	}

	printf("[DSM Client] Handshake sent.\n");

	// 4. Read PID and send SIGCONT
	if (!f || fscanf(f, "%d", &restored_pid) != 1) {
		perror("fscanf");
		close(sockfd);
		exit(EXIT_FAILURE);
	}
	fclose(f);

	if (kill(restored_pid, SIGCONT) != 0) {
		perror("kill(SIGCONT)");
		close(sockfd);
		exit(EXIT_FAILURE);
	}

	printf("[DSM Client] Sent SIGCONT to PID %d.\n", restored_pid);

	close(sockfd);
}
