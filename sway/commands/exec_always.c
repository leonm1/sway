#define _POSIX_C_SOURCE 200809L
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>
#include <signal.h>
#include "sway/commands.h"
#include "sway/config.h"
#include "sway/security.h"
#include "sway/server.h"
#include "sway/tree/container.h"
#include "sway/tree/root.h"
#include "sway/tree/workspace.h"
#include "log.h"
#include "stringop.h"

struct cmd_results *cmd_exec_always(int argc, char **argv) {
	struct cmd_results *error = NULL;
	if (!config->active) return cmd_results_new(CMD_DEFER, NULL, NULL);
	if ((error = checkarg(argc, "exec_always", EXPECTED_MORE_THAN, 0))) {
		return error;
	}

	char *tmp = NULL;
	if (strcmp(argv[0], "--no-startup-id") == 0) {
		wlr_log(WLR_INFO, "exec switch '--no-startup-id' not supported, ignored.");
		--argc; ++argv;
		if ((error = checkarg(argc, "exec_always", EXPECTED_MORE_THAN, 0))) {
			return error;
		}
	}

	if (argc == 1 && (argv[0][0] == '\'' || argv[0][0] == '"')) {
		tmp = strdup(argv[0]);
		strip_quotes(tmp);
	} else {
		tmp = join_args(argv, argc);
	}

	int sv[2];
	create_client_socket(sv);

	// Put argument into cmd array
	char cmd[4096];
	strncpy(cmd, tmp, sizeof(cmd) - 1);
	cmd[sizeof(cmd) - 1] = 0;
	free(tmp);
	wlr_log(WLR_DEBUG, "Executing %s", cmd);

	int fd[2];
	if (pipe(fd) != 0) {
		wlr_log(WLR_ERROR, "Unable to create pipe for fork");
	}

	pid_t pid, child;
	// Fork process
	if ((pid = fork()) == 0) {
		// Fork child process again
		setsid();
		sigset_t set;
		sigemptyset(&set);
		sigprocmask(SIG_SETMASK, &set, NULL);
		close(fd[0]);

		int sockfd = dup(sv[1]);
		if (sockfd == -1) {
			child = -1;
			ssize_t s = 0;
			while ((size_t)s < sizeof(pid_t)) {
				s += write(fd[1], ((uint8_t *)&child) + s, sizeof(pid_t) - s);
			}
			exit(0);
		}

		char sockvar[32];
		snprintf(sockvar, sizeof(sockvar), "%d", sockfd);
		setenv("WAYLAND_SOCKET", sockvar, 1);

		if ((child = fork()) == 0) {
			close(fd[1]);
			execl("/bin/sh", "/bin/sh", "-c", cmd, (void *)NULL);
			_exit(0);
		}
		ssize_t s = 0;
		while ((size_t)s < sizeof(pid_t)) {
			s += write(fd[1], ((uint8_t *)&child) + s, sizeof(pid_t) - s);
		}
		close(fd[1]);
		_exit(0); // Close child process
	} else if (pid < 0) {
		close(fd[0]);
		close(fd[1]);
		close(sv[0]);
		close(sv[1]);
		return cmd_results_new(CMD_FAILURE, "exec_always", "fork() failed");
	}
	close(fd[1]); // close write
	close(sv[1]); // close write

	ssize_t s = 0;
	while ((size_t)s < sizeof(pid_t)) {
		s += read(fd[0], ((uint8_t *)&child) + s, sizeof(pid_t) - s);
	}
	close(fd[0]);
	// cleanup child process
	waitpid(pid, NULL, 0);
	if (child > 0) {
		wlr_log(WLR_DEBUG, "Child process created with pid %d", child);
		root_record_workspace_pid(child);
	} else {
		return cmd_results_new(CMD_FAILURE, "exec_always",
			"Second fork() failed");
	}

	create_secure_client(server.wl_display, sv[0], cmd);
	return cmd_results_new(CMD_SUCCESS, NULL, NULL);
}
