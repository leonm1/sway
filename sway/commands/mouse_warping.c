#include <string.h>
#include <strings.h>
#include "sway/commands.h"

struct cmd_results *cmd_mouse_warping(int argc, char **argv) {
	struct cmd_results *error = NULL;
	if ((error = checkarg(argc, "mouse_warping", EXPECTED_EQUAL_TO, 1))) {
		return error;
	} else if (strcasecmp(argv[0], "output") == 0) {
		config->mouse_warping = WARP_OUTPUT;
	} else if (strcasecmp(argv[0], "none") == 0) {
		config->mouse_warping = WARP_NONE;
	} else if (strcasecmp(argv[0], "container") == 0) {
		config->mouse_warping = WARP_CONTAINER;
	} else {
		return cmd_results_new(CMD_FAILURE, "mouse_warping",
				"Expected 'mouse_warping container|output|none'");
	}
	return cmd_results_new(CMD_SUCCESS, NULL, NULL);
}

