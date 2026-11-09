/* Fuzz the kernel's boot config parser (lib/bootconfig.c), built in userspace the way
 * tools/bootconfig does, then walk the resulting tree like the kernel's consumers do. */
#include <linux/bootconfig.h>

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	const char *msg;
	char key[XBC_KEYLEN_MAX];
	struct xbc_node *leaf, *vnode, *child;
	const char *val;
	int pos, nodes, ret;
	size_t dsize, len;
	char *cmdline;

	if (xbc_init((const char *)data, size, &msg, &pos) < 0)
		return -1;

	xbc_for_each_key_value(leaf, val) {
		ret = xbc_node_compose_key(leaf, key, sizeof(key));
		if (ret < 0)
			continue;
		(void)xbc_find_node(key);
		(void)xbc_node_find_value(NULL, key, &vnode);
		vnode = xbc_node_get_child(leaf);
		if (vnode)
			xbc_array_for_each_value(vnode, val)
				(void)strlen(val);
	}

	xbc_node_for_each_child(xbc_root_node(), child) {
		xbc_node_for_each_subkey(child, leaf)
			(void)xbc_node_get_data(leaf);
	}

	/* The kernel renders the config into the command line in two passes: size, then fill. */
	ret = xbc_snprint_cmdline(NULL, 0, xbc_root_node());
	if (ret >= 0) {
		len = (size_t)ret + 1;
		cmdline = malloc(len);
		if (cmdline) {
			(void)xbc_snprint_cmdline(cmdline, len, xbc_root_node());
			free(cmdline);
		}
	}

	xbc_get_info(&nodes, &dsize);
	xbc_exit();
	return 0;
}
