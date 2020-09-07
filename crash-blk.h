/*
 * A small program that setup the squash mount and overlayfs mount without using libc.
 */
#define _GNU_SOURCE
#include <stdlib.h>

#define NBD_CMD_MASK_COMMAND 0x0000ffff

struct nbd_dev {
	int nbd_fd;
	char *nbd_dev_file;

	int k_socket_fd;
	int u_socket_fd;

	void *opaque;

	struct nbd_io_ops *ops;
	pid_t worker_pid;
};

struct nbd_io_ops {
	int (*read)(char *data, int len, int from, void *opaque);
	int (*write)(char *data, int len, int from, void *opaque);
};

#define REUSE_AREA_SIZE (1 << 20)
struct crash_block_dev {
	unsigned long size;
	int vmcore_fd;

	// TODO: Use bit based radix tree
	int area_num;
	struct areas {
		unsigned long offset;
		unsigned long size;
	} *areas;

	struct nbd_dev *nbd_dev;
};

int crash_block_dev_start(struct crash_block_dev *cdev);
int crash_block_dev_stop(struct crash_block_dev *cdev);
struct crash_block_dev* crash_block_dev_new(char *nbd_dev_file, size_t size);
