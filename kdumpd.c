/*
 * A small program that setup the squash mount and overlayfs mount without using libc.
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <unistd.h>
#include <sys/mman.h>
#include <malloc.h>
#include "crash-blk.h"

/*
 * Enable Linux Swap on reuseable crash mem
 * to reduce crashkernel memory pressure
 */
int setup_crash_blk_swap() {
	struct crash_block_dev* cdev = crash_block_dev_new(
			"/dev/nbd0", 128 * 1024 * 1024);

	crash_block_dev_start(cdev);
	return 0;
}

/*
 * Move the base kdump initramfs image to
 * reuseable crash mem, then mount it
 */
int setup_crash_blk_initfs() {
	return -1;
}

/*
 * Just mount the default initamfs image
 */
int setup_default_initfs() {
	return -1;
}

int main(int argc, char *argv[])
{
	setup_crash_blk_swap();

	mallopt(M_TOP_PAD, 4096);
	mallopt(M_TRIM_THRESHOLD, 4096);

	while(1) {
		sleep(1);
	}

	return 0;
}

