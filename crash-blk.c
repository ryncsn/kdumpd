/*
 * A small program that setup the squash mount and overlayfs mount without using libc.
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stddef.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <string.h>
#include <errno.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <linux/nbd.h>

#include <errno.h>

#include "crash-blk.h"
#include "utils.h"

static int nbd_socket_alloc(struct nbd_dev *dev) {
	int socket[2];
	int err;

	err = socketpair(AF_UNIX, SOCK_STREAM, 0, socket);
	if (err) {
		// TODO stderr
		printf("Failed to open socker.");
	}

	dev->k_socket_fd = socket[0];
	dev->u_socket_fd = socket[1];

	return 0;
}

static int nbd_fd_setup(struct nbd_dev *ndev, char *nbd_path, int bs, int cnt) {
	int nbd_fd, err;

	nbd_fd = open(nbd_path, O_RDWR);
	if (nbd_fd == -1) {
		// TODO error
		return -1;
	}

	printf("NBD_SET_BLKSIZE %x\n", bs);
	err = ioctl(nbd_fd, NBD_SET_BLKSIZE, bs);
	if (err)
		printf("TODO Failure.");

	printf("NBD_SET_SIZE_BLOCKS %x\n", cnt);
	err = ioctl(nbd_fd, NBD_SET_SIZE_BLOCKS, cnt);
	if (err)
		printf("TODO Failure.");

	// printf("NBD_SET_SIZE %x\n", bs * cnt);
	// err = ioctl(nbd_fd, NBD_SET_SIZE, bs * cnt);
	// if (err)
	// 	printf("TODO Failure.");

	printf("NBD_CLEAR_SOCK");
	err = ioctl(nbd_fd, NBD_CLEAR_SOCK);
	if (err)
		printf("TODO Failure.");

	printf("NBD_CLEAR_QUE");
	err = ioctl(nbd_fd, NBD_CLEAR_QUE);
	if (err)
		printf("TODO Failure.");

	ndev->nbd_fd = nbd_fd;
	return 0;
}

static int rw_len(int fd, void *buf, size_t len, char is_write) {
	ssize_t res;

	while (len > 0) {
		if (is_write)
			res = write(fd, buf, len);
		else
			res = read(fd, buf, len);

		if (res > 0) {
			len -= res;
			buf += res;
			continue;
		}

		if (errno != EAGAIN) {
			printf("TODO Failure.");
			break;
		} else {
			printf("TODO Failure.");
		}
	}

	return res;
}

static int nbd_worker_loop(struct nbd_dev *ndev) {
	int ret, nbd_fd;
	struct nbd_request req;
	struct nbd_reply rep;
	char *req_data;

	ret = 0;
	req_data = NULL;
	while (1) {
		ret = rw_len(ndev->u_socket_fd,
				&req, sizeof(struct nbd_request), 0);

		req.from = ntohll(req.from);
		req.type = ntohl(req.type);
		req.len = ntohl(req.len);

		if (ret == -1) {
			continue;
		}

		if (req.magic != htonl(NBD_REQUEST_MAGIC)) {
			printf("nbd socket error: Invalid magic.");
			continue;
		}

		memcpy(rep.handle, req.handle, sizeof(rep.handle));
		switch (req.type & NBD_CMD_MASK_COMMAND) {
			case NBD_CMD_DISC:
				printf("DEBUG: NBD_CMD_DISC\n");
				/* DISC: DISConnect */
				return 0;

			case NBD_CMD_WRITE:
				printf("DEBUG: NBD_CMD_WRITE, len %x, from %llx\n", req.len, req.from);

				req_data = malloc(req.len);
				rw_len(ndev->u_socket_fd, req_data, req.len, 0);
				ret = ndev->ops->write(req_data, req.len, req.from,
						ndev->opaque);

				printf("DEBUG: NBD_CMD_WRITE_REP\n");
				rep.magic = htonl(NBD_REPLY_MAGIC);
				rep.error = htonl(ret);
				rw_len(ndev->u_socket_fd, &rep, sizeof(rep), 1);
				printf("DEBUG: NBD_CMD_WRITE_REP DONE\n");

				break;

			case NBD_CMD_READ:
				printf("DEBUG: NBD_CMD_READ, len %x, from %llx\n", req.len, req.from);
				req_data = malloc(req.len);
				ret = ndev->ops->read(req_data, req.len, req.from,
						ndev->opaque);

				printf("DEBUG: NBD_CMD_READ REP\n");
				rep.magic = htonl(NBD_REPLY_MAGIC);
				rep.error = htonl(ret);
				rw_len(ndev->u_socket_fd, &rep, sizeof(rep), 1);
				printf("DEBUG: NBD_CMD_READ REP DONE 1\n");
				rw_len(ndev->u_socket_fd, req_data, req.len, 1);
				printf("DEBUG: NBD_CMD_READ REP DONE 2\n");

				break;

			case NBD_CMD_FLUSH:
			case NBD_CMD_TRIM:
				printf("Unsupported NBD CMD: %x", req.type);
				break;

			default:
				// TODO
				printf("Invalid NBD CMD: %x", req.type);
				break;
		}

		if (req_data) {
			free(req_data);
		}
	}

	return nbd_fd;
}

static int nbd_worker(struct nbd_dev *ndev) {
	int ret;

	close(ndev->u_socket_fd);

	ret = ioctl(ndev->nbd_fd, NBD_SET_SOCK, ndev->k_socket_fd);
	if (ret) {
		printf("TODO\n");
	}

	/* Start and hold the device */
	ret = ioctl(ndev->nbd_fd, NBD_DO_IT);
	if (ret) {
		printf("TODO\n");
	}

	return ret;
}

static int nbd_sub_worker(struct nbd_dev *ndev) {
	close(ndev->k_socket_fd);

	return nbd_worker_loop(ndev);
}

static int nbd_start_worker(struct nbd_dev *ndev) {
	int ret;
	pid_t worker_pid, sub_worker_pid;

	printf("DEBUG: Starting nbd_worker\n");

	worker_pid = fork();
	if (!worker_pid) {
		printf("DEBUG: Starting nbd_sub_worker\n");

		sub_worker_pid = fork();

		if (!sub_worker_pid) {
			nbd_sub_worker(ndev);
		} else {
			nbd_worker(ndev);
			waitpid(sub_worker_pid, &ret, 0);
			// TODO: check ret
		}
	} else {
		close(ndev->u_socket_fd);
		close(ndev->k_socket_fd);

		ndev->worker_pid = worker_pid;
	}

	return 0;
}

static int vmcore_reuse_rw(char *data, int len, int from,
		void *opaque, char is_write) {
	int idx, offset, copy;
	struct crash_block_dev *cdev;

	idx = from / REUSE_AREA_SIZE;
	cdev = opaque;
	if (idx > cdev->area_num) {
		printf("ERR: DEBUG: %x out of border\n", from);
		return -1;
	}

	while (len > 0) {
		copy = (len < REUSE_AREA_SIZE) ? len : REUSE_AREA_SIZE;
		offset = from & (REUSE_AREA_SIZE - 1);
		lseek(cdev->vmcore_fd, cdev->areas[idx].offset + offset, SEEK_SET);

		lseek(cdev->vmcore_fd, cdev->areas[idx].offset + offset, SEEK_SET);
		printf("DEBUG: Hit 0x%lx - 0x%lx\n", cdev->areas[idx].offset, cdev->areas[idx].offset + copy);

		if (is_write) {
			printf("DEBUG: lseek 0x%lx, write 0x%x\n", cdev->areas[idx].offset + offset, copy);
			write(cdev->vmcore_fd, data, copy);
		} else {
			printf("DEBUG: lseek 0x%lx, read 0x%x\n", cdev->areas[idx].offset + offset, copy);
			read(cdev->vmcore_fd, data, copy);
		}

		data += copy;
		len -= copy;
	}

	return 0;
}

static int vmcore_reuse_read(char *data, int len, int from, void *opaque) {
	return vmcore_reuse_rw(data, len, from, opaque, 0);
}

static int vmcore_reuse_write(char *data, int len, int from, void *opaque) {
	return vmcore_reuse_rw(data, len, from, opaque, 1);
}

static struct nbd_io_ops cdev_io_ops = {
	vmcore_reuse_read,
	vmcore_reuse_write,
};

// TODO maxsize not used
static size_t vmcore_find_reuseable(char *vmcore_file, size_t max_size, struct crash_block_dev *data) {
	int i = 0;
	unsigned long start, end, offset;
	size_t size = 0;
	FILE *f = fopen("/vmcore-debug", "r");

	// TODO
	data->areas = malloc(sizeof(*data->areas) * 128);
	while (i < 128 && EOF != fscanf(f, "0x%lx - 0x%lx (%lx)\n", &start, &end, &offset)) {
		while (i < 128 && REUSE_AREA_SIZE < (end - start)) {
			printf("DEBUG: using area %lx - %lx, offset: %lx\n",
					start, start + REUSE_AREA_SIZE, offset);
			data->areas[i].offset = offset;
			start += REUSE_AREA_SIZE;
			offset += REUSE_AREA_SIZE;
			size += REUSE_AREA_SIZE;
			i ++;
		}
	}
	data->area_num = i;
	fclose(f);

	printf("DEBUG: usable size %lx\n", size);
	return size;
}

int crash_block_dev_start(struct crash_block_dev *cdev) {
	return nbd_start_worker(cdev->nbd_dev);
};

int crash_block_dev_stop(struct crash_block_dev *cdev) {
	// TODO
	return 0;
};

struct crash_block_dev* crash_block_dev_new(size_t size) {
	struct nbd_dev *ndev;
	struct crash_block_dev *cdev;

	int block_size, blocks;
	size_t actual_size;

	cdev = calloc(1, sizeof(*cdev));
	ndev = calloc(1, sizeof(*ndev));

	cdev->nbd_dev = ndev;
	ndev->ops = &cdev_io_ops;
	ndev->opaque = cdev;

	/* Find reuseable areas*/
	actual_size = vmcore_find_reuseable("/proc/vmcore", 0, cdev);
	cdev->size = actual_size;
	cdev->vmcore_fd = open("/proc/vmcore", O_RDWR);

	block_size = 512;
	blocks = actual_size / block_size;

	nbd_fd_setup(ndev, "/dev/nbd0", block_size, blocks);
	nbd_socket_alloc(ndev);

	return cdev;
}
