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
	int ret;

	ret = socketpair(AF_UNIX, SOCK_STREAM, 0, socket);
	if (ret) {
		fprintf(stderr, "Failed to allocate NBD socket.\n");
		return ret;
	}

	dev->k_socket_fd = socket[0];
	dev->u_socket_fd = socket[1];

	return 0;
}

static int nbd_fd_setup(struct nbd_dev *ndev, int bs, int cnt) {
	int nbd_fd, ret;

	nbd_fd = open(ndev->nbd_dev_file, O_RDWR);
	if (nbd_fd == -1) {
		fprintf(stderr, "Failed to open NBD device.\n");
		return -1;
	}

	ret = ioctl(nbd_fd, NBD_SET_BLKSIZE, bs);
	if (ret) {
		fprintf(stderr, "Failed to set NBD block size.\n");
		goto out_err;
	}

	printf("NBD_SET_SIZE_BLOCKS %x\n", cnt);
	ret = ioctl(nbd_fd, NBD_SET_SIZE_BLOCKS, cnt);
	if (ret) {
		fprintf(stderr, "Failed to set NBD size.\n");
		goto out_err;
	}

	printf("NBD_CLEAR_SOCK");
	ret = ioctl(nbd_fd, NBD_CLEAR_SOCK);
	if (ret) {
		fprintf(stderr, "Failed to clear up NBD socket.\n");
		goto out_err;
	}

	printf("NBD_CLEAR_QUE");
	ret = ioctl(nbd_fd, NBD_CLEAR_QUE);
	if (ret) {
		fprintf(stderr, "Failed to clear up NBD queue.\n");
		goto out_err;
	}

	ndev->nbd_fd = nbd_fd;
	return 0;

out_err:
	return ret;
}

static ssize_t rw_len(int fd, void *buf, size_t len, char is_write) {
	ssize_t ret;

	while (len > 0) {
		if (is_write)
			ret = write(fd, buf, len);
		else
			ret = read(fd, buf, len);

		if (ret > 0) {
			len -= ret;
			buf += ret;
		} else {
			if (errno != EAGAIN) {
				fprintf(stderr, "NBD socket read error.\n");
				return errno;
			}
		}
	}

	return ret;
}

static int nbd_worker_loop(struct nbd_dev *ndev) {
	int ret;
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
			fprintf(stderr, "NBD socket error: Invalid magic.\n");
			continue;
		}

		memcpy(rep.handle, req.handle, sizeof(rep.handle));
		switch (req.type & NBD_CMD_MASK_COMMAND) {
			case NBD_CMD_DISC:
				/* DISC: DISConnect */
				printf("Quit on NBD_CMD_DISC\n");
				return 0;

			case NBD_CMD_WRITE:
				req_data = malloc(req.len);

				rw_len(ndev->u_socket_fd, req_data, req.len, 0);
				ret = ndev->ops->write(req_data, req.len, req.from,
						ndev->opaque);

				rep.magic = htonl(NBD_REPLY_MAGIC);
				rep.error = htonl(ret);
				rw_len(ndev->u_socket_fd, &rep, sizeof(rep), 1);

				break;
			case NBD_CMD_READ:
				req_data = malloc(req.len);
				ret = ndev->ops->read(req_data, req.len, req.from,
						ndev->opaque);

				rep.magic = htonl(NBD_REPLY_MAGIC);
				rep.error = htonl(ret);

				rw_len(ndev->u_socket_fd, &rep, sizeof(rep), 1);
				rw_len(ndev->u_socket_fd, req_data, req.len, 1);

				break;
			case NBD_CMD_FLUSH:
			case NBD_CMD_TRIM:
				fprintf(stderr, "Unsupported NBD CMD: %x\n",
					req.type);
				break;
			default:
				fprintf(stderr, "Invalid NBD CMD: %x\n",
					req.type);
				break;
		}

		if (req_data) {
			free(req_data);
			req_data = NULL;
		}
	}

	return ret;
}

static int nbd_worker(struct nbd_dev *ndev) {
	int ret;

	close(ndev->u_socket_fd);

	ret = ioctl(ndev->nbd_fd, NBD_SET_SOCK, ndev->k_socket_fd);
	if (ret) {
		fprintf(stderr, "Failed to set NBD socket\n");
	}

	/* Start and hold the device */
	ret = ioctl(ndev->nbd_fd, NBD_DO_IT);
	if (ret) {
		fprintf(stderr, "Failed to start NBD device\n");
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
	printf("Starting NBD device worker on device %s.\n", ndev->nbd_dev_file);

	worker_pid = fork();
	if (!worker_pid) {
		sub_worker_pid = fork();
		if (!sub_worker_pid) {
			nbd_sub_worker(ndev);
		} else {
			nbd_worker(ndev);
			waitpid(sub_worker_pid, &ret, 0);
			// TODO: check here
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
		fprintf(stderr, "Out of VMCORE IO request 0x%x@0x%x\n", len, from);
		return -1;
	}

	while (len > 0) {
		copy = (len < REUSE_AREA_SIZE) ? len : REUSE_AREA_SIZE;
		offset = from & (REUSE_AREA_SIZE - 1);
		lseek(cdev->vmcore_fd, cdev->areas[idx].offset + offset, SEEK_SET);

		if (is_write) {
			write(cdev->vmcore_fd, data, copy);
		} else {
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
	// TODO: Not stopping yet
	return 0;
};

struct crash_block_dev* crash_block_dev_new(char *nbd_dev_file, size_t max_size) {
	struct nbd_dev *ndev;
	struct crash_block_dev *cdev;

	int block_size, blocks;
	size_t actual_size;

	cdev = calloc(1, sizeof(*cdev));
	ndev = calloc(1, sizeof(*ndev));

	cdev->nbd_dev = ndev;
	ndev->ops = &cdev_io_ops;
	ndev->opaque = cdev;
	ndev->nbd_dev_file = strdup(nbd_dev_file);

	/* Find reuseable areas*/
	actual_size = vmcore_find_reuseable("/proc/vmcore", 0, cdev);
	cdev->size = actual_size;
	cdev->vmcore_fd = open("/proc/vmcore", O_RDWR);

	block_size = 512;
	blocks = actual_size / block_size;

	nbd_fd_setup(ndev, block_size, blocks);
	nbd_socket_alloc(ndev);

	return cdev;
}
