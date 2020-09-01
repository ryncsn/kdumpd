#define _GNU_SOURCE

#include <stdlib.h>
#include <stdio.h>
#include <dirent.h>
#include <stddef.h>
#include <sys/types.h>
#include <asm/unistd.h>
#include <linux/mount.h>
#include <linux/fcntl.h>
#include <linux/loop.h>

#define KDUMP_EARLY_MODULE_DIR "/kdump/modules"

typedef struct MountPoint {
	const char *what;
	const char *where;
	const char *type;
	const char *options;
	unsigned long flags;

	const char *blob;
} MountPoint;

static const MountPoint mount_table[] = {
	{ "sysfs",       "/sys",	"sysfs",      NULL,		MS_NOSUID|MS_NOEXEC|MS_NODEV },
	{ "proc",	"/proc",	"proc",       NULL,		MS_NOSUID|MS_NOEXEC|MS_NODEV },
	{ "devtmpfs",    "/dev",	"devtmpfs",   "mode=755",	MS_NOSUID|MS_STRICTATIME },
};

// TODO: Error checks in each step
int load_modules() {
	DIR *dir;
	int fd;
	struct dirent *ent;

	dir = opendir(KDUMP_EARLY_MODULE_DIR);
	if (!dir) {
		// TODO
		printf("ERR\n");
	}

	if (dir) {
		while ((ent = readdir(dir)) != NULL) {
			fd = open(ent->d_name, O_RDONLY, 0);
			finit_module(fd, "", 0);
			close(fd);
			unlink(preload_modules[i]);
		}
	}
}

int mount_basic_mp(void) {
	int i;
	const MountPoint *p;

	for (i = 0; i < sizeof(mount_table) / sizeof(MountPoint); i ++) {
		p = mount_table + i;

		mkdir(p->where, 0755);
		mount(p->what, p->where, p->type, p->flags, p->options);
	}
}

int kdump_early_setup(void) {
	load_modules();
	mount_basic_mp();
}
