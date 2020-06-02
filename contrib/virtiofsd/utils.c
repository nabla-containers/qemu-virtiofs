/*
  FUSE: Filesystem in Userspace
  Copyright (C) 2001-2007  Miklos Szeredi <miklos@szeredi.hu>

  This program can be distributed under the terms of the GNU GPLv2.
  See the file COPYING.
*/

#include <unistd.h>
#include <stdio.h>
#include <errno.h>
#include <err.h>
#include <fcntl.h>
#include <stdlib.h>
#include <sys/syscall.h>
#include <sys/mount.h>
#include <sys/resource.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <gmodule.h>
#include "utils.h"

/* Raise the maximum number of open file descriptors to the system limit */
void setup_nofile_rlimit(void)
{
	gchar *nr_open = NULL;
	struct rlimit rlim;
	long long max;

	if (!g_file_get_contents("/proc/sys/fs/nr_open", &nr_open, NULL, NULL)) {
		fprintf(stderr, "unable to read /proc/sys/fs/nr_open\n");
		exit(1);
	}

	errno = 0;
	max = strtoll(nr_open, NULL, 0);
	if (errno) {
		err(1, "strtoll(%s)", nr_open);
	}

	rlim.rlim_cur = max;
	rlim.rlim_max = max;

	if (setrlimit(RLIMIT_NOFILE, &rlim) < 0) {
		err(1, "setrlimit(RLIMIT_NOFILE)");
	}

	g_free(nr_open);
}

static void setup_remount_slave(void)
{
	gchar *mountinfo = NULL;
	gchar *line;
	gchar *nextline;

	if (!g_file_get_contents("/proc/self/mountinfo", &mountinfo, NULL, NULL)) {
		fprintf(stderr, "unable to read /proc/self/mountinfo\n");
		exit(EXIT_FAILURE);
	}

	for (line = mountinfo; line; line = nextline) {
		gchar **fields = NULL;
		char *eol;

		nextline = NULL;

		eol = strchr(line, '\n');
		if (eol) {
			*eol = '\0';
			nextline = eol + 1;
		}

		/*
		 * The line format is:
		 * 442 441 253:4 / / rw,relatime shared:1 - xfs /dev/sda1 rw
		 */
		fields = g_strsplit(line, " ", -1);
		if (!fields[0] || !fields[1] || !fields[2] || !fields[3] ||
		    !fields[4] || !fields[5] || !fields[6]) {
			goto next; /* parsing failed, skip line */
		}

		if (!strstr(fields[6], "shared")) {
			goto next; /* not shared, skip line */
		}

		if (mount(NULL, fields[4], NULL, MS_SLAVE, NULL) < 0) {
			err(1, "mount(%s, MS_SLAVE)", fields[4]);
		}

next:
		g_strfreev(fields);
	}

	g_free(mountinfo);
}

/* This magic is based on lxc's lxc_pivot_root() */
static void setup_pivot_root(const char *source)
{
	int oldroot;
	int newroot;

	oldroot = open("/", O_DIRECTORY | O_RDONLY | O_CLOEXEC);
	if (oldroot < 0) {
		err(1, "open(/)");
	}

	newroot = open(source, O_DIRECTORY | O_RDONLY | O_CLOEXEC);
	if (newroot < 0) {
		err(1, "open(%s)", source);
	}

	if (fchdir(newroot) < 0) {
		err(1, "fchdir(newroot)");
	}

	if (syscall(__NR_pivot_root, ".", ".") < 0){
		err(1, "pivot_root(., .)");
	}

	if (fchdir(oldroot) < 0) {
		err(1, "fchdir(oldroot)");
	}

	if (mount("", ".", "", MS_SLAVE | MS_REC, NULL) < 0) {
		err(1, "mount(., MS_SLAVE | MS_REC)");
	}

	if (umount2(".", MNT_DETACH) < 0) {
		err(1, "umount2(., MNT_DETACH)");
	}

	if (fchdir(newroot) < 0) {
		err(1, "fchdir(newroot)");
	}

	close(newroot);
	close(oldroot);
}

/*
 * Make the source directory our root so symlinks cannot escape and no other
 * files are accessible.
 */
void setup_mount_namespace(const char *source)
{
	if (unshare(CLONE_NEWNS) != 0) {
		err(1, "unshare(CLONE_NEWNS)");
	}

	setup_remount_slave();

	if (mount(source, source, NULL, MS_BIND, NULL) < 0) {
		err(1, "mount(%s, %s, MS_BIND)", source, source);
	}

	setup_pivot_root(source);
}

