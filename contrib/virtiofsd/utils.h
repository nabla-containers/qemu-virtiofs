/*
  FUSE: Filesystem in Userspace
  Copyright (C) 2001-2007  Miklos Szeredi <miklos@szeredi.hu>

  This program can be distributed under the terms of the GNU GPLv2.
  See the file COPYING.
*/

#ifndef UTILS_H
#define UTILS_H

/* Raise the maximum number of open file descriptors to the system limit */
void setup_nofile_rlimit(void);

/*
 * Make the source directory our root so symlinks cannot escape and no other
 * files are accessible.
 */
void setup_mount_namespace(const char *source);

#endif /* UTILS_H */
