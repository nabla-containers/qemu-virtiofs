/*
  FUSE: Filesystem in Userspace
  Copyright (C) 2001-2007  Miklos Szeredi <miklos@szeredi.hu>

  This program can be distributed under the terms of the GNU GPLv2.
  See the file COPYING.
*/

/** @file
 *
 * This FUSE daemon mirrors the existing file system hierarchy of the system,
 * starting at the provided source directory (-o source). It is read-only and
 * does not implement update operations on files, directories, attributes, nor
 * anything. The directory structure is captured in memory before the VM starts
 * as a memory file system. The reading of file content is implemented with the
 * help of setupmapping operations for the desired regions of the file (the
 * client is in charge of knowing what and where to map files).
 *
 * ## Source code ##
 * \include memfs_ll.c
 */

#ifdef FUSE_NOVIRTIO
#define FUSE_USE_VERSION 31
#else
#include "fuse_virtio.h"
#endif

#include "fuse_lowlevel.h"
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <stddef.h>
#include <stdbool.h>
#include <string.h>
#include <limits.h>
#include <dirent.h>
#include <assert.h>
#include <errno.h>
#include <err.h>
#include <inttypes.h>
#include <pthread.h>
#include <sys/syscall.h>
#include <sys/file.h>
#include <sys/xattr.h>
#include <sys/mount.h>
#include <sys/resource.h>
#include <sys/mman.h>

#include <gmodule.h>
#include "seccomp.h"
#include "utils.h"

#define BLOCKSIZE 4096

#define O_WRITE(flags) ((flags) & (O_RDWR | O_WRONLY))
#define O_READ(flags)  (((flags) & (O_RDWR | O_RDONLY)) | !O_WRITE(flags))

#define U_ATIME (1 << 0)
#define U_CTIME (1 << 1)
#define U_MTIME (1 << 2)

/* Assume we are always squashing uids */
#define FUSE_UID 0
#define FUSE_GID 0

#define RNDUP(n, d) (((n) + (d) - 1) / (d))

/*
 * The memory filesystem is stored as a tree of lo_inode structs. A lo_inode
 * can be a regular node (file) or a directory. A directory is a list of
 * (name, lo_inode) tuples.
 *
 * This version uses a single linked list for the directory entries. This leads
 * to having O(N) time complexity for lookups (not great for directories with
 * lot of entries). The reason is that having a single list keeps the memory
 * overhead low (as compared to a hash table), and makes the implementation of
 * readdir very simple as the links can be used as the readdir offsets. A
 * better option would be to use a balanced tree and implement some type of
 * iterator (for readdir), or have both a linked list _and_ a tree per
 * directory.
 *
 * Locking. This is a memory filesystem that is constructed before the first
 * connection, so there is no need to serialize accesses. All accesses
 * performed concurrenctly are read-only, and only made after the memfs tree
 * was constructed.
 */

struct lo_inode {
	union {
		struct {
			int host_fd;
		} reg;
		struct {
			const char *path;
		} symlink;
		struct {
			/* List of memfs_dirent structs */
			GSList *list;
		} dir;
	} u;
	struct stat vstat;
};

struct memfs_dirent {
	const char *name;
	struct lo_inode *node;
};

struct filehandle {
	struct lo_inode *node;
	int o_flags;
};

struct lo_map_elem {
	union {
		struct lo_inode *inode;
		ssize_t freelist;
	};
	bool in_use;
};

/* Maps FUSE fh or ino values to internal objects */
struct lo_map {
	struct lo_map_elem *elems;
	size_t nelems;
	ssize_t freelist;
};

struct lo_key {
	ino_t ino;
	dev_t dev;
};

enum {
	CACHE_NEVER,
	CACHE_AUTO,
	CACHE_ALWAYS,
};

struct lo_data {
	int debug;
	int xattr;
	const char *source;
	double timeout;
	int cache;
	int timeout_set;
	struct lo_inode root;
	struct lo_map ino_map;
};

static const struct fuse_opt lo_opts[] = {
	{ "source=%s",
	  offsetof(struct lo_data, source), 0 },
	{ "xattr",
	  offsetof(struct lo_data, xattr), 1 },
	{ "no_xattr",
	  offsetof(struct lo_data, xattr), 0 },
	{ "timeout=%lf",
	  offsetof(struct lo_data, timeout), 0 },
	{ "timeout=",
	  offsetof(struct lo_data, timeout_set), 1 },
	{ "cache=never",
	  offsetof(struct lo_data, cache), CACHE_NEVER },
	{ "cache=auto",
	  offsetof(struct lo_data, cache), CACHE_AUTO },
	{ "cache=always",
	  offsetof(struct lo_data, cache), CACHE_ALWAYS },

	FUSE_OPT_END
};

static struct lo_data *lo_data(fuse_req_t req)
{
	return (struct lo_data *) fuse_req_userdata(req);
}

static bool lo_debug(fuse_req_t req)
{
	return lo_data(req)->debug != 0;
}

static int lo_map_grow(struct lo_map *map, size_t new_nelems)
{
	struct lo_map_elem *new_elems;
	size_t i;

	if (new_nelems <= map->nelems)
		return 1;

	new_elems = realloc(map->elems, sizeof(map->elems[0]) * new_nelems);
	if (new_elems == NULL)
		return 0;

	for (i = map->nelems; i < new_nelems; i++) {
		new_elems[i].freelist = i + 1;
		new_elems[i].in_use = false;
	}
	new_elems[new_nelems - 1].freelist = -1;

	map->elems = new_elems;
	map->freelist = map->nelems;
	map->nelems = new_nelems;
	return 1;
}

static struct lo_map_elem *lo_map_alloc_elem(struct lo_map *map)
{
	struct lo_map_elem *elem;

	if (map->freelist == -1 && !lo_map_grow(map, map->nelems + 256))
		return NULL;

	elem = &map->elems[map->freelist];
	map->freelist = elem->freelist;

	elem->in_use = true;

	return elem;
}

static struct lo_map_elem *lo_map_reserve(struct lo_map *map, size_t key)
{
	ssize_t *prev;

	if (!lo_map_grow(map, key + 1))
		return NULL;

	for (prev = &map->freelist;
	     *prev != -1;
	     prev = &map->elems[*prev].freelist) {
		if (*prev == key) {
			struct lo_map_elem *elem = &map->elems[key];

			*prev = elem->freelist;
			elem->in_use = true;
			return elem;
		}
	}
	return NULL;
}

static void lo_map_init(struct lo_map *map)
{
	map->elems = NULL;
	map->nelems = 0;
	map->freelist = -1;
}

static struct lo_map_elem *lo_map_get(struct lo_map *map, size_t key)
{
	if (key >= map->nelems)
		return NULL;
	if (!map->elems[key].in_use)
		return NULL;
	return &map->elems[key];
}

static ssize_t lo_add_inode_mapping(struct lo_map *map, struct lo_inode *inode)
{
	struct lo_map_elem *elem;

	elem = lo_map_alloc_elem(map);
	if (elem == NULL)
		return -1;

	elem->inode = inode;
	return elem - map->elems;
}

static struct lo_inode *lo_inode(fuse_req_t req, fuse_ino_t ino)
{
	struct lo_data *lo = lo_data(req);
	struct lo_map_elem *elem;

	elem = lo_map_get(&lo->ino_map, ino);

	if (elem == NULL) {
		return NULL;
	}

	return elem->inode;
}

/* Copied from https://github.com/tniessen/memfs-fuse */
static void update_times(struct lo_inode *node, int which)
{
	time_t now = time(0);
	if (which & U_ATIME) node->vstat.st_atime = now;
	if (which & U_CTIME) node->vstat.st_ctime = now;
	if (which & U_MTIME) node->vstat.st_mtime = now;
}

static void init_stat(struct lo_inode *node, struct stat *sb, fuse_ino_t inum)
{
	struct stat *stbuf = &node->vstat;

	memset(stbuf, 0, sizeof(struct stat));
	stbuf->st_mode  = sb->st_mode;
	stbuf->st_nlink = 0;
	stbuf->st_size = 0;
	stbuf->st_blocks = 0;
	stbuf->st_ino = inum;
	stbuf->st_uid = FUSE_UID;
	stbuf->st_gid = FUSE_GID;
	/* mainly used for chr and blk devices */
	stbuf->st_rdev = sb->st_rdev;
	/* not absolutely sure about the consequence of this */
	stbuf->st_dev = sb->st_dev;

	update_times(node, U_ATIME | U_MTIME | U_CTIME);
}

static gint memfs_dirent_cmp(gconstpointer a, gconstpointer b)
{
	struct memfs_dirent *dir = (struct memfs_dirent *)a;
	assert(dir);
	char *needle = (char *)b;
	return strcmp(dir->name, needle);
}

static void memfs_dir_add(struct lo_inode *parent, const char *name,
                          struct lo_inode *inode)
{
	struct memfs_dirent *dir = calloc(1, sizeof(struct memfs_dirent));
	if (dir == NULL) {
		err(1, "failed to calloc: %s", name);
	}

	dir->name = strndup(name, PATH_MAX);
	dir->node = inode;
	parent->u.dir.list = g_slist_prepend(parent->u.dir.list, dir);

	/* From parent directory to inode. */
	inode->vstat.st_nlink++;
}

static struct lo_inode *memfs_dir_find(struct lo_inode *parent, const char *name)
{
	GSList *link;
	struct memfs_dirent *d;

	link = g_slist_find_custom(parent->u.dir.list, name, memfs_dirent_cmp);
	if (link == NULL) {
		return NULL;
	}

	d = (struct memfs_dirent *)link->data;
	/* There shouldn't be a link without data. */
	assert(d);
	return d->node;
}

/* Allocates an inode, adds it to the parent dir and to the inode mapping. */
static struct lo_inode *memfs_mknod(struct lo_data *lo, struct lo_inode *parent,
                                    const char *name, struct stat *sb)
{
	struct lo_inode *inode;
	fuse_ino_t inum;

	inode = calloc(1, sizeof(struct lo_inode));
	if (inode == NULL) {
		err(1, "failed to calloc: %s", name);
	}

	inum = lo_add_inode_mapping(&lo->ino_map, inode);
	if (inum == -1) {
		errx(1, "lo_add_inode_mapping: %s", name);
	}

	init_stat(inode, sb, inum);

	memfs_dir_add(parent, name, inode);

	return inode;
}

static struct lo_inode *memfs_mkdir(struct lo_data *lo, struct lo_inode *parent,
                                    const char *name, struct stat *sb)
{
	struct lo_inode *inode;

	assert(S_ISDIR(sb->st_mode));

	inode = memfs_mknod(lo, parent, name, sb);
	if (inode == NULL) {
		return NULL;
	}

	inode->u.dir.list = NULL;

	memfs_dir_add(inode, ".", inode);
	memfs_dir_add(inode, "..", inode);

	/* For the dotdot entry (..): inode to parent */
	parent->vstat.st_nlink++;

	return inode;
}

/* Creates a regular file in memfs. */
static struct lo_inode *memfs_mkfile(struct lo_data *lo, struct lo_inode *parent,
                                     const char *name, struct stat *sb)
{
	struct lo_inode *inode;
	int fd;

	assert(S_ISREG(sb->st_mode));

	inode = memfs_mknod(lo, parent, name, sb);
	if (inode == NULL) {
		return NULL;
	}

	fd = openat(AT_FDCWD, name, O_RDWR);
	if (fd == -1) {
		err(1, "failed to openat: %s", name);
	}

	inode->u.reg.host_fd = fd;
	inode->vstat.st_size = sb->st_size;
	inode->vstat.st_blocks = RNDUP(sb->st_size, BLOCKSIZE);

	return inode;
}

/* Creates a symlink in memfs. */
static struct lo_inode *memfs_mklink(struct lo_data *lo, struct lo_inode *parent,
                                     const char *name, struct stat *sb)
{
	struct lo_inode *inode;
	char *lnk;
	int res;

	assert(S_ISLNK(sb->st_mode));

	inode = memfs_mknod(lo, parent, name, sb);
	if (inode == NULL) {
		return NULL;
	}

	lnk = calloc(1, sb->st_size + 1);
	if (lnk == NULL)
		err(1, "failed to calloc: %s", name);

	res = readlink(name, lnk, sb->st_size + 1);
	if (res == -1)
		err(1, "failed to readlink: %s", name);

	if (res > sb->st_size)
		errx(1, "symlink increased in size between fstat and readlink");

	/* readlink doesn't add it: */
	lnk[res] = '\0';

	/* Move ownership of lnk to the inode. */
	inode->u.symlink.path = lnk;
	inode->vstat.st_size = sb->st_size;
	inode->vstat.st_blocks = RNDUP(sb->st_size, BLOCKSIZE);

	return inode;
}

static bool is_hardlink(struct stat *sb)
{
	return sb->st_nlink > 1 && !S_ISDIR(sb->st_mode) && !S_ISLNK(sb->st_mode);
}

/* Populates the memfs recursively starting at the current directory. */
static void memfs_from_dir(struct lo_data *lo, struct lo_inode *parent,
                           GHashTable *ht_ino)
{
	struct dirent *dirent;
	DIR *d = opendir(".");

	if (d == NULL) {
		return;
	}

	while ((dirent = readdir(d)) != NULL) {
		struct lo_inode *node = NULL;
		struct stat sb;
		const char *name = dirent->d_name;
		int res;

		res = fstatat(AT_FDCWD, name, &sb, AT_SYMLINK_NOFOLLOW);
		if (res == -1) {
			err(1, "failed to fstatat: %s", name);
		}

		if (is_hardlink(&sb)) {
			node = g_hash_table_lookup(ht_ino,
						GINT_TO_POINTER(sb.st_ino));
			if (node) {
				memfs_dir_add(parent, name, node);
				continue;
			}
		}

		switch (sb.st_mode & S_IFMT) {

			case S_IFREG:
				node = memfs_mkfile(lo, parent, name, &sb);
				if (node == NULL)
					errx(1, "failed to mkfile: %s", name);
				break;

			case S_IFDIR:
				if (strcmp(name, ".") == 0)
					break;
				if (strcmp(name, "..") == 0)
					break;

				node = memfs_mkdir(lo, parent, name, &sb);
				if (node == NULL)
					errx(1, "failed to mkdir: %s", name);

				/* Recursive call is here */
				if (chdir(name) < 0)
					err(1, "failed to chdir: %s", name);
				memfs_from_dir(lo, node, ht_ino);
				if (chdir("..") < 0)
					err(1, "failed to chdir: ..");
				break;

			case S_IFLNK:
				node = memfs_mklink(lo, parent, name, &sb);
				if (node == NULL)
					errx(1, "failed to mklink: %s", name);
				break;

			case S_IFBLK:
			case S_IFCHR:
			case S_IFIFO:
			case S_IFSOCK:
				node = memfs_mknod(lo, parent, name, &sb);
				if (node == NULL)
					errx(1, "failed to mknod: %s", name);
				break;

			default:
				warnx("ignoring file: %s", name);
				break;
		}

		if (is_hardlink(&sb) && node) {
			assert(node);
			g_hash_table_insert(ht_ino, GINT_TO_POINTER(sb.st_ino), node);
		}
	}

	closedir(d);
}

static void lo_getattr(fuse_req_t req, fuse_ino_t ino,
                       struct fuse_file_info *fi)
{
	struct stat buf;
	struct stat *stbuf = &buf;
	struct lo_data *lo = lo_data(req);
	struct lo_inode *node = lo_inode(req, ino);

	if (node == NULL)
		return (void) fuse_reply_err(req, ENOENT);

	(void) fi;

	stbuf->st_mode    = node->vstat.st_mode;
	stbuf->st_nlink   = node->vstat.st_nlink;
	stbuf->st_size    = node->vstat.st_size;
	stbuf->st_blocks  = node->vstat.st_blocks;
	stbuf->st_blksize = BLOCKSIZE;
	stbuf->st_uid     = node->vstat.st_uid;
	stbuf->st_gid     = node->vstat.st_gid;
	stbuf->st_mtime   = node->vstat.st_mtime;
	stbuf->st_atime   = node->vstat.st_atime;
	stbuf->st_ctime   = node->vstat.st_ctime;
	stbuf->st_ino     = node->vstat.st_ino;
	stbuf->st_dev     = node->vstat.st_dev;
	stbuf->st_rdev    = node->vstat.st_rdev;

	fuse_reply_attr(req, stbuf, lo->timeout);
}

static int lo_do_lookup(fuse_req_t req, fuse_ino_t parent, const char *name,
                        struct fuse_entry_param *e)
{
	struct lo_data *lo = lo_data(req);
	struct lo_inode *inode;
	struct lo_inode *dir_node = lo_inode(req, parent);

	if (dir_node == NULL)
		return ENOTDIR;

	if (!S_ISDIR(dir_node->vstat.st_mode))
		return ENOTDIR;

	inode = memfs_dir_find(dir_node, name);
	if (inode) {
		memset(e, 0, sizeof(*e));

		e->attr_timeout    = lo->timeout;
		e->entry_timeout   = lo->timeout;

		e->attr.st_mode    = inode->vstat.st_mode;
		e->attr.st_nlink   = inode->vstat.st_nlink;
		e->attr.st_size    = inode->vstat.st_size;
		e->attr.st_blocks  = inode->vstat.st_blocks;
		e->attr.st_blksize = BLOCKSIZE;
		e->attr.st_uid     = inode->vstat.st_uid;
		e->attr.st_gid     = inode->vstat.st_gid;
		e->attr.st_mtime   = inode->vstat.st_mtime;
		e->attr.st_atime   = inode->vstat.st_atime;
		e->attr.st_ctime   = inode->vstat.st_ctime;
		e->attr.st_ino     = inode->vstat.st_ino;
		e->attr.st_dev     = inode->vstat.st_dev;
		e->attr.st_rdev    = inode->vstat.st_rdev;

		e->ino             = inode->vstat.st_ino;

		return 0;
	} else {
		return ENOENT;
	}
}

static void lo_lookup(fuse_req_t req, fuse_ino_t parent, const char *name)
{
	struct fuse_entry_param e;
	int err;

	if (lo_debug(req))
		fprintf(stderr, "lo_lookup(parent=%" PRIu64 ", name=%s)\n",
			parent, name);

	err = lo_do_lookup(req, parent, name, &e);
	if (err)
		fuse_reply_err(req, err);
	else
		fuse_reply_entry(req, &e);
}

static void lo_readlink(fuse_req_t req, fuse_ino_t ino)
{
	struct lo_inode *inode = lo_inode(req, ino);

	if (inode == NULL)
		return (void) fuse_reply_err(req, ENOENT);

	if (!S_ISLNK(inode->vstat.st_mode)) {
		return (void) fuse_reply_err(req, EINVAL);
	}

	fuse_reply_readlink(req, inode->u.symlink.path);
}

struct lo_dirp {
	GSList *link;
};

static struct lo_dirp *lo_dirp(struct fuse_file_info *fi)
{
	return (struct lo_dirp *) (uintptr_t) fi->fh;
}

static void lo_opendir(fuse_req_t req, fuse_ino_t ino, struct fuse_file_info *fi)
{
	int error = ENOMEM;
	struct lo_data *lo = lo_data(req);
	struct lo_dirp *d;
	struct lo_inode *inode = lo_inode(req, ino);

	if (inode == NULL)
		return (void) fuse_reply_err(req, ENOENT);

	if (!S_ISDIR(inode->vstat.st_mode))
		return (void) fuse_reply_err(req, ENOTDIR);

	d = calloc(1, sizeof(struct lo_dirp));
	if (d == NULL) {
		goto out_err;
	}

	d->link = inode->u.dir.list;

	fi->fh = (uintptr_t) d;
	if (lo->cache == CACHE_ALWAYS)
		fi->keep_cache = 1;
	fuse_reply_open(req, fi);
	return;

out_err:
	if (d)
		free(d);
	fuse_reply_err(req, error);
}

/*
 * This function is called by the client multiple times for a single directory:
 * each time at an increasing offset. Given that we are storing the directory
 * entries as a linked list, we use the offset to store pointers to the linked
 * list instead. The only complication is that the first call will receive an
 * offset of 0 (the client wants to read the directory from the beginning).
 * When that case is recognized (offset=0), the initial link used is the one
 * given by d->link.
 */
static void lo_do_readdir(fuse_req_t req, fuse_ino_t ino, size_t size,
                          off_t offset, struct fuse_file_info *fi, int plus)
{
	struct lo_dirp *d = lo_dirp(fi);
	char *buf;
	char *p;
	size_t rem = size;
	int err;
	GSList *link;

	buf = calloc(1, size);
	if (buf == NULL) {
		err = ENOMEM;
		goto error;
	}
	p = buf;

	if (offset == 0) {
		/* This is the case explained in the description of the
		 * function above.  The client wants to read from the beginning
		 * (offset=0) but we are reusing the offset as the address of
		 * links. So, we just start from the link provided in the
		 * fuse_file_info which was set at lo_opendir().
		 */
		link = d->link;
	} else {
		/* Another complication. Sometimes, the client wants us to
		 * return the entries starting at a previous offset (i.e. a
		 * previous link in the list). In that case, we honor the
		 * request by setting link to the requested offset (making this
		 * crazy cast).
		 */
		if (offset != (uintptr_t)d->link)
			d->link = (GSList *)offset;
		link = d->link;
	}

	while (link != NULL) {
		/* There shouldn't be a link without valid data. */
		assert(link->data != NULL);
		struct memfs_dirent *entry = (struct memfs_dirent *)link->data;
		size_t entsize;
		struct lo_inode *child = entry->node;
		const char *name = entry->name;
		off_t nextoff = (off_t) link->next;

		if (link->next == NULL) {
			/* No more directory entries. */
			break;
		}

		struct fuse_entry_param e = (struct fuse_entry_param) {
			.attr.st_ino = child->vstat.st_ino,
			.attr.st_mode = child->vstat.st_mode,
		};

		if (plus) {
			/* The reference passthrough_ll implementation has a
			 * lookup here. It's needed to increase the reference
			 * count of the inode, so we know when to delete it. In
			 * this case, the filesystem is readonly and no node is
			 * ever deleted.
			 * */
			entsize = fuse_add_direntry_plus(NULL, p, rem, name,
					&e, nextoff);
		} else {
			entsize = fuse_add_direntry(NULL, p, rem, name,
					&e.attr, nextoff);
		}
		if (entsize > rem) {
			break;
		}

		p += entsize;
		rem -= entsize;
		link = link->next;

		nextoff = (uintptr_t)link;
		d->link = link;
	}

	err = 0;
error:
	if (err)
		fuse_reply_err(req, err);
	else
		fuse_reply_buf(req, buf, size - rem);
	free(buf);
}

static void lo_readdir(fuse_req_t req, fuse_ino_t ino, size_t size,
                       off_t offset, struct fuse_file_info *fi)
{
	lo_do_readdir(req, ino, size, offset, fi, 0);
}

static void lo_readdirplus(fuse_req_t req, fuse_ino_t ino, size_t size,
                           off_t offset, struct fuse_file_info *fi)
{
	lo_do_readdir(req, ino, size, offset, fi, 1);
}

static void lo_releasedir(fuse_req_t req, fuse_ino_t ino, struct fuse_file_info *fi)
{
	struct lo_dirp *d = lo_dirp(fi);
	(void) ino;
	free(d);
	fuse_reply_err(req, 0);
}

static void lo_open(fuse_req_t req, fuse_ino_t ino, struct fuse_file_info *fi)
{
	struct lo_data *lo = lo_data(req);
	struct lo_inode *node = lo_inode(req, ino);

	if (lo_debug(req))
		fprintf(stderr, "lo_open(ino=%" PRIu64 ", flags=%d)\n",
			ino, fi->flags);

	if (node == NULL)
		return (void) fuse_reply_err(req, ENOENT);

	if (!S_ISREG(node->vstat.st_mode)) {
		if (S_ISDIR(node->vstat.st_mode))
			return (void) fuse_reply_err(req, EISDIR);
		return (void) fuse_reply_err(req, EINVAL);
	}

	if (O_WRITE(fi->flags)) {
		/* This is a readonly filesystem */
		return (void) fuse_reply_err(req, EROFS);
	}

	/* This (node->vstat.st_*time) is the only piece of data that gets
	 * updated in this readonly filesystem. Is it worth protecting this
	 * with a lock?
	 */
	update_times(node, U_ATIME);

	/* The "file handle" is a pointer to a struct we use to keep track of
	 * the inode and the flags passed to open().
	 */
	struct filehandle *fh = malloc(sizeof(struct filehandle));
	if (fh == NULL)
		return (void) fuse_reply_err(req, ENOMEM);

	fh->node = node;
	fh->o_flags = fi->flags;
	fi->fh = (uint64_t) fh;

	if (lo->cache == CACHE_NEVER)
		fi->direct_io = 1;
	else if (lo->cache == CACHE_ALWAYS)
		fi->keep_cache = 1;
	fuse_reply_open(req, fi);
}

static void lo_release(fuse_req_t req, fuse_ino_t ino, struct fuse_file_info *fi)
{
	(void) ino;

	struct filehandle *fh = (struct filehandle *) fi->fh;

	free(fh);
	fuse_reply_err(req, 0);
}

static void lo_setupmapping(fuse_req_t req, fuse_ino_t ino, uint64_t foffset,
                            uint64_t len, uint64_t moffset, uint64_t flags,
                            struct fuse_file_info *fi)
{
	struct lo_inode *node = lo_inode(req, ino);
	int ret = 0, fd;
	VhostUserFSSlaveMsg msg = { 0 };
	uint64_t vhu_flags;

	if (node == NULL)
		return (void) fuse_reply_err(req, ENOENT);

	if (lo_debug(req))
		fprintf(stderr, "lo_setupmapping(moffset=0x%p foffset=0x%p fd=%d)\n",
				(void *)moffset, (void *)foffset, fd);

	if (!S_ISREG(node->vstat.st_mode)) {
		if (S_ISDIR(node->vstat.st_mode))
			return (void) fuse_reply_err(req, EISDIR);
		return (void) fuse_reply_err(req, EINVAL);
	}

	/* This is a readonly filesystem. */
	vhu_flags = VHOST_USER_FS_FLAG_MAP_R;

	msg.fd_offset[0] = foffset;
	msg.len[0] = len;
	msg.c_offset[0] = moffset;
	msg.flags[0] = vhu_flags;

	/* This was opened at startup time (while doing memfs_from_dir()) */
	fd = node->u.reg.host_fd;

	if (fuse_virtio_map(req, &msg, fd)) {
		fprintf(stderr, "%s: map over virtio failed (ino=%" PRId64 "fd=%d moffset=0x%" PRIx64 ")\n",
			__func__, ino, fi ? (int)fi->fh : fd, moffset);
		ret = EINVAL;
	}

	fuse_reply_err(req, ret);
}

static void lo_removemapping(fuse_req_t req, struct fuse_session *se,
                             fuse_ino_t ino, uint64_t moffset,
                             uint64_t len, struct fuse_file_info *fi)
{
	struct lo_inode *node = lo_inode(req, ino);
	VhostUserFSSlaveMsg msg = { 0 };
	int ret = 0;

	if (node == NULL)
		return (void) fuse_reply_err(req, ENOENT);

	if (lo_debug(req))
		fprintf(stderr, "lo_removemapping(offset=0x%p len=0x%p)\n",
				(void *)moffset, (void *)len);

	if (!S_ISREG(node->vstat.st_mode)) {
		if (S_ISDIR(node->vstat.st_mode))
			return (void) fuse_reply_err(req, EISDIR);
		return (void) fuse_reply_err(req, EINVAL);
	}

	msg.len[0] = len;
	msg.c_offset[0] = moffset;
	if (fuse_virtio_unmap(se, &msg)) {
		fprintf(stderr,
			"%s: unmap over virtio failed "
			"(offset=0x%lx, len=0x%lx)\n", __func__, moffset, len);
		ret = EINVAL;
	}

	fuse_reply_err(req, ret);
}

static void lo_destroy(void *userdata, struct fuse_session *se)
{
	if (fuse_lowlevel_is_virtio(se)) {
		VhostUserFSSlaveMsg msg = { 0 };

		msg.len[0] = ~(uint64_t)0; /* Special: means 'all' */
		msg.c_offset[0] = 0;
		if (fuse_virtio_unmap(se, &msg)) {
			fprintf(stderr, "%s: unmap during destroy failed\n", __func__);
		}
	}
}

static int setup_root(struct lo_data *lo, const char *source)
{
	struct lo_inode *root = &lo->root;
	GHashTable *ht_ino;
	struct stat sb;

	memset(&sb, 0, sizeof(struct stat));
	sb.st_mode = S_IFDIR | 0755;
	init_stat(root, &sb, FUSE_ROOT_ID);
	root->u.dir.list = NULL;
	memfs_dir_add(root, ".", root);

	if (chdir(source) < 0)
		err(1, "failed to chdir to %s", source);

	/* Use a map between host inode to memfs inode pointers in order to
	 * find hardlinks. */
	ht_ino = g_hash_table_new(g_direct_hash, g_direct_equal);

	memfs_from_dir(lo, root, ht_ino);

	g_hash_table_destroy(ht_ino);
	return 0;
}

static void lo_init(void *userdata,
		    struct fuse_conn_info *conn)
{
	if (conn->want & FUSE_CAP_FLOCK_LOCKS) {
		fprintf(stderr, "%s: can not activate flock locks\n", __func__);
		conn->want &= ~FUSE_CAP_FLOCK_LOCKS;
	}
}

static const struct fuse_lowlevel_ops lo_oper = {
	.init           = lo_init,
	.lookup         = lo_lookup,
	.getattr        = lo_getattr,
	.readlink       = lo_readlink,
	.opendir        = lo_opendir,
	.readdir        = lo_readdir,
	.readdirplus    = lo_readdirplus,
	.releasedir     = lo_releasedir,
	.open	        = lo_open,
	.release        = lo_release,
	.destroy        = lo_destroy,
	.setupmapping   = lo_setupmapping,
	.removemapping  = lo_removemapping,
};

int main(int argc, char *argv[])
{
	struct fuse_args args = FUSE_ARGS_INIT(argc, argv);
	struct fuse_session *se;
	struct fuse_cmdline_opts opts;
	struct lo_data lo = { .debug = 0 };
	struct lo_map_elem *root_elem;
	int ret = -1;

	/* Don't mask creation mode, kernel already did that */
	umask(0);

	setup_nofile_rlimit();

	lo.cache = CACHE_AUTO;

	lo_map_init(&lo.ino_map);
	lo_map_reserve(&lo.ino_map, 0)->in_use = false;
	root_elem = lo_map_reserve(&lo.ino_map, FUSE_ROOT_ID);
	root_elem->inode = &lo.root;

	if (fuse_parse_cmdline(&args, &opts) != 0)
		return 1;
	if (opts.show_help) {
		printf("usage: %s [options]\n\n", argv[0]);
		fuse_cmdline_help();
		printf("    -o source=PATH	     shared directory tree\n");
		fuse_lowlevel_help();
		ret = 0;
		goto err_out1;
	} else if (opts.show_version) {
		fuse_lowlevel_version();
		ret = 0;
		goto err_out1;
	}

#ifdef FUSE_NOVIRTIO
	if (opts.mountpoint == NULL) {
		printf("usage: %s [options] <mountpoint>\n", argv[0]);
		printf("       %s --help\n", argv[0]);
		ret = 1;
		goto err_out1;
	}
#endif

	if (fuse_opt_parse(&args, &lo, lo_opts, NULL)== -1)
		return 1;

	lo.debug = opts.debug;
	if (lo.source) {
		struct stat stat;
		int res;

		res = lstat(lo.source, &stat);
		if (res == -1) {
			err(1, "failed to stat source (\"%s\"): %m\n",
				 lo.source);
			exit(1);
		}
		if (!S_ISDIR(stat.st_mode)) {
			err(1, "source is not a directory\n");
			exit(1);
		}

	} else {
		lo.source = "/";
	}

	if (!lo.timeout_set) {
		switch (lo.cache) {
		case CACHE_NEVER:
			lo.timeout = 0.0;
			break;

		case CACHE_AUTO:
			lo.timeout = 1.0;
			break;

		case CACHE_ALWAYS:
			lo.timeout = 86400.0;
			break;
		}
	} else if (lo.timeout < 0) {
		err(1, "timeout is negative (%lf)\n",
			 lo.timeout);
		exit(1);
	}

	/* Do this before setting seccomp as setup_root traverses all of the
	 * directory tree at lo.source.
	 */
	ret = setup_root(&lo, lo.source);
	if (ret != 0)
		goto err_out1;

	se = fuse_session_new(&args, &lo_oper, sizeof(lo_oper), &lo);
	if (se == NULL)
	    goto err_out1;

	if (fuse_set_signal_handlers(se) != 0)
	    goto err_out2;

	if (fuse_session_mount(se) != 0)
	    goto err_out3;

	fuse_daemonize(opts.foreground);

	/*
	 * Lock down this process to prevent access to other processes or files
	 * outside source directory.  This reduces the impact of arbitrary code
	 * execution bugs.
	 */
	setup_mount_namespace(lo.source);
	setup_seccomp_memfsd();

	/* Block until ctrl+c or fusermount -u */
	ret = virtio_loop(se);

	fuse_session_unmount(se);
err_out3:
	fuse_remove_signal_handlers(se);
err_out2:
	fuse_session_destroy(se);
err_out1:
	fuse_opt_free_args(&args);

	/* XXX: close all files and free all used memory. */

	return ret ? 1 : 0;
}
