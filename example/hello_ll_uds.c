/*
  FUSE: Filesystem in Userspace
  Copyright (C) 2001-2007  Miklos Szeredi <miklos@szeredi.hu>
  Copyright (C) 2022  Tofik Sonono <tofik.sonono@intel.com>

  This program can be distributed under the terms of the GNU GPLv2.
  See the file COPYING.
*/

/** @file
 *
 * minimal example filesystem using low-level API and a custom io. This custom
 * io is implemented using UNIX domain sockets (of type SOCK_STREAM)
 *
 * Compile with:
 *
 *     gcc -Wall hello_ll_uds.c `pkg-config fuse3 --cflags --libs` -o hello_ll_uds
 *
 * ## Source code ##
 * \include hello_ll.c
 */

#define FUSE_USE_VERSION 34


#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include "libvduse.h"
#include "standard-headers/linux/virtio_fs.h"
#include "standard-headers/linux/virtio_ring.h"

#include <fuse_lowlevel.h>
#include <fuse_kernel.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <poll.h>
#include <threads.h>
#include <fcntl.h>
#include <unistd.h>
#include <assert.h>

static const char *hello_str = "Hello World!\n";
static const char *hello_name = "hello";

static struct fuse_session *ses[2];
static struct fuse_args args;

static thread_local VduseVirtqElement *cur_elem;

static int hello_stat(fuse_ino_t ino, struct stat *stbuf)
{
	stbuf->st_ino = ino;
	switch (ino) {
	case 1:
		stbuf->st_mode = S_IFDIR | 0755;
		stbuf->st_nlink = 2;
		break;

	case 2:
		stbuf->st_mode = S_IFREG | 0444;
		stbuf->st_nlink = 1;
		stbuf->st_size = strlen(hello_str);
		break;

	default:
		return -1;
	}
	return 0;
}

static void hello_ll_getattr(fuse_req_t req, fuse_ino_t ino,
			     struct fuse_file_info *fi)
{
	struct stat stbuf;

	(void) fi;

	memset(&stbuf, 0, sizeof(stbuf));
	if (hello_stat(ino, &stbuf) == -1)
		fuse_reply_err(req, ENOENT);
	else
		fuse_reply_attr(req, &stbuf, 1.0);
}

static void hello_ll_init(void *userdata, struct fuse_conn_info *conn)
{
	(void)userdata;

	/* Disable the receiving and processing of FUSE_INTERRUPT requests */
	conn->no_interrupt = 1;
}

static void hello_ll_lookup(fuse_req_t req, fuse_ino_t parent, const char *name)
{
	struct fuse_entry_param e;

	if (parent != 1 || strcmp(name, hello_name) != 0)
		fuse_reply_err(req, ENOENT);
	else {
		memset(&e, 0, sizeof(e));
		e.ino = 2;
		e.attr_timeout = 1.0;
		e.entry_timeout = 1.0;
		hello_stat(e.ino, &e.attr);

		fuse_reply_entry(req, &e);
	}
}

struct dirbuf {
	char *p;
	size_t size;
};

static void dirbuf_add(fuse_req_t req, struct dirbuf *b, const char *name,
		       fuse_ino_t ino)
{
	struct stat stbuf;
	size_t oldsize = b->size;
	b->size += fuse_add_direntry(req, NULL, 0, name, NULL, 0);
	b->p = (char *) realloc(b->p, b->size);
	memset(&stbuf, 0, sizeof(stbuf));
	stbuf.st_ino = ino;
	fuse_add_direntry(req, b->p + oldsize, b->size - oldsize, name, &stbuf,
			  b->size);
}

#define min(x, y) ((x) < (y) ? (x) : (y))

static int reply_buf_limited(fuse_req_t req, const char *buf, size_t bufsize,
			     off_t off, size_t maxsize)
{
	if (off < bufsize)
		return fuse_reply_buf(req, buf + off,
				      min(bufsize - off, maxsize));
	else
		return fuse_reply_buf(req, NULL, 0);
}

static void hello_ll_readdir(fuse_req_t req, fuse_ino_t ino, size_t size,
			     off_t off, struct fuse_file_info *fi)
{
	(void) fi;

	if (ino != 1)
		fuse_reply_err(req, ENOTDIR);
	else {
		struct dirbuf b;

		memset(&b, 0, sizeof(b));
		dirbuf_add(req, &b, ".", 1);
		dirbuf_add(req, &b, "..", 1);
		dirbuf_add(req, &b, hello_name, 2);
		reply_buf_limited(req, b.p, b.size, off, size);
		free(b.p);
	}
}

static void hello_ll_open(fuse_req_t req, fuse_ino_t ino,
			  struct fuse_file_info *fi)
{
	if (ino != 2)
		fuse_reply_err(req, EISDIR);
	else if ((fi->flags & O_ACCMODE) != O_RDONLY)
		fuse_reply_err(req, EACCES);
	else
		fuse_reply_open(req, fi);
}

static void hello_ll_read(fuse_req_t req, fuse_ino_t ino, size_t size,
			  off_t off, struct fuse_file_info *fi)
{
	(void) fi;

	assert(ino == 2);
	reply_buf_limited(req, hello_str, strlen(hello_str), off, size);
}

static const struct fuse_lowlevel_ops hello_ll_oper = {
	.init           = hello_ll_init,
	.lookup		= hello_ll_lookup,
	.getattr	= hello_ll_getattr,
	.readdir	= hello_ll_readdir,
	.open		= hello_ll_open,
	.read		= hello_ll_read,
};

static struct virtio_fs_config fs_config = {
		.tag = "a",
        .num_request_queues = 1,
};

static ssize_t stream_writev(int fd, struct iovec *iov, int count,
                             void *userdata) {
	(void)userdata;

	ssize_t written = 0;
	int cur = 0;
	for (;;) {
		written = writev(fd, iov+cur, count-cur);
		if (written < 0)
			return written;

		while (cur < count && written >= iov[cur].iov_len)
			written -= iov[cur++].iov_len;
		if (cur == count)
			break;

		iov[cur].iov_base = (char *)iov[cur].iov_base + written;
		iov[cur].iov_len -= written;
	}
	return written;
}


static int poll_one_forever(int fd) {
	static const int timeout_inf = -1;
	struct pollfd pollfd = {
		.fd = fd,
		.events = POLLIN | POLLPRI,
	};

	return poll(&pollfd, 1, timeout_inf);
}

static ssize_t iov_to_buf(const struct iovec *iov, int iov_count, void *buf, size_t buf_len) {
	ssize_t total_bytes_copied = 0;
	char *buf_ptr = (char *)buf;

	for (int i = 0; i < iov_count; i++) {
		size_t bytes_to_copy = iov[i].iov_len;
		if (total_bytes_copied + bytes_to_copy > buf_len) {
			return buf_len + 1;
		}

		memcpy(buf_ptr, iov[i].iov_base, bytes_to_copy);
		total_bytes_copied += bytes_to_copy;
		buf_ptr += bytes_to_copy;
	}

	return total_bytes_copied;
}

static ssize_t stream_read(int fd, void *buf, size_t buf_len, void *userdata) {
	VduseVirtq *vq = userdata;
	ssize_t s;
	(void)fd;

	// TODO Do we need an extra fd to exit thread?
	int r = poll_one_forever(vduse_queue_get_fd(vq));
	assert(r == 1);

	assert(!cur_elem);
	cur_elem = vduse_queue_pop(vq, sizeof(*cur_elem));
	assert(cur_elem);

	s = iov_to_buf(cur_elem->out_sg, cur_elem->out_num, buf, buf_len);
	assert(s > 0 && s <= buf_len); // return -1

	return s;
}

static ssize_t stream_splice_send(int fdin, off_t *offin, int fdout,
					    off_t *offout, size_t len,
                                  unsigned int flags, void *userdata) {
	(void)userdata;

	size_t count = 0;
	while (count < len) {
		int i = splice(fdin, offin, fdout, offout, len - count, flags);
		if (i < 1)
			return i;

		count += i;
	}
	return count;
}

static void vduse_dev_enable_queue(VduseDev *dev, VduseVirtq *vq)
{
    int idx = vduse_dev_get_queue(dev, 0) == vq ? 0 : 1;
	struct fuse_session *se;
	const struct fuse_custom_io io = {
		.writev = stream_writev,
		.read = stream_read,
		.splice_receive = NULL,
		.splice_send = stream_splice_send,
	};
	int cfd = vduse_queue_get_fd(vq);
	int r;

	se = fuse_session_new(&args, &hello_ll_oper,
					sizeof(hello_ll_oper), vq);
	assert(se);

	r = fuse_set_signal_handlers(se);
	assert(r == 0);

	r = fuse_session_custom_io(se, &io, cfd);
	assert(r == 0);

	r = fuse_session_loop(se);
	assert(r == 0);

	ses[idx] = se;
}

static void vduse_dev_disable_queue(VduseDev *dev, VduseVirtq *vq)
{
    int idx = vduse_dev_get_queue(dev, 0) == vq ? 0 : 1;

	fuse_remove_signal_handlers(ses[idx]);
	fuse_session_destroy(ses[idx]);
}

static const VduseOps vduse_ops = {
        /* Called when virtqueue can be processed */
        .enable_queue = vduse_dev_enable_queue,
        /* Called when virtqueue processing should be stopped */
        .disable_queue = vduse_dev_disable_queue,
};

static VduseDev *create_vdpa(void) {
	static const char *vduse_name = "fsd";
	size_t q_size = 1024;
	uint32_t device_id = VIRTIO_ID_FS;
	uint32_t vendor_id = /* #define PCI_VENDOR_ID_REDHAT */ 0x1b36;
	uint64_t features = 1ULL << VIRTIO_F_VERSION_1
			| 1ULL << VIRTIO_RING_F_INDIRECT_DESC
			/* | 1ULL << VIRTIO_RING_F_EVENT_IDX */
			| 1ULL << 33 /* VIRTIO_F_ACCESS_PLATFORM */;
	uint16_t num_queues = 2;
	uint32_t config_size = sizeof(fs_config);
	static VduseDev *vduse_dev;
	char *config = (void *)&fs_config;
	void *priv = NULL;
	int r;

	vduse_dev = vduse_dev_create(vduse_name, device_id, vendor_id,
	                             features, num_queues, config_size, config,
	                             &vduse_ops, priv);
	assert(vduse_dev);

	// TODO: make this configurable.
	r = vduse_set_reconnect_log_file(vduse_dev, "/tmp/vduse_reconnect.log");

	for (int i = 0; i < num_queues; ++i) {
		r = vduse_dev_setup_queue(vduse_dev, i, q_size);
		assert(r == 0);
	}

	return vduse_dev;
}

static void fuse_cmdline_help_uds(void)
{
	printf("    -h   --help            print help\n"
	       "    -V   --version         print version\n"
	       "    -d   -o debug          enable debug output (implies -f)\n");
}

int main(int argc, char *argv[])
{
	args = (typeof(args))FUSE_ARGS_INIT(argc, argv);
	struct fuse_cmdline_opts opts;
		VduseDev *vdev;
	int ret = -1;

	if (fuse_parse_cmdline(&args, &opts) != 0)
		return 1;
	if (opts.show_help) {
		printf("usage: %s [options]\n\n", argv[0]);
		fuse_cmdline_help_uds();
		fuse_lowlevel_help();
		ret = 0;
		goto err;
	} else if (opts.show_version) {
		printf("FUSE library version %s\n", fuse_pkgversion());
		fuse_lowlevel_version();
		ret = 0;
		goto err;
	}

	vdev = create_vdpa();
	if (!vdev)
		goto err;


	// Wait until vqs are initialized
	while (1) {
		ret = poll_one_forever(vduse_dev_get_fd(vdev));
		assert(ret > 0);

		ret = vduse_dev_handler(vdev);
		assert(ret == 0);
	}

	ret = vduse_dev_destroy(vdev);
	if (ret) {
		fprintf(stderr, "Error destroying vduse: %d(%s)", -ret, strerror(-ret));
	}

err:
	free(opts.mountpoint);
	fuse_opt_free_args(&args);

	return ret ? 1 : 0;
}
