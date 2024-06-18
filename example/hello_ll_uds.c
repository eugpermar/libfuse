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
#include <standard-headers/linux/vdpa.h>

#include <netlink/socket.h>
#include <netlink/genl/genl.h>
#include <netlink/genl/ctrl.h>

#include <fuse_lowlevel.h>
#include <fuse_kernel.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <poll.h>
#include <threads.h>
#include <fcntl.h>
#include <unistd.h>
#include <assert.h>
#include <sys/mount.h>

static const char hello_str[] = "qM8G7h2FQz4WXpdVeL6g0uYvMRb1NtnO2cD5xP3KZjAa9sIbvRf7LUj8yMT0WoXhBnDwUp9rLFxgzKvNaWi8mJkPSO6Yt4ZE5X13NC2HqbDcfGLJxZsUzHa7pkYrOv9MwP0V9jt5UnM0lF4Jr8x6yZn3PZUBYqFHzKJ2LD8m9AhNBj2W1R5G60TxCgVy3XNa0kT7lm9EvDhP4J8YWg5qzr6QLXn7M3oVi2QX5zYvRJ1L2Ka7Hc9oMbDp5G8tUn6PwCf3XqN0Ve4YXZ1xLz3j7P9FrV2K6m1Ah8QNiJ5TW0oMbD1CzQ3GRf7Xg2vW8Z5L4a9NnYpF6Lh7R8wJc2U3Mi5T0tVqK4OxG6Ym1XgP9Ln7WJ5kY3R8z1QdL4a0eF2bMvJ9TX7Uz3P6WiY8m0HlN2Lg5YqG4rF7oPxD8c1F6aV4Zy0pNi3WhL9T7X5gR1K6mP2cQ3Ue8VoN7Y4z7LpFn6X0Mg5YqJ1v3X8rZh9UoN2kD5W1V7yT3aL6F0m9Q4Pg8eYc5zX2oNi1Wr6K7M4U8n3P5L0VJ9Yq7hR2G6c1TxZ4F3bJ5N8M0uL2oKv1D9W6iR7zF5G4T3pY8Xj2a0mN1L7P9v6M3Q5nK8hT4F2iY7XW1oZ6eR3G9cL5U0tQ7D8P4bM1N3kF2xR9W7V6Y5Uo4G3J0pZ8a2iL1mK9T6X7N5cV4F3hY8J0R2L1Q9uN7M6kX5V3iT4oY7Z2rG8F1cL5W0P9a6N4D3eQ1mJ7T2X9L5V6G8K4oN3R1Y7cW0F5J2P9h6M4X3D8a1T7K5V9n2Y6L3iF0R8W4J7X2G5mN6Q3L1V0cT9Y8M5oK4F7N3P1J6X2i9R8G5D7Y4L0W3Q2F9m8T6V1oK7N5G3P4J0X9L1cQ8Y2i6T7D5M3V0F4R9N1K8W2G7L3T5oX6Y4J1P2D9M7Q8F0cK5N3R6V2G9T4J7iL1W8Y3X5oN0Q2F4D7T1M9R6P8V3K5J2X4iG0Y7L1T9D8N6F3W4V2R7Q1X5G9P6J0L3oT8Y7D4W2M5V1N3R9Q6F8X7iJ4L2K5G0T9Y3D8W1N6P5M4R2X7F3V9Q0oJ6T5L1Y7i2N4G8K3P9F6W0R7Q1X3D4V5J9L2oT6M8Y0K5P7N4F3X1J9W2i6L7T8D0R5Y4G3V7K2M9P6F0N1X3Q4J5oT8L7W9D2Y6i1G4R3V7N5Q0X9P6J8T2D1L7M4Y5K3F6W0R9G2Q7N1X8P4T6J5L0D2Y3i7K9V8W6F1X4Q2R3M9P5T7N0L8J4Y6o1G2V3D5X9W7T4K6N8L3Y0P2J5M7D1i6Q9G8R4X2F3N7T5V1oL4K9J6D3W7X8Q2G5R1Y0M6i9N4P2F3L7T8V6J5K1o2W4Q7Y9D3M8R5X6P1F4G0L7T2J9i3N6V5X8K4D1W7Y2Q9R3P0F6L5M4T8oJ1G7N2X6D3V5Q9K0Y4W8R1i2M7J6T4P3L9G1X8V5Q2N4K3W7F6R0oY5D1T8J4L6V7X3Q9F2i5M0R1P8Y7D6N4T9J3W5K2X1o8Q7F6G4L9R2M0P3D5T7X1V8W4J6Y2N9K5Q0i3L7R1G4T8N2M6V3J5X9K7D1W4P6F2Q8Y5L0o9M3T7R1X4G2J6N5D8W3K9Y0F7i4Q2P8L5V6N1J3M9K4T7R2D8X5W0o6F1G7Q3L9V2P4N6D5i3T8X1K7W9Y0R2M6J5Q8L4P3N7D9F6T2X1V5K0o4G7Y3L9J6W8M2Q5R1T3X7D6N4J9K5F8P1G2L0o3M6Q7R5Y4T9J8D2V1N3X5K7W6P0L4F9Q2i1Y3G8M6J7T9D2W4X5K1o3Q8N7L4V2G6P9M1D0R3J7Y4qM8G7h2FQz4WXpdVeL6g0uYvMRb1NtnO2cD5xP3KZjAa9sIbvRf7LUj8yMT0WoXhBnDwUp9rLFxgzKvNaWi8mJkPSO6Yt4ZE5X13NC2HqbDcfGLJxZsUzHa7pkYrOv9MwP0V9jt5UnM0lF4Jr8x6yZn3PZUBYqFHzKJ2LD8m9AhNBj2W1R5G60TxCgVy3XNa0kT7lm9EvDhP4J8YWg5qzr6QLXn7M3oVi2QX5zYvRJ1L2Ka7Hc9oMbDp5G8tUn6PwCf3XqN0Ve4YXZ1xLz3j7P9FrV2K6m1Ah8QNiJ5TW0oMbD1CzQ3GRf7Xg2vW8Z5L4a9NnYpF6Lh7R8wJc2U3Mi5T0tVqK4OxG6Ym1XgP9Ln7WJ5kY3R8z1QdL4a0eF2bMvJ9TX7Uz3P6WiY8m0HlN2Lg5YqG4rF7oPxD8c1F6aV4Zy0pNi3WhL9T7X5gR1K6mP2cQ3Ue8VoN7Y4z7LpFn6X0Mg5YqJ1v3X8rZh9UoN2kD5W1V7yT3aL6F0m9Q4Pg8eYc5zX2oNi1Wr6K7M4U8n3P5L0VJ9Yq7hR2G6c1TxZ4F3bJ5N8M0uL2oKv1D9W6iR7zF5G4T3pY8Xj2a0mN1L7P9v6M3Q5nK8hT4F2iY7XW1oZ6eR3G9cL5U0tQ7D8P4bM1N3kF2xR9W7V6Y5Uo4G3J0pZ8a2iL1mK9T6X7N5cV4F3hY8J0R2L1Q9uN7M6kX5V3iT4oY7Z2rG8F1cL5W0P9a6N4D3eQ1mJ7T2X9L5V6G8K4oN3R1Y7cW0F5J2P9h6M4X3D8a1T7K5V9n2Y6L3iF0R8W4J7X2G5mN6Q3L1V0cT9Y8M5oK4F7N3P1J6X2i9R8G5D7Y4L0W3Q2F9m8T6V1oK7N5G3P4J0X9L1cQ8Y2i6T7D5M3V0F4R9N1K8W2G7L3T5oX6Y4J1P2D9M7Q8F0cK5N3R6V2G9T4J7iL1W8Y3X5oN0Q2F4D7T1M9R6P8V3K5J2X4iG0Y7L1T9D8N6F3W4V2R7Q1X5G9P6J0L3oT8Y7D4W2M5V1N3R9Q6F8X7iJ4L2K5G0T9Y3D8W1N6P5M4R2X7F3V9Q0oJ6T5L1Y7i2N4G8K3P9F6W0R7Q1X3D4V5J9L2oT6M8Y0K5P7N4F3X1J9W2i6L7T8D0R5Y4G3V7K2M9P6F0N1X3Q4J5oT8L7W9D2Y6i1G4R3V7N5Q0X9P6J8T2D1L7M4Y5K3F6W0R9G2Q7N1X8P4T6J5L0D2Y3i7K9V8W6F1X4Q2R3M9P5T7N0L8J4Y6o1G2V3D5X9W7T4K6N8L3Y0P2J5M7D1i6Q9G8R4X2F3N7T5V1oL4K9J6D3W7X8Q2G5R1Y0M6i9N4P2F3L7T8V6J5K1o2W4Q7Y9D3M8R5X6P1F4G0L7T2J9i3N6V5X8K4D1W7Y2Q9R3P0F6L5M4T8oJ1G7N2X6D3V5Q9K0Y4W8R1i2M7J6T4P3L9G1X8V5Q2N4K3W7F6R0oY5D1T8J4L6V7X3Q9F2i5M0R1P8Y7D6N4T9J3W5K2X1o8Q7F6G4L9R2M0P3D5T7X1V8W4J6Y2N9K5Q0i3L7R1G4T8N2M6V3J5X9K7D1W4P6F2Q8Y5L0o9M3T7R1X4G2J6N5D8W3K9Y0F7i4Q2P8L5V6N1J3M9K4T7R2D8X5W0o6F1G7Q3L9V2P4N6D5i3T8X1K7W9Y0R2M6J5Q8L4P3N7D9F6T2X1V5K0o4G7Y3L9J6W8M2Q5R1T3X7D6N4J9K5F8P1G2L0o3M6Q7R5Y4T9J8D2V1N3X5K7W6P0L4F9Q2i1Y3G8M6J7T9D2W4X5K1o3Q8N7L4V2G6P9M1D0R3J7Y4qM8G7h2FQz4WXpdVeL6g0uYvMRb1NtnO2cD5xP3KZjAa9sIbvRf7LUj8yMT0WoXhBnDwUp9rLFxgzKvNaWi8mJkPSO6Yt4ZE5X13NC2HqbDcfGLJxZsUzHa7pkYrOv9MwP0V9jt5UnM0lF4Jr8x6yZn3PZUBYqFHzKJ2LD8m9AhNBj2W1R5G60TxCgVy3XNa0kT7lm9EvDhP4J8YWg5qzr6QLXn7M3oVi2QX5zYvRJ1L2Ka7Hc9oMbDp5G8tUn6PwCf3XqN0Ve4YXZ1xLz3j7P9FrV2K6m1Ah8QNiJ5TW0oMbD1CzQ3GRf7Xg2vW8Z5L4a9NnYpF6Lh7R8wJc2U3Mi5T0tVqK4OxG6Ym1XgP9Ln7WJ5kY3R8z1QdL4a0eF2bMvJ9TX7Uz3P6WiY8m0HlN2Lg5YqG4rF7oPxD8c1F6aV4Zy0pNi3WhL9T7X5gR1K6mP2cQ3Ue8VoN7Y4z7LpFn6X0Mg5YqJ1v3X8rZh9UoN2kD5W1V7yT3aL6F0m9Q4Pg8eYc5zX2oNi1Wr6K7M4U8n3P5L0VJ9Yq7hR2G6c1TxZ4F3bJ5N8M0uL2oKv1D9W6iR7zF5G4T3pY8Xj2a0mN1L7P9v6M3Q5nK8hT4F2iY7XW1oZ6eR3G9cL5U0tQ7D8P4bM1N3kF2xR9W7V6Y5Uo4G3J0pZ8a2iL1mK9T6X7N5cV4F3hY8J0R2L1Q9uN7M6kX5V3iT4oY7Z2rG8F1cL5W0P9a6N4D3eQ1mJ7T2X9L5V6G8K4oN3R1Y7cW0F5J2P9h6M4X3D8a1T7K5V9n2Y6L3iF0R8W4J7X2G5mN6Q3L1V0cT9Y8M5oK4F7N3P1J6X2i9R8G5D7Y4L0W3Q2F9m8T6V1oK7N5G3P4J0X9L1cQ8Y2i6T7D5M3V0F4R9N1K8W2G7L3T5oX6Y4J1P2D9M7Q8F0cK5N3R6V2G9T4J7iL1W8Y3X5oN0Q2F4D7T1M9R6P8V3K5J2X4iG0Y7L1T9D8N6F3W4V2R7Q1X5G9P6J0L3oT8Y7D4W2M5V1N3R9Q6F8X7iJ4L2K5G0T9Y3D8W1N6P5M4R2X7F3V9Q0oJ6T5L1Y7i2N4G8K3P9F6W0R7Q1X3D4V5J9L2oT6M8Y0K5P7N4F3X1J9W2i6L7T8D0R5Y4G3V7K2M9P6F0N1X3Q4J5oT8L7W9D2Y6i1G4R3V7N5Q0X9P6J8T2D1L7M4Y5K3F6W0R9G2Q7N1X8P4T6J5L0D2Y3i7K9V8W6F1X4Q2R3M9P5T7N0L8J4Y6o1G2V3D5X9W7T4K6N8L3Y0P2J5M7D1i6Q9G8R4X2F3N7T5V1oL4K9J6D3W7X8Q2G5R1Y0M6i9N4P2F3L7T8V6J5K1o2W4Q7Y9D3M8R5X6P1F4G0L7T2J9i3N6V5X8K4D1W7Y2Q9R3P0F6L5M4T8oJ1G7N2X6D3V5Q9K0Y4W8R1i2M7J6T4P3L9G1X8V5Q2N4K3W7F6R0oY5D1T8J4L6V7X3Q9F2i5M0R1P8Y7D6N4T9J3W5K2X1o8Q7F6G4L9R2M0P3D5T7X1V8W4J6Y2N9K5Q0i3L7R1G4T8N2M6V3J5X9K7D1W4P6F2Q8Y5L0o9M3T7R1X4G2J6N5D8W3K9Y0F7i4Q2P8L5V6N1J3M9K4T7R2D8X5W0o6F1G7Q3L9V2P4N6D5i3T8X1K7W9Y0R2M6J5Q8L4P3N7D9F6T2X1V5K0o4G7Y3L9J6W8M2Q5R1T3X7D6N4J9K5F8P1G2L0o3M6Q7R5Y4T9J8D2V1N3X5K7W6P0L4F9Q2i1Y3G8M6J7T9D2W4X5K1o3Q8N7L4V2G6P9M1D0R3J7Y4qM8G7h2FQz4WXpdVeL6g0uYvMRb1NtnO2cD5xP3KZjAa9sIbvRf7LUj8yMT0WoXhBnDwUp9rLFxgzKvNaWi8mJkPSO6Yt4ZE5X13NC2HqbDcfGLJxZsUzHa7pkYrOv9MwP0V9jt5UnM0lF4Jr8x6yZn3PZUBYqFHzKJ2LD8m9AhNBj2W1R5G60TxCgVy3XNa0kT7lm9EvDhP4J8YWg5qzr6QLXn7M3oVi2QX5zYvRJ1L2Ka7Hc9oMbDp5G8tUn6PwCf3XqN0Ve4YXZ1xLz3j7P9FrV2K6m1Ah8QNiJ5TW0oMbD1CzQ3GRf7Xg2vW8Z5L4a9NnYpF6Lh7R8wJc2U3Mi5T0tVqK4OxG6Ym1XgP9Ln7WJ5kY3R8z1QdL4a0eF2bMvJ9TX7Uz3P6WiY8m0HlN2Lg5YqG4rF7oPxD8c1F6aV4Zy0pNi3WhL9T7X5gR1K6mP2cQ3Ue8VoN7Y4z7LpFn6X0Mg5YqJ1v3X8rZh9UoN2kD5W1V7yT3aL6F0m9Q4Pg8eYc5zX2oNi1Wr6K7M4U8n3P5L0VJ9Yq7hR2G6c1TxZ4F3bJ5N8M0uL2oKv1D9W6iR7zF5G4T3pY8Xj2a0mN1L7P9v6M3Q5nK8hT4F2iY7XW1oZ6eR3G9cL5U0tQ7D8P4bM1N3kF2xR9W7V6Y5Uo4G3J0pZ8a2iL1mK9T6X7N5cV4F3hY8J0R2L1Q9uN7M6kX5V3iT4oY7Z2rG8F1cL5W0P9a6N4D3eQ1mJ7T2X9L5V6G8K4oN3R1Y7cW0F5J2P9h6M4X3D8a1T7K5V9n2Y6L3iF0R8W4J7X2G5mN6Q3L1V0cT9Y8M5oK4F7N3P1J6X2i9R8G5D7Y4L0W3Q2F9m8T6V1oK7N5G3P4J0X9L1cQ8Y2i6T7D5M3V0F4R9N1K8W2G7L3T5oX6Y4J1P2D9M7Q8F0cK5N3R6V2G9T4J7iL1W8Y3X5oN0Q2F4D7T1M9R6P8V3K5J2X4iG0Y7L1T9D8N6F3W4V2R7Q1X5G9P6J0L3oT8Y7D4W2M5V1N3R9Q6F8X7iJ4L2K5G0T9Y3D8W1N6P5M4R2X7F3V9Q0oJ6T5L1Y7i2N4G8K3P9F6W0R7Q1X3D4V5J9L2oT6M8Y0K5P7N4F3X1J9W2i6L7T8D0R5Y4G3V7K2M9P6F0N1X3Q4J5oT8L7W9D2Y6i1G4R3V7N5Q0X9P6J8T2D1L7M4Y5K3F6W0R9G2Q7N1X8P4T6J5L0D2Y3i7K9V8W6F1X4Q2R3M9P5T7N0L8J4Y6o1G2V3D5X9W7T4K6N8L3Y0P2J5M7D1i6Q9G8R4X2F3N7T5V1oL4K9J6D3W7X8Q2G5R1Y0M6i9N4P2F3L7T8V6J5K1o2W4Q7Y9D3M8R5X6P1F4G0L7T2J9i3N6V5X8K4D1W7Y2Q9R3P0F6L5M4T8oJ1G7N2X6D3V5Q9K0Y4W8R1i2M7J6T4P3L9G1X8V5Q2N4K3W7F6R0oY5D1T8J4L6V7X3Q9F2i5M0R1P8Y7D6N4T9J3W5K2X1o8Q7F6G4L9R2M0P3D5T7X1V8W4J6Y2N9K5Q0i3L7R1G4T8N2M6V3J5X9K7D1W4P6F2Q8Y5L0o9M3T7R1X4G2J6N5D8W3K9Y0F7i4Q2P8L5V6N1J3M9K4T7R2D8X5W0o6F1G7Q3L9V2P4N6D5i3T8X1K7W9Y0R2M6J5Q8L4P3N7D9F6T2X1V5K0o4G7Y3L9J6W8M2Q5R1T3X7D6N4J9K5F8P1G2L0o3M6Q7R5Y4T9J8D2V1N3X5K7W6P0L4F9Q2i1Y3G8M6J7T9D2W4X5K1o3Q8N7L4V2G6P9M1D0R3J7Y4";
static const char *hello_name = "hello";

static thrd_t threads[2];
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

static size_t iov_copy(const struct iovec *src, int src_count, struct iovec *dest, int dest_count) {
	size_t total_copied = 0;
	int src_index = 0;
	int dest_index = 0;
	size_t src_offset = 0;
	size_t dest_offset = 0;

	while (src_index < src_count && dest_index < dest_count) {
		// Calculate the remaining bytes in the current src and dest iovec
		size_t src_remaining = src[src_index].iov_len - src_offset;
		size_t dest_remaining = dest[dest_index].iov_len - dest_offset;

		// Determine the amount to copy
		size_t to_copy = src_remaining < dest_remaining ? src_remaining : dest_remaining;

		// Perform the copy
		memcpy((char *)dest[dest_index].iov_base + dest_offset,
				(char *)src[src_index].iov_base + src_offset,
				to_copy);

		// Update offsets and total copied
		src_offset += to_copy;
		dest_offset += to_copy;
		total_copied += to_copy;

		// If we've exhausted the current src iovec, move to the next one
		if (src_offset == src[src_index].iov_len) {
			src_index++;
			src_offset = 0;
		}

		// If we've exhausted the current dest iovec, move to the next one
		if (dest_offset == dest[dest_index].iov_len) {
			dest_index++;
			dest_offset = 0;
		}
	}

	return total_copied;
}

static ssize_t stream_writev(int fd, struct iovec *iov, int count,
                             void *userdata) {
	const struct fuse_out_header *out = iov[0].iov_base;
	VduseVirtq *vq = userdata;
	size_t written;

	(void)fd;
	assert(iov[0].iov_len >= sizeof(*out));

	assert(cur_elem);

	written = iov_copy(iov, count, cur_elem->in_sg, cur_elem->in_num);
	vduse_queue_push(vq, cur_elem, written);
	vduse_queue_notify(vq);

	free(cur_elem);
	cur_elem = NULL;
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
	// VduseVirtqElement *elem, **added_elem;
	ssize_t s;
	int vduse_fd = vduse_queue_get_fd(vq);

	(void)fd;

	do {
		assert(!cur_elem);
		cur_elem = vduse_queue_pop(vq, sizeof(*cur_elem));
		if (cur_elem) {
			break;
		}

		// TODO Do we need an extra fd to exit thread?
		fprintf(stderr, "[eperezma %s:%d]poll_one_forever q=%p enter\n", __func__, __LINE__, vq);
		int r = poll_one_forever(vduse_fd);
		fprintf(stderr, "[eperezma %s:%d][poll_one_forever q=%p ret=%d][errno=%d]\n", __func__, __LINE__, vq, r, errno);
		assert(r == 1);
		fprintf(stderr, "[DEBUG poll r=%d][errno=%d]\n", r, errno);

		// We know for sure vq fd is eventfd
		r = read(vduse_fd, (uint64_t[]){0}, sizeof(uint64_t));
		fprintf(stderr, "[DEBUG read r=%d][errno=%d]\n", r, errno);
		if (r == -1 && errno == EAGAIN) {
			continue;
		}
		assert(r == sizeof(uint64_t));
	} while (1);

	fprintf(stderr, "[DEBUG %s:%d][elem=%p]\n", __func__, __LINE__, cur_elem);

	s = iov_to_buf(cur_elem->out_sg, cur_elem->out_num, buf, buf_len);
	assert(s > 0); // return -1
	assert(s > sizeof(struct fuse_in_header));
	assert(s <= buf_len);

	return s;
}

static ssize_t stream_splice_send(int fdin, off_t *offin, int fdout,
					    off_t *offout, size_t len,
                                  unsigned int flags, void *userdata) {
	(void)userdata;
	assert(!"splice send unsupported ATM");

	size_t count = 0;
	while (count < len) {
		int i = splice(fdin, offin, fdout, offout, len - count, flags);
		if (i < 1)
			return i;

		count += i;
	}
	return count;
}

static int fuse_poll_queue(void *arg)
{
	VduseVirtq *vq = arg;
	int idx = vduse_dev_get_queue(vduse_queue_get_dev(vq), 0) == vq ? 0 : 1;
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
	return 0;
}

static void vduse_dev_enable_queue(VduseDev *dev, VduseVirtq *vq)
{
	int idx = vduse_dev_get_queue(dev, 0) == vq ? 0 : 1;
	int *started_vqs = vduse_dev_get_priv(dev);

	int r = thrd_create(&threads[idx], fuse_poll_queue, vq);
	assert(r == 0);

	(*started_vqs)++;
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

/* Copied from kernel doc vduse */
static int netlink_add_vduse(const char *name, enum vdpa_command cmd)
{
        struct nl_sock *nlsock;
        struct nl_msg *msg;
        int famid;

        nlsock = nl_socket_alloc();
        if (!nlsock)
                return -ENOMEM;

        if (genl_connect(nlsock))
                goto free_sock;

        famid = genl_ctrl_resolve(nlsock, VDPA_GENL_NAME);
        if (famid < 0)
                goto close_sock;

        msg = nlmsg_alloc();
        if (!msg)
                goto close_sock;

        if (!genlmsg_put(msg, NL_AUTO_PORT, NL_AUTO_SEQ, famid, 0, 0, cmd, 0))
                goto nla_put_failure;

        NLA_PUT_STRING(msg, VDPA_ATTR_DEV_NAME, name);
        if (cmd == VDPA_CMD_DEV_NEW)
                NLA_PUT_STRING(msg, VDPA_ATTR_MGMTDEV_DEV_NAME, "vduse");

        if (nl_send_sync(nlsock, msg))
                goto close_sock;

        nl_close(nlsock);
        nl_socket_free(nlsock);

        return 0;
nla_put_failure:
        nlmsg_free(msg);
close_sock:
        nl_close(nlsock);
free_sock:
        nl_socket_free(nlsock);
        return -1;
}

static VduseDev *create_vdpa(void *priv) {
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
	int r;

	vduse_dev = vduse_dev_create(vduse_name, device_id, vendor_id,
	                             features, num_queues, config_size, config,
	                             &vduse_ops, priv);
	assert(vduse_dev);

	// TODO: make this configurable.
	r = vduse_set_reconnect_log_file(vduse_dev, "/tmp/vduse_reconnect.log");
	assert(r == 0);
	r = unlink("/tmp/vduse_reconnect.log");

	for (int i = 0; i < num_queues; ++i) {
		r = vduse_dev_setup_queue(vduse_dev, i, q_size);
		assert(r == 0);
	}

	r = netlink_add_vduse("fsd", VDPA_CMD_DEV_NEW);
	assert (r == 0);

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
	bool mount_called = false;
	int q_started = 0;

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

	vdev = create_vdpa(&q_started);
	if (!vdev)
		goto err;


	// Wait until vqs are initialized
	while (1) {
		fprintf(stderr, "[eperezma %s:%d][poll_one_forever devfd enter]\n", __func__, __LINE__);
		ret = poll_one_forever(vduse_dev_get_fd(vdev));
		fprintf(stderr, "[eperezma %s:%d][poll_one_forever devfd ret=%d][errno=%d]\n", __func__, __LINE__, ret, errno);
		assert(ret > 0);

		ret = vduse_dev_handler(vdev);
		assert(ret == 0);

		if (!mount_called && q_started == 2) {
			int r = mount("a", "/mnt", "virtiofs", 0 /* mountflags */, NULL /* data */);
			assert(r == 0);
			mount_called = true;
		}
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
