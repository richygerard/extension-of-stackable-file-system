/*
 * Header file for set_ecryption_key
 */

#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <openssl/md5.h>

#define WRAPFS_MAX_KEY_BYTES 16

#define SET_ENCRYPTION_KEY _IOW('f', 0, char *)

