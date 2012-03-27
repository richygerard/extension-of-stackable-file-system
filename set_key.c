/*
 * set_encryption_key ioctl
 * driver program for setting encryption key
 */

#include "set_key.h"

/* checks zeros from the input */
int check_zeros(char *string, int len)
{
	int i, check = 0;
	/* checking if all the characters in the string are 0s */
	for (i = 0; i < len; i++)
	{
		if (memcmp(&string[i], "0", 1) == 0)
		{
			check++;

		}
	}
	if (check == len)
		return 1;
	else
		return 0;
}

/* main */
int main(int argc, char **argv) 
{
	int fd;
	char temp[100];
	char *h_key;

	if (argc < 3 || argc >3) {
		printf("Error. Set password by ./set_key 'mnt_pnt' 'pwd'");
		return 0;
	}

	if (argc == 3) {

		/* setting the mount point */
		strcpy(temp, argv[1]);
		strcat(temp, "tmp.tmp");
		fd = open(temp, O_RDWR | O_CREAT);
		if (fd < 0) {
			printf("WRAPFS is not mounted\n");
			goto out;
		}

		/* checking zeros in the string */
		if (check_zeros(argv[2], strlen(argv[2]))) {
			/* if zeros, revoking key of 0's is sent */
			memset(h_key, 0, WRAPFS_MAX_KEY_BYTES);
			if (!ioctl(fd, SET_ENCRYPTION_KEY, h_key)) {
				printf("revoking key not sent\n");
				goto out;
			}
			printf("revoking key is sent\n");
			goto out;
		}

		/* hashing input key */
		MD5((unsigned char *) argv[2], strlen(argv[2]), (unsigned char *)h_key);
		/* sending key */
		if (ioctl(fd, SET_ENCRYPTION_KEY, h_key)) {
			printf("encryption key sent\n");
		}
		else
			printf("encryption key not sent\n");
	}
out:
	close(fd);
	remove(temp);
	return 0;
}
