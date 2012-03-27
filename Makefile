WRAPFS_VERSION="0.1"
EXTRA_CFLAGS += -DWRAPFS_VERSION=\"$(WRAPFS_VERSION)\" $(EXTRA)

obj-m := wrapfs.o 
wrapfs-objs := dentry.o file.o inode.o main.o super.o lookup.o mmap.o
all:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules
	gcc -Wall -Werror -o set_key set_key.c set_key.h -lssl
clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean
	rm set_key
	rm *.o *~
