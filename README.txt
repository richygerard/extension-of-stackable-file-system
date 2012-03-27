EXTENSION OF 'WRAPFS' STACKABLE FILE SYSTEM IN LINUX

-------------
INTRODUCTION
-------------

	* A New Stackable file system has been written with the extension of 'wrapfs' file system in Linux Kernel 3.2.2. 

	* The File System implements address space operations as well as it is extended to be a crypt file system.


--------------------
SYSTEM REQUIREMENTS
--------------------

	* The WRAPFS File system is implemented in CentOS v 3.2.2. Gcc version is 4.1.2 which compiles the set_key user level code as well as the kernel file system specific code.
	
	* For MD5 Hashing, set_key will require OpenSSL libraries. To work with that, we need to install openssl-devel and openssl libraries.
	
-------------
SOURCE CODE
-------------

	The following files are present in the folder
	
	-------------------
	Kernel Level Files 
	-------------------
	
	* MAIN.C : All the mount options for the file system can be found here.
	
	* FILE.C : File operations.
	 
	* LOOKUP.C : The Lookup operations are performed here.
	
	* DENTRY.C : Directory Entry operations.
	
	* INODE.C : Inode operations.
	
	* MMAP.C : The address space operations are implemented in mmap.c
	
	* SUPER.C : Super Block Operations.
	
	* WRAPFS.H : Kernel Module Program header file.
	
	----------------
	User Level Files
	-----------------
	
	* SET_KEY.C : User Level Program file.
	
	* SET_KEY.H : User Level Program header file.
	
	* MAKEFILE : Makefile is used to 'make' the program and convert it into executables : "set_key" [USER] & "wrapfs.ko" [KERNEL].
	
	* README.HW2 : Ofcourse, This is the Readme file :)
	
	
-------------------
KERNEL COMPILATION
-------------------

	* CentOS has been installed and its configuration file is stored as kernel.config in the directory. Kernel configuration was based on a minimal required module setup which included networking options (eth0 interface support for access through ssh), basic drivers for file systems, boot configuration requirements, basic device drivers and SCSI drivers. 
	
	
------------------------------------------
ADDRESS SPACE OPERATIONS & MMAP OPERATIONS
------------------------------------------

	* READ ADDRESS SPACE OPERATION :
			For the reading address space operation, unionfs_readpage has been used. wrapfs_readpage calls the lower level file and maps the page onto the lower level file. The page offset is determined by page_offset(page). We use vfs_read to read the page in temporary virtual space by kmap(). The last bytes of the page are memset with 0 and then we flush the page.
			
	* WRITE ADDRESS SPACE OPERATION :
			For the writing address space operation, git's commit as mentioned in the homework was useful. The git at that time of converting from address space operation to vm operation was learnt and its reverse was done in wrapfs_writepage. wrapfs_write begin and wrapfs_write grabs a page to be written and we do the actual writing (using vfs_write) to the lower file in write_end. The wrapfs_write_end follows a close way resembling to the how to wrapfs_readpage is performed. The method of wrapfs_readpage and wrapfs_write_end will be the same except the vfs_write instead of vfs_read.

	* Created a new address space operations object for the address space implementations.
		const struct address_space_operations wrapfs_aops = {
        .readpage = wrapfs_readpage,
        .writepage = wrapfs_writepage,
        .write_begin = wrapfs_write_begin,
        .write_end = wrapfs_write_end,
		};
		
	* When the mmap option is set at mount time, a global variable of g_mmap is set. The switching of mmap file operation and address space file operation takes place in the iget() : wrapfs_mmap_fops and wrapfs_main_fops. This idea is triggered by looking at the state of the git tree as given in the homework. So, 2 file operation objects are created to switch between the two.
	
	* The mmap operation is triggered by specifiying the -o mmap option set at mount time. Then, wrapfs_mmap_fops object gets initialized and the corresponding operations are used.

	* For the MMAP operations, we have created a new file operations object : wrapfs_mmap_ops
	
	 const struct file_operations wrapfs_mmap_fops = {
        .llseek         = generic_file_llseek,
        .read           = do_sync_read,
        .aio_read       = generic_file_aio_read,
        .write          = do_sync_write,
        .aio_write      = generic_file_aio_write,
        .unlocked_ioctl = wrapfs_unlocked_ioctl,
	#ifdef CONFIG_COMPAT
        .compat_ioctl   = wrapfs_compat_ioctl,
	#endif
         .mmap           = wrapfs_mmap,
        .open           = wrapfs_open,
        .flush          = wrapfs_flush,
        .release        = wrapfs_file_release,
         .fsync          = wrapfs_fsync,
        .fasync         = wrapfs_fasync,
		};

--------------------------------
ENCRYPTION AND DECRYPTION DESIGN
-------------------------------

	* In the Kernel Module, there are various checks on boundary conditions which are required since we are in kernel mode and we have exclusive access for everything. We need to build our module to be too robust and prone to error conditions.
		
	* When we compile the code using WRAPFS_CRYPTO flag set, data file encryption and decryption is enabled. What we do here is, we bring the page from the lower file, decrypt that page and send it to the page to be retrieved. In the same way, whenever we write a file to disk, the pages are mapped onto the virtual space through kmap() temporary page allocator and we do the encrypt phenomena and write that page to disk.
	
	* Encryption and Decryption is done as done in HW1. A simple encryption and decryption counter aes process takes place. The encryption key is retrieved from the super block for every encryption and decryption process. If No key is present in the super block, no data is retrieved/written.
	
	* The key is 256 bit MD5 hashed key as injected from the user program 'set_key'. The key can revoked by sending 0s as password.
	
	* After every mount, the encryption key has to be injected into the super block for every encryption and decryption process. The key is stored in super block in a character pointer.
		
	* In wrapfs_readpage, we read the page by decrypting the page from the lower file. The input is page_data and the output is dpage_data which is the result of wrapfs_decrypt(). wrapfs_decrypt() needs the key from the super block to perform the op. Similarly, the encryption takes place in the write_end where the page_data is the input and epage_data is the output. 


-------------------------------
USER PROGRAM : SET_KEY - IOCTL
-------------------------------

	* User IOCTL is used to set the encryption key in the super block.
	
	* From the User, it receives the mount point as well as the password. IOCTL runs by making a temporary file in the mount point and then injects the encryption key to the super block. After the key injection, the temporary file gets removed automatically.
	
	* Here, I am sending a char buffer as input to the super block which is a hashed version of the user input key. MD5 digest is used as the passphrase hashed encryption key.
	
	* The IOCTL is a IOW ioctl which sends data to the kernel. It is defined as below :

		#define SET_ENCRYPTION_KEY _IOW('f', 0, char *)

	* The Name of the IOCTL is SET_ENCRYPTION_KEY and it a write data ioctl which writes data to the Kernel. In order to avoid collisions with other IOCTLs, we define the number 0 and also associate a constant 'f' with it. We send a character pointer through this IOCTL.

	* A snippet of sending IOCTL to Kernel is below. We MD5 the password and send it in a character buffer.

		MD5((unsigned char *) argv[2], strlen(argv[2]), (unsigned char *)h_key);
			 /* sending key */
		if (ioctl(fd, SET_ENCRYPTION_KEY, h_key)) {
	      		printf("encryption key sent\n");
	  	 }
		else
   			printf("encryption key not sent\n");

	* If the password is a set of 0s, a revoking key is sent to the super block. Else, the hashed version of the password is sent.
	
	* The password is stored in the super block in a char pointer. The key can be revoked by sending 0s. For every file read or write access, you need an encryption key to be injected to the super block. A revoking key is stored as a sequence of null characters in the Super Block.
	
	* The IOCTL's input is checked everytime if it is a revoking key or an encryption key. And the subsequent processes follow.

---------------------------
COMPILING THE SOURCE CODE
---------------------------

	* For evaluation, first compile the kernel. The Kernel's config file in /hw2 directory will help the same.
	
	* In hw2 directory, 'make' the source code and find 2 executables as said before - 'wrapfs.ko' and 'set_key'. You can run make 'from inside the directory'. Dont make the files in the 'kernel source tree' Make it inside the wrapfs/folder. If you need WRAPFS_CRYPTO to be enabled, give it in make command as given in the example below.
	
	* Set the 'WRAPFS_CRYPTO' flag in Makefile for evaluating the file data encryption and decryption. You may also set the 'DEBUG' flag to get more information.
	
	* Then, Insert the module using "insmod wrapfs.ko" and remove the module use "rmmod wrapfs.ko".	
	
	* After inserting the module, mount the file using the mount option
	
	'mount -t wrapfs <dest_pt> <src_pt>' 
	
	for address space operations. For file data encryption and decryption, set the mmap option using 
	
	'mount -t wrapfs -o mmap <dest_pt> <src_pt>'
	
	* The user level program 'set_key' is generated once you run the Makefile. Use this 'set_key' to set the encryption key to the super block for the file data encryption and decryption. 
	
	'./set_key <src_pt> <pwd>'
	
	* To Revoke the key, give the password as 0s.
	
	'./set_key <src_pt> "00000"
	
	
	Eg :
	
	For address space operations :
	$ make
	$ insmod wrapfs.ko
	$ mount -t wrapfs /usr/src /mnt/wrapfs
	$ ./set_key /mnt/wrapfs/ "password_here"
	$ umount /mnt/wrapfs
	$ rmmod wrapfs.ko
	
	For File Data Encryption & Decryption :
	$ make EXTRA+=-DWRAPFS_CRYPTO;
	$ insmod wrapfs.ko
	$ mount -t wrapfs -o mmap /usr/src /mnt/wrapfs
	$ ./set_key /mnt/wrapfs/ "password_here"
	$ umount /mnt/wrapfs
	$ rmmod wrapfs.ko
	
	* To set the 'WRAPFS_CRYPTO' flag and 'DEBUG' flag, use this make command : make EXTRA+="-DWRAPFS_CRYPTO -DDEBUG"

