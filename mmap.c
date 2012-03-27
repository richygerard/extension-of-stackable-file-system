/*
 * 2012 - Richy Gerard
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */

#include "wrapfs.h"

/* wrapfs_crypto mode for encrypted file system */
#ifdef WRAPFS_CRYPTO

/* allocating block cipher */
static struct crypto_blkcipher *ceph_crypto_alloc_cipher(void)
{
#ifdef DEBUG
	TRACK;
#endif
	return crypto_alloc_blkcipher("ctr(aes)", 0, CRYPTO_ALG_ASYNC);
}


/*
 * wrapfs_encrypt() uses input key to encrypt page_data
 * to epage_data with source length src_len
 *
 */
static int wrapfs_encrypt(const char *page_data, char *epage_data, \
				const char *key, int src_len) 
{
	int ret = 0, dst_len = src_len;
	struct scatterlist sg_in[1], sg_out[1];
	struct crypto_blkcipher *tfm = ceph_crypto_alloc_cipher();
	struct blkcipher_desc desc = { .tfm = tfm, .flags = 0 };

#ifdef DEBUG
	TRACK;
#endif
	/* checking errors on input args */
	if (page_data == NULL) {
		ret = -EINVAL;
		goto out;
	}

	if (key[0] == '\0') {
		printk(KERN_INFO "err in encrypt key");
		ret = -EINVAL;
		goto out;
	}

	if (src_len == 0) {
		ret = -EINVAL;
		goto out;
	}

	if (IS_ERR(tfm)) {
		printk(KERN_INFO "err in wrapfs encrypt tfm");
		ret = PTR_ERR(tfm);
		goto out;
	}

	/* memsetting epage_data */
	memset(epage_data, 0, dst_len);
	/* Setting the Key for Block cipher */
	ret = crypto_blkcipher_setkey((void *)tfm, key, \
				 WRAPFS_MAX_KEY_BYTES);
	sg_init_table(sg_in, 1);
	sg_init_table(sg_out, 1);
	/* input buffer is page_data and output buffer is epage_data */
	sg_set_buf(&sg_in[0], page_data, src_len);
	sg_set_buf(&sg_out[0], epage_data, dst_len);
	if (ret < 0) {
		ret = -EACCES;
		goto out_free;
	}

	/*
	print_hex_dump(KERN_ERR, "enc key: ", DUMP_PREFIX_NONE, 16, 1,
		       key, key_len, 1);
	print_hex_dump(KERN_ERR, "enc src: ", DUMP_PREFIX_NONE, 16, 1,
			src, src_len, 1);
	print_hex_dump(KERN_ERR, "enc pad: ", DUMP_PREFIX_NONE, 16, 1,
			pad, zero_padding, 1);
	*/

	/* Encrypting the Block Cipher */
#ifdef DEBUG
	TRACK_STRING(page_data);
#endif
	ret = crypto_blkcipher_encrypt(&desc, sg_out, sg_in, src_len);
#ifdef DEBUG
	TRACK_STRING(epage_data);
#endif
	if (ret < 0) {
		printk(KERN_INFO "encryption failed : %d\n", ret);
		goto out_free;
	}

out_free:
	crypto_free_blkcipher(tfm);
	
out:
	return ret;
}

/*
 * wrapfs_decrypt() uses input key to decrypt page_data
 * to dpage_data with source length src_len
 *
 */
static int wrapfs_decrypt(const char *page_data, char *dpage_data,
				const char *key, int src_len)
{
	int ret = 0, dst_len = src_len;
	struct scatterlist sg_in[1], sg_out[1];
	struct crypto_blkcipher *tfm = ceph_crypto_alloc_cipher();
	struct blkcipher_desc desc = { .tfm = tfm, .flags = 0 };

#ifdef DEBUG
	TRACK;
#endif
	if (page_data == NULL) {
		ret = -EINVAL;
		goto out;
	}

	if (key[0] == '\0') {
		printk(KERN_INFO "err in decrypt key");
		ret = -EINVAL;
		goto out;
	}

	if (src_len == 0) {
		ret = -EINVAL;
		goto out;
	}

	if (IS_ERR(tfm)) {
		printk(KERN_INFO "err in wrapfs decrypt tfm");
		ret = PTR_ERR(tfm);
		goto out;
	}
	/* memsetting dpage_data */	
	memset(dpage_data, 0, PAGE_CACHE_SIZE);
	/* Setting the key for Block cipher */
	ret = crypto_blkcipher_setkey((void *)tfm, key,\
				 WRAPFS_MAX_KEY_BYTES);
	sg_init_table(sg_in, 1);
	sg_init_table(sg_out, 1);
	/* Input buffer is page_data and output buffer is dpage_data */
	sg_set_buf(&sg_in[0], page_data, src_len);
	sg_set_buf(&sg_out[0], dpage_data, dst_len);

	if (ret < 0) {
		ret = -EACCES;
		goto out_free;
	}
	/*
	print_hex_dump(KERN_ERR, "dec key: ", DUMP_PREFIX_NONE, 16, 1,
		       key, key_len, 1);
	print_hex_dump(KERN_ERR, "dec  in: ", DUMP_PREFIX_NONE, 16, 1,
		       src, src_len, 1);
	*/

	/* Crypto Block Cipher Decryption */
#ifdef DEBUG
	TRACK_STRING(page_data);
#endif
	ret = crypto_blkcipher_decrypt(&desc, sg_out, sg_in, src_len);
#ifdef DEBUG
	TRACK_STRING(dpage_data);
#endif
	if (ret < 0) {
		pr_err("decryption failed : %d\n", ret);
		return ret;
	}

out_free:
	crypto_free_blkcipher(tfm);
out:
        return ret;
}

#endif

/*
 * wrapfs_readpage for address space read page operation
 * 
 */
static int wrapfs_readpage(struct file *file, struct page *page)
{
	int err = 0;
	struct file *lower_file;
	struct inode *inode;
	char *page_data = NULL;
	mode_t orig_mode;
	mm_segment_t old_fs;

#ifdef WRAPFS_CRYPTO
	int err1 = 0; 
	struct wrapfs_sb_info *wrapfsb = NULL;
	char *dpage_data = NULL;
#endif
#ifdef DEBUG
	TRACK;
#endif

	BUG_ON(file == NULL);
	lower_file = wrapfs_lower_file(file);
	/* FIXME: is this assertion right here? */
	BUG_ON(lower_file == NULL);
	inode = file->f_path.dentry->d_inode;

	/*
	 * Use vfs_read because some lower file systems don't have a
	 * readpage method, and some file systems (esp. distributed ones)
	 * don't like their pages to be accessed directly.  Using vfs_read
	 * may be a little slower, but a lot safer, as the VFS does a lot of
	 * the necessary magic for us.
	 */
	
	page_data = (char *) kmap(page);
	lower_file->f_pos = page_offset(page);
	mutex_lock_nested(&lower_file->f_path.dentry->d_inode->i_mutex,\
						 I_MUTEX_NORMAL);
	old_fs = get_fs();
	set_fs(KERNEL_DS);
	/*
	 * generic_file_splice_write may call us on a file not opened for
	 * reading, so temporarily allow reading.
	 */
	orig_mode = lower_file->f_mode;
	lower_file->f_mode |= FMODE_READ;
#ifdef WRAPFS_CRYPTO
	wrapfsb = (struct wrapfs_sb_info *) file->f_path.dentry->\
					d_sb->s_fs_info;
	if (wrapfsb->key[0] == '\0') {
#ifdef DEBUG
		printk(KERN_INFO "encryption key is not set/revoked\n");
#endif
		err = -EACCES;
		goto out_err;
	}
#endif
	err = vfs_read(lower_file, page_data, PAGE_CACHE_SIZE,
					 &lower_file->f_pos);
	lower_file->f_mode = orig_mode;
	set_fs(old_fs);
	if (err < 0) {
		goto out_err;
	}
#ifdef WRAPFS_CRYPTO

	dpage_data = kmalloc (PAGE_CACHE_SIZE, GFP_KERNEL);
	memset(dpage_data, 0, PAGE_CACHE_SIZE);
	if (wrapfsb->key[0] == '\0') {
		/* no key -> do ordinary vfs_read */
	}
	else {
		/* key -> decrypt and vfs_read */
		err1 = wrapfs_decrypt(page_data, dpage_data, \
			wrapfsb->key, PAGE_CACHE_SIZE);
	}

	memcpy(page_data, dpage_data, PAGE_CACHE_SIZE);
	if (err1 < 0) {
		/* check if decryption took place */
		printk(KERN_INFO "Error in Decryption");
	}
	kfree(dpage_data);
#endif	
out_err:

	if (err >= 0 && err < PAGE_CACHE_SIZE)
		memset(page_data + err, 0, PAGE_CACHE_SIZE - err);
	kunmap(page);
	mutex_unlock(&lower_file->f_path.dentry->d_inode->i_mutex);

	if (err < 0)
		goto out;
	err = 0;
	/* if vfs_read succeeded above, sync up our times */
	fsstack_copy_attr_atime(inode, lower_file->f_path.dentry->d_inode);
	flush_dcache_page(page);

	/*
	 * we have to unlock our page, b/c we _might_ have gotten a locked
	 * page.  but we no longer have to wakeup on our page here, b/c
	 * UnlockPage does it
	 */

out :
	if (err == 0)
		SetPageUptodate(page);
	else
		ClearPageUptodate(page);

	unlock_page(page);
	return err;
}


/* 
 * wrapfs_writepage writes page with reference to 
 * writeback_Control wbc
 */
static int wrapfs_writepage(struct page *page, struct writeback_control *wbc)
{

	int err = -EIO;
	struct inode *inode;
	struct inode *lower_inode;
	struct page *lower_page;
	struct address_space *lower_mapping; /* lower inode mapping */
	gfp_t mask;

#ifdef DEBUG
	TRACK;
#endif
	BUG_ON(!PageUptodate(page));
	inode = page->mapping->host;
	/* if no lower inode, nothing to do */
	if (!inode || !WRAPFS_I(inode)) {
		err = 0;
		goto out;
	}
	lower_inode = wrapfs_lower_inode(inode);
	lower_mapping = lower_inode->i_mapping;
	/*
	 * find lower page (returns a locked page)
	 *
	 * We turn off __GFP_FS while we look for or create a new lower
	 * page.  This prevents a recursion into the file system code, which
	 * under memory pressure conditions could lead to a deadlock.  This
	 * is similar to how the loop driver behaves (see loop_set_fd in
	 * drivers/block/loop.c).  If we can't find the lower page, we
	 * redirty our page and return "success" so that the VM will call us
	 * again in the (hopefully near) future.
	 */
	mask = mapping_gfp_mask(lower_mapping) & ~(__GFP_FS);
	lower_page = find_or_create_page(lower_mapping, page->index, mask);
	if (!lower_page) {
		err = 0;
		set_page_dirty(page);
		goto out;
	}
	/* copy page data from our upper page to the lower page */
	copy_highpage(lower_page, page);
	flush_dcache_page(lower_page);
	SetPageUptodate(lower_page);
	set_page_dirty(lower_page);

	/*
	 * Call lower writepage (expects locked page).  However, if we are
	 * called with wbc->for_reclaim, then the VFS/VM just wants to
	 * reclaim our page.  Therefore, we don't need to call the lower
	 * ->writepage: just copy our data to the lower page (already done
	 * above), then mark the lower page dirty and unlock it, and return
	 * success.
	 */
	BUG_ON(!lower_mapping->a_ops->writepage);
	wait_on_page_writeback(lower_page); /* prevent multiple writers */
	clear_page_dirty_for_io(lower_page); /* emulate VFS behavior */
	err = lower_mapping->a_ops->writepage(lower_page, wbc);
	if (err < 0)
		goto out_release;
	if (err == AOP_WRITEPAGE_ACTIVATE) {
		err = 0;
		unlock_page(lower_page);
	}

out_release:
	/* b/c find_or_create_page increased refcnt */
	page_cache_release(lower_page);

out:
	unlock_page(page);
	return err;
}

static int wrapfs_write_begin(struct file *file,
			struct address_space *mapping,
			loff_t pos, unsigned len, unsigned flags,
			struct page **pagep, void **fsdata)
{
	pgoff_t index = pos >> PAGE_CACHE_SHIFT;
	struct page *page;
	int rc = 0;

#ifdef DEBUG
	TRACK;
#endif
	page = grab_cache_page_write_begin(mapping, index, flags);
	if (!page)
		return -ENOMEM;
	*pagep = page;
	return rc;
}

static int wrapfs_write_end(struct file *file,
			struct address_space *mapping,
			loff_t pos, unsigned len, unsigned copied,
			struct page *page, void *fsdata)
{
	unsigned from = pos & (PAGE_CACHE_SIZE - 1);
	unsigned to = from + copied;
	unsigned bytes = to - from;
	struct inode *inode = mapping->host;
	struct inode *lower_inode = NULL;
	struct file *lower_file = NULL;
	int err = 0;
	char *page_data = NULL;
	mode_t orig_mode;
	mm_segment_t old_fs;

#ifdef WRAPFS_CRYPTO
	char *epage_data = NULL;
	struct wrapfs_sb_info *wrapfsb = NULL;
#endif
#ifdef DEBUG
	TRACK;
#endif

	if (!file || !WRAPFS_F(file)) {
		err = 0;
		goto out;
	}
	BUG_ON(file == NULL);
	lower_file = wrapfs_lower_file(file);
	BUG_ON(lower_file == NULL);
	page_data = (char *) kmap(page);
	lower_file->f_pos = page_offset(page) + from;
#ifdef WRAPFS_CRYPTO
	epage_data = kmalloc(bytes, GFP_KERNEL);
	if (!epage_data) {
#ifdef DEBUG	
		printk(KERN_INFO "err in epage_data malloc");
#endif
		err = PTR_ERR(epage_data);
		goto out;
	}

	if (IS_ERR(epage_data)) {
#ifdef DEBUG
		printk(KERN_INFO "err in epage_data");
#endif
		err = PTR_ERR(epage_data);
		goto out;
	}

	wrapfsb = (struct wrapfs_sb_info *) file->f_path.dentry->\
					d_sb->s_fs_info;
	if (wrapfsb->key[0] == '\0') {

#ifdef DEBUG
		printk(KERN_INFO "encryption key is not set/revoked\n");
#endif
		err = -EACCES;
		goto out;
	}

	old_fs = get_fs();
	set_fs(KERNEL_DS);
	orig_mode = lower_file->f_mode;
	lower_file->f_mode |= FMODE_WRITE;
	if (wrapfsb->key[0] == '\0') {
		err = vfs_write(lower_file, page_data + from, bytes, \
					&lower_file->f_pos);
	}
	else {
		err = wrapfs_encrypt(page_data + from, epage_data, \
						wrapfsb->key, bytes);
		err = vfs_write(lower_file, epage_data, bytes, \
					&lower_file->f_pos);
	}
#else
	old_fs = get_fs();
	set_fs(KERNEL_DS);
	orig_mode = lower_file->f_mode;
	lower_file->f_mode |= FMODE_WRITE;
	err = vfs_write(lower_file, page_data + from, bytes, \
			&lower_file->f_pos);
#endif
	lower_file->f_mode = orig_mode;
	set_fs(old_fs);
	kunmap(page);
#ifdef WRAPFS_CRYPTO
	kfree(epage_data);
#endif
	if (err < 0) {
		printk(KERN_INFO "vfs_write failed\n");
		goto out;
	}
	/*
	 * checking if lower_file has inode and then assigning 
	 * lower_inode the inode from file.
	 */
	lower_inode = lower_file->f_path.dentry->d_inode;
	if (lower_inode != NULL) {
		lower_inode = wrapfs_lower_inode(inode);
	}
	BUG_ON(!lower_inode);
	BUG_ON(!inode);
	/* copying inode size and times */
	fsstack_copy_inode_size(inode, lower_inode);
	fsstack_copy_attr_times(inode, lower_inode);
	mark_inode_dirty_sync(inode);
out:
	if (err < 0)
		ClearPageUptodate(page);
	unlock_page(page);
	page_cache_release(page);
	return err;	

}

static int wrapfs_fault(struct vm_area_struct *vma, struct vm_fault *vmf)
{
	int err;
	struct file *file, *lower_file;
	const struct vm_operations_struct *lower_vm_ops;
	struct vm_area_struct lower_vma;

#ifdef DEBUG
	TRACK;
#endif
	memcpy(&lower_vma, vma, sizeof(struct vm_area_struct));
	file = lower_vma.vm_file;
	lower_vm_ops = WRAPFS_F(file)->lower_vm_ops;
	BUG_ON(!lower_vm_ops);

	lower_file = wrapfs_lower_file(file);
	/*
	 * XXX: vm_ops->fault may be called in parallel.  Because we have to
	 * resort to temporarily changing the vma->vm_file to point to the
	 * lower file, a concurrent invocation of wrapfs_fault could see a
	 * different value.  In this workaround, we keep a different copy of
	 * the vma structure in our stack, so we never expose a different
	 * value of the vma->vm_file called to us, even temporarily.  A
	 * better fix would be to change the calling semantics of ->fault to
	 * take an explicit file pointer.
	 */
	lower_vma.vm_file = lower_file;
	err = lower_vm_ops->fault(&lower_vma, vmf);
	return err;
}

/*
 * XXX: the default address_space_ops for wrapfs is empty.  We cannot set
 * our inode->i_mapping->a_ops to NULL because too many code paths expect
 * the a_ops vector to be non-NULL.
 */
const struct address_space_operations wrapfs_aops = {
	.readpage = wrapfs_readpage,
	.writepage = wrapfs_writepage,
	.write_begin = wrapfs_write_begin,
	.write_end = wrapfs_write_end,
};

const struct vm_operations_struct wrapfs_vm_ops = {
	.fault		= wrapfs_fault,
};
