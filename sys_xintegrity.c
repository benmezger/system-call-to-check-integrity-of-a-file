#include <linux/linkage.h>
#include <linux/moduleloader.h>
#include <linux/err.h>
#include <linux/slab.h>
#include <linux/uaccess.h>
#include <linux/crypto.h>
#include <linux/compiler.h>
#include <linux/scatterlist.h>
#include <linux/xattr.h>
#include <linux/highmem.h>
#include <linux/moduleparam.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/file.h>
#include <linux/module.h>
#include <crypto/hash.h>
#include <linux/fs.h>
#include <linux/string.h>
#include <linux/types.h>
#include "sys_integrity.h"

asmlinkage extern long (*sysptr)(void *arg);


static int init_desc(struct hash_desc *desc)
{
	int rc;
	desc->tfm=crypto_alloc_hash("md5",0,CRYPTO_ALG_ASYNC);
	if(IS_ERR(desc->tfm))
	{
		printk("failed to load\n");
		rc=PTR_ERR(desc->tfm);
		return rc;
	}
	desc->flags=0;
	rc=crypto_hash_init(desc);
	if(rc)
		crypto_free_hash(desc->tfm);
	return rc;
}

asmlinkage long xintegrity(void *arg)
{
	int j,xattr=0,z;
	loff_t i_size,offset=0;
	unsigned char c;
	char *pswd="secretpswd";
	char *rbuf=NULL;
	unsigned char *digest=NULL;
	unsigned char *buf=NULL;
	int fd,rc,err,rbuf_len;
	struct scatterlist sg[1];

	struct hash_desc desc;
	
	struct file *filp,*f;
	struct mode1 *m1;
	struct mode2 *m2;
	struct mode3 *m3; 
	if (arg == NULL)
	{
		return -EINVAL;	
	}

	if(!access_ok(VERIFY_READ,arg,sizeof(unsigned char)))
	{
		printk("Pointer to the starting block of memory in user space is invalid\n");
		return -EACCES;	
	}

	if(copy_from_user(&c,arg,sizeof(unsigned char)))
	{
		printk("Error copying from the user space\n");
		return -EFAULT;

	}

	if(1==c)
	{

		if(!access_ok(VERIFY_READ,(struct mode1 *)arg,sizeof(struct mode1)))
		{
			printk("Pointer to starting block of memory of mode1 is invalid\n");
			return -EACCES;

		}
		m1=kmalloc(sizeof(struct mode1),GFP_KERNEL);
		if(NULL==m1)
		{
			printk("There is no kernel memory available\n");

			return -ENOMEM;

		}

		if(((struct mode1 *)arg)->filename==NULL)
		{
			printk("The user passed the filename as NULL\n");
			kfree(m1);
			return -EINVAL;
		}
		if(0==((struct mode1 *)arg)->ilen)
		{
			printk("The user passed an ilen of zero\n");
			kfree(m1);
			return -EINVAL;
		}
		if(copy_from_user(m1,(struct mode1 *)arg,sizeof(struct mode1)))
		{
			printk("Error copying mode 1 structure from user space\n");

			kfree(m1);

			return -EFAULT;
		}



		if(!access_ok(VERIFY_READ,((struct mode1 *)arg)->filename,strlen(((struct mode1 *)arg)->filename)))
		{

			printk("Pointer to filename is invalid\n");
			kfree(m1);
			return -EACCES;

		}
		m1->filename=getname(((struct mode1 *)arg)->filename);
		if(m1->filename==NULL)
		{
			printk("There is no kernel memory available\n");

			kfree(m1);

			return PTR_ERR(m1->filename);
		}

		if(m1->ilen==0)
		{
			printk("Invalid ilen,ilen was passed as 0\n");

			putname(m1->filename);
			kfree(m1);
			return -EINVAL;
		}
		if(((struct mode1 *)arg)->ibuf==NULL)
		{
			printk("ibuf passed is null\n");
			putname(m1->filename);
			kfree(m1);
			return -EFAULT;
		}

		if(!access_ok(VERIFY_WRITE,((struct mode1 *)arg)->ibuf,16))
		{
			printk("Pointer to ibuf is invalid\n");
			putname(m1->filename);
			kfree(m1);
			return -EACCES;
		}

		m1->ibuf=kmalloc(16,GFP_KERNEL);
		if(m1->ibuf==NULL)
		{
			printk("There is no kernel memory\n");
			putname(m1->filename);
			kfree(m1);
			return -ENOMEM;

		}
		if(copy_from_user(m1->ibuf,((struct mode1 *)arg)->ibuf,16))
		{
			kfree(m1->ibuf);
			putname(m1->filename);
			kfree(m1);
			printk("Error copying ibuf from user space");
			return -EFAULT;
		}


		filp=filp_open(m1->filename,O_RDONLY,0);

		if(!filp || IS_ERR(filp))
		{
			kfree(m1->ibuf);
			putname(m1->filename);
			kfree(m1);
			printk("wraps_read_file err %d\n",(int)PTR_ERR(filp));
			return -1;
		}

		if(!filp->f_op->read)
		{
			printk("file does not allow reads\n");
			kfree(m1->ibuf);
			putname(m1->filename);
			kfree(m1);
			filp_close(filp,NULL);

			return -2;
		}
		xattr=vfs_getxattr(filp->f_path.dentry,"user.md5check",m1->ibuf,16);

		if(!xattr || xattr<0)
		{
			printk("Error in retrieving the integrity value using vfs_getxattr \n");
			kfree(m1->ibuf);
			putname(m1->filename);
			kfree(m1);
			return -EFAULT;
		}

		if(copy_to_user(((struct mode1 *)arg)->ibuf,m1->ibuf,16))
		{
			kfree(m1->ibuf);
			putname(m1->filename);
			kfree(m1);
			return -EFAULT;
		}
		printk("The value in ibuf is ");
		for(j=0;j<16;j++)
			printk(" %x",((struct mode1 *)arg)->ibuf[j]);
		printk("\n");
		
		kfree(m1->ibuf);
		putname(m1->filename);
		kfree(m1);
		filp_close(filp,NULL);

		return 0;
	} 
	else if(2==c)
	{
		if(!access_ok(VERIFY_READ,(struct mode2 *)arg,sizeof(struct mode2)))
		{
			printk("Pointer to starting block of memory of mode2 is invalid\n");
			return -EACCES;

		}
		m2=kmalloc(sizeof(struct mode2),GFP_KERNEL);
		if(NULL==m2)
		{
			printk("There is no kernel memory available\n");
			return -ENOMEM;

		}
		if(((struct mode2 *)arg)->filename==NULL) 
		{
			printk("The user passed an invalid filename\n");
			kfree(m2);
			return -EINVAL;
		}

		if(0==((struct mode2 *)arg)->ilen)
		{
			printk("The user passed an ilen of zero\n");
			kfree(m2);
			return -EINVAL;
		}

		if(0==((struct mode2 *)arg)->clen)
		{
			printk("The user passed a clen of zero\n");
			kfree(m2);
			return -EINVAL;
		}


		if(((struct mode2 *)arg)->credbuf==NULL)
		{
			printk("The user passed a NULL password\n");
			kfree(m2);
			return -EINVAL;
		}

		if(copy_from_user(m2,(struct mode2 *)arg,sizeof(struct mode2)))
		{
			printk("Error copying from user space\n");
			kfree(m2);
			return -EFAULT;
		}

		if(!access_ok(VERIFY_READ,((struct mode2 *)arg)->filename,strlen(((struct mode2 *)arg)->filename)))
		{
			printk("Pointer to filename in user space is invalid\n");
			kfree(m2);
			return -EACCES;

		}
		m2->filename=getname(((struct mode2 *)arg)->filename);
		
		if(m2->filename==NULL)
		{
			printk("There is no kernel memory available\n");
			kfree(m2);
			return -EFAULT;
		}

		if(!access_ok(VERIFY_WRITE,((struct mode2 *)arg)->ibuf,16))
		{
			printk("Pointer to the ibuf is invalid\n");
			putname(m2->filename);
			kfree(m2);
			return -EACCES;
		}

		m2->ibuf=kmalloc(16,GFP_KERNEL);
		if(m2->ibuf==NULL)
		{
			printk("There is no kernel memory available\n");
			putname(m2->filename);
			
			kfree(m2);
			return -ENOMEM;

		}
		if(copy_from_user(m2->ibuf,((struct mode2 *)arg)->ibuf,16))
		{
			printk("Error copying ibuf from user space\n");
			kfree(m2->ibuf);
			putname(m2->filename);
			kfree(m2);
			return -EFAULT;
		}
		if(!access_ok(VERIFY_READ,((struct mode2 *)arg)->credbuf,strlen(((struct mode2 *)arg)->credbuf)))
		{
			printk("Pointer to password is invalid\n");
			kfree(m2->ibuf);
			putname(m2->filename);
			kfree(m2);
			return -EACCES;

		}
		m2->credbuf=getname(((struct mode2 *)arg)->credbuf);

		if(m2->credbuf==NULL)
		{
			printk("There is no kernel memory available\n");
			kfree(m2->ibuf);
			putname(m2->filename);
			kfree(m2);

			return -ENOMEM;

		}
		
		if(strlen(m2->credbuf)!=m2->clen)
		{
			printk("Credential buffer size and the length specified by the user don't match\n");
			putname(m2->credbuf);
			kfree(m2->ibuf);
			putname(m2->filename);
			kfree(m2);
		}

		if(strcmp(pswd,m2->credbuf))
		{
			printk("You have given the wrong password and hence are not allowed to compute the integrity of the file\n");
			putname(m2->credbuf);
			kfree(m2->ibuf);
			putname(m2->filename);
			kfree(m2);
			return -EPERM;
		}


		filp=filp_open(m2->filename,O_RDONLY,0);

		if(!filp || IS_ERR(filp))
		{
			printk("wraps_read_file err %d\n",(int)PTR_ERR(filp));
			kfree(m2->ibuf);
			putname(m2->filename);
			putname(m2->credbuf);
			kfree(m2);
			return -1;
		}
		if(!filp->f_op->write)
		{
			printk("file does not allow reads\n");
			kfree(m2->ibuf);
			putname(m2->filename);
			putname(m2->credbuf);
			kfree(m2);
			filp_close(filp,NULL);
			return -2;
		}

		rc=init_desc(&desc);

		if(rc)
		{
			printk("Error initializing crypto hash; rc=[%d]\n",rc);
			kfree(m2->ibuf);
			putname(m2->filename);
			putname(m2->credbuf);
			kfree(m2);
			filp_close(filp,NULL);
			return rc;
		}
		rbuf=kzalloc(PAGE_SIZE,GFP_KERNEL);
		digest=kmalloc(16,GFP_KERNEL);
		if(!rbuf)
		{
			crypto_free_hash(desc.tfm);
			kfree(m2->ibuf);
			kfree(digest);
			kfree(rbuf);
			putname(m2->filename);
			putname(m2->credbuf);
			kfree(m2);
			filp_close(filp,NULL);
			return -ENOMEM;

		}
		i_size=i_size_read(filp->f_dentry->d_inode);


		while(offset<i_size)

		{

			rbuf_len=kernel_read(filp,offset,rbuf,PAGE_SIZE);
			if(rbuf_len<0)
			{
				printk("rbuf_len is less than 0\n");
				rc=rbuf_len;
				break;

			}
			if(rbuf_len==0)
			{
				printk("rbuflen is zero\n");
				break;
			}
			offset+=rbuf_len;
			sg_init_one(sg,rbuf,rbuf_len);
			rc=crypto_hash_update(&desc,sg,rbuf_len);
			if(rc)
			{
				
				crypto_free_hash(desc.tfm);
				kfree(m2->ibuf);
				putname(m2->filename);
				putname(m2->credbuf);

				kfree(m2);
				kfree(rbuf);
				kfree(digest);
				filp_close(filp,NULL);
				return rc;

			}

		}
		kfree(rbuf);
		if(!rc)
			rc=crypto_hash_final(&desc,digest);
		if(rc)
		{
			printk("Error in computing crypto hash\n");

			crypto_free_hash(desc.tfm);

			putname(m2->filename);
			putname(m2->credbuf);
			kfree(m2->ibuf);
			kfree(m2);
			kfree(digest);
			filp_close(filp,NULL);
			return rc;

		}
		err=vfs_setxattr(filp->f_path.dentry,"user.md5check",digest,16,0);
		if(err<0)
		{
			printk("The value of err is %d\n",err);
			printk("Error in setting attribute \n");
			kfree(digest);
			kfree(m2->ibuf);
			putname(m2->filename);
			putname(m2->credbuf);
			kfree(m2);
			filp_close(filp,NULL);
			return -EFAULT;
		}


		xattr=vfs_getxattr(filp->f_path.dentry,"user.md5check",m2->ibuf,16);
		if(xattr==0)
		{
			printk("Error in retrieving attribute\n");
			kfree(digest);
			kfree(m2->ibuf);
			putname(m2->filename);
			putname(m2->credbuf);
			kfree(m2);
			filp_close(filp,NULL);
			return -EFAULT;


		}

		if(copy_to_user(((struct mode2 *)arg)->ibuf,m2->ibuf,16))
		{

			kfree(m2->ibuf);
			putname(m2->filename);
			putname(m2->credbuf);
			kfree(m2);
			kfree(digest);
			filp_close(filp,NULL);
			return -EFAULT;
		}

		kfree(m2->ibuf);
		putname(m2->filename);
		putname(m2->credbuf);
		kfree(m2);
		kfree(digest);
		filp_close(filp,NULL);

		return 0;
	}




	else if(3==c)
	{

		if(!access_ok(VERIFY_READ,(struct mode3 *)arg,sizeof(struct mode3)))
		{
			printk("Pointer to starting block of memory of mode3 is invalid\n");
			return -EACCES;

		}
		m3=kmalloc(sizeof(struct mode3),GFP_KERNEL);
		if(NULL==m3)
		{
			printk("No memory for structure\n");
			return -ENOMEM;

		}
		if(((struct mode3 *)arg)->filename==NULL)
		{
			printk("The user passed an invalid filename\n");
			kfree(m3);
			return -EINVAL;
		}
		if(((struct mode3 *)arg)->oflag<0)
		{
			printk("The user passed an invalid oflag\n");
			kfree(m3);
			return -EINVAL;
		}
		if(copy_from_user(m3,(struct mode3 *)arg,sizeof(struct mode3)))
		{
			printk("Error copying structure\n");

			kfree(m3);

			return -EFAULT;
		}


		if(!access_ok(VERIFY_READ,((struct mode3 *)arg)->filename,strlen(((struct mode3 *)arg)->filename)))
		{

			printk("Pointer to filename is invalid\n");
			kfree(m3);
			return -EACCES;


		}
		m3->filename=getname(((struct mode3 *)arg)->filename);
		if(m3->filename==NULL)
		{

			printk("There is no kernel memory available\n");
			kfree(m3);
			return -ENOMEM;


		}

		buf=kmalloc(16,GFP_KERNEL);

		if(buf==NULL)
		{
			printk("There is no kernel memory available\n");
			putname(m3->filename);
			kfree(m3);
			return -ENOMEM;

		}

		filp=filp_open(m3->filename,O_RDONLY,0);


		if(!filp || IS_ERR(filp))
		{

			printk("wraps_read_file err %d\n",(int)PTR_ERR(filp));

			if((64 & m3->oflag)==64)
				goto opening;
			else
			{
				putname(m3->filename);
				kfree(m3);
				kfree(buf);

				return -1;

			}


		}


		xattr=vfs_getxattr(filp->f_path.dentry,"user.md5check",buf,16);

		if(!xattr || xattr<0)
		{
			printk("The getxattr does not return any attribute \n");
			putname(m3->filename);
			kfree(m3);
			kfree(buf);
			filp_close(filp,NULL);
			return -EFAULT;


		}


		for (z = 0; z <16; z++)
			printk(" %x", buf[z]);
		printk("\n");
		rc=init_desc(&desc);


		if(rc!=0)
		{
			printk("Error initializing crypto hash; rc=[%d]\n",rc);
			crypto_free_hash(desc.tfm);
			kfree(buf);
			putname(m3->filename);
			kfree(m3);
			filp_close(filp,NULL);
			return rc;

		}




		rbuf=kzalloc(PAGE_SIZE,GFP_KERNEL);





		if(!rbuf)
		{
			crypto_free_hash(desc.tfm);


			kfree(buf);
			putname(m3->filename);
			kfree(m3);
			kfree(rbuf);
			filp_close(filp,NULL);
			return -ENOMEM;

		}

		digest=kmalloc(16,GFP_KERNEL);


		i_size=i_size_read(filp->f_dentry->d_inode);



		while(offset<i_size)

		{

			rbuf_len=kernel_read(filp,offset,rbuf,PAGE_SIZE);
			if(rbuf_len<0)
			{
				printk("rbuf_len is less than 0\n");
				rc=rbuf_len;
				break;

			}
			if(rbuf_len==0)
			{
				printk("rbuflen is zero\n");
				break;
			}
			offset+=rbuf_len;
			sg_init_one(sg,rbuf,rbuf_len);

			rc=crypto_hash_update(&desc,sg,rbuf_len);
			if(rc)
			{
				
				kfree(buf);
				putname(m3->filename);
				kfree(m3);
				kfree(rbuf);
				kfree(digest);
				filp_close(filp,NULL);
				return rc;

			}

		}
		kfree(rbuf);
		if(!rc)
			rc=crypto_hash_final(&desc,digest);



		crypto_free_hash(desc.tfm);

		filp_close(filp,NULL);


		if(memcmp(digest,buf,16))
		{
			printk("The checksum of the file does not match the stored checksum and hence your file has been modified\n");
			kfree(buf);
			putname(m3->filename);
			kfree(m3);

			kfree(digest);
			return -EPERM;	

		}
		printk("The existing md5 value and the newly computed value match\n");
		opening:
		fd=get_unused_fd();
		f=filp_open(m3->filename,m3->oflag,m3->mode);
		fd_install(fd,f);
		kfree(buf);
		putname(m3->filename);
		kfree(m3);

		kfree(digest);
		return fd;



	}

	return 0;
}


static int __init init_sys_xintegrity(void)
{
	printk("installed new sys_xintegrity module\n");
	if (sysptr == NULL)
		sysptr = xintegrity;

	return 0;
}


static void  __exit exit_sys_xintegrity(void)
{
	if (sysptr != NULL)
		sysptr = NULL;
	printk("removed sys_xintegrity module\n");
}
module_init(init_sys_xintegrity);
module_exit(exit_sys_xintegrity);
MODULE_LICENSE("GPL");

