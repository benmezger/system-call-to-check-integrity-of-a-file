#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <fcntl.h>
#include <string.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <openssl/md5.h>		
#include "sys_integrity.h"


extern int errno;

int main(int argc, char *argv[])
{
	
	int modeno,rc,i;
	
	struct mode1 m1;
	struct mode2 m2;
	struct mode3 m3;
	memset(&m1, 0, sizeof m1);
	memset(&m2, 0, sizeof m2);
	memset(&m3, 0, sizeof m3);
	if(argc<2)
	{
		printf("You have to enter a mode number and its corresponding arguements\n");
		return -1;
	}
	modeno=atoi(argv[1]);

	if(1==modeno)
	{

		m1.flag=(unsigned char)atoi(argv[1]);
		m1.filename=argv[2];
		m1.ibuf=(unsigned char *)malloc(16);
		bzero(m1.ibuf,16);
		m1.ilen=16;
		printf("User entered mode %d and the file name passed  to the system call is %s\n",m1.flag,m1.filename);
		rc=syscall(__NR_xintegrity,(void *) &m1);
		
		if(rc == 0)
		{
			printf("The system call returned %d\n",rc);
			printf("The integrity value of the file is ");
			for(i=0;i<16;i++)
				printf(" %x",m1.ibuf[i]);
			printf("\n");
		}
		else
			printf("The system call returned %d (errno=%d)\n",rc,errno);

		exit(rc);
	}
	else if (2==modeno)
	{
		m2.flag=(unsigned char)atoi(argv[1]);
		m2.filename=argv[2];
		m2.ibuf=(unsigned char *)malloc(16);
		bzero(m2.ibuf,16);
		m2.ilen=16;
		m2.credbuf=(unsigned char *)argv[3];
		if(m2.credbuf!=NULL)
			m2.clen=strlen(argv[3]);
		else
			m2.clen=0;
		printf("User entered mode %d, the file name passed to the system call is %s ,the password passed is %s\n",m2.flag,m2.filename,m2.credbuf);
		rc=syscall(__NR_xintegrity,(void *) &m2);
		
		if(rc == 0)
		{
			printf("The system call returned %d\n",rc);
			printf("The calculated integrity of the file is ");
			for(i=0;i<16;i++)
				printf(" %x",m2.ibuf[i]);
			printf("\n");
		}
		else
			printf("The system call returned %d (errno=%d)\n",rc,errno);

		exit(rc);


	}
	else if(3==modeno)
	{
		m3.flag=(unsigned char)atoi(argv[1]);
		m3.filename=argv[2];
		if(argv[3]!=NULL)
			m3.oflag=atoi(argv[3]);
		else
			m3.oflag=-1;
		if((64 & m3.oflag)==64)
			m3.mode=atoi(argv[4]);


		printf("User entered mode %d and the file name passed to the system call is  %s  and the oflag %d  \n",m3.flag,m3.filename,m3.oflag);
		rc=syscall(__NR_xintegrity,(void *) &m3);
		if(rc >= 0)
		{
			printf(" The system call returned %d\n",rc);
			
			exit(rc);
		}		
		else
		{
			printf(" The system call returned %d (errno=%d)\n",rc,errno);
			exit(rc);
		}
	}
	else
		printf("You have enter only one of modes 1, 2 or 3\n");

	return 0;
}

