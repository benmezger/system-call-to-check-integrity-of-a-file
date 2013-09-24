#define __NR_xintegrity	349


struct mode1
{
	unsigned char flag;
	const char *filename;
	unsigned char *ibuf;
	unsigned int ilen;
};

struct mode2
{
	unsigned char flag;
	const char *filename;
	unsigned char *ibuf;
	unsigned int ilen;
	unsigned char *credbuf;
	unsigned int clen;
};

struct mode3
{
	unsigned char flag;
	const char *filename;
	int oflag;
	int mode;
};



