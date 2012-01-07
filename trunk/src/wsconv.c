#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>

#include <sys/time.h>
#include <time.h>

//common types define
#define UINT32 unsigned int
#define INT32 signed int
#define UINT16 unsigned short
#define INT16 signed short
#define UINT8 unsigned char
#define INT8 signed char

//return value
#define RET_OK (0)
//error ret < 0
#define RET_UNKOWN_ERR (-1)
#define RET_PMT_ERR (-(100))
#define RET_NO_MEM (-101)
#define RET_IO_ERR (-102)
#define RET_UNDEF_VAL (-103)
#define RET_FMT_ERR (-104)

//version
#define VER_MAJOR 0
#define VER_MINOR 2

//mode
#define OPT_STR "m:vhq"

//buf size
#define PKT_MAX_SZ (3000)
#define SP_RD_BUF_SZ ((PKT_MAX_SZ)*3)
#define SP_WR_BUF_SZ ((PKT_MAX_SZ)+sizeof(pcap_pkt_hdr_t))

#define PCAP_DEF_PKT_GAP 100 //usecond

//help
#define TRY_HELP() fprintf(stderr,"Try premeter '-h' for help.\n")
#define HELP_STR "\
NAME:\n\
	wsconv - wireshark format converter\n\
\n\
SYNOPSIS:\n\
	wsconv [OPTION] IN_FILE OUT_FILE\n\
\n\
DESCRIPTION:\n\
	Convert packet format between strings and pcap to each other.\n\
\n\
OPTION:\n\
	-h\n\
		Print this help.\n\
	-v\n\
		Print version.\n\
	-m <MODE>\n\
		The mode of converting.The mode my be one of follows:\n\
		<sp>\n\
		Convert packet strings to pcap.\n\
		<bs>\n\
		Convert binary to packet strings, but it's not spported. try 'od -A n -t x IN_FILE'.\n\
	EMPTY\n\
		The same to '-m sp'.\n\
	-q\n\
		quiet mode, no prompt.\n\
\n\
IN_FILE:\n\
	File to read from.\n\
	1. the format is strict:\n\
	(1)packet string must be in HEX.\n\
	(2)packet end by empty line.\n\
	2. '-' means standard input.\n\
\n\
OUT_FILE:\n\
	File to write in.\n\
	1. '-' means standard output.\n\
\n\
AUTHOR:\n\
	Wu Shujie\n\
	Software Engineer\n\
	Cambridge Industries Group Ltd.\n\
	Office Addr:22/F,Qi Lai Building,No.889,Yi Shan Road,Shanghai\n\
	Email:sjwu@ci-g.com\n\
	Internal Mobile: 6231\n\
\n"

typedef struct conv_mod_st
{
	char src_fmt;
	char des_fmt;
	char * opt;
} conv_mod_t;

typedef struct cfg_st
{
	char * optstring;
	conv_mod_t conv_mod;
	char quiet;
	char * src_pth;
	char * des_pth;
} cfg_t;

typedef struct io_mgr_st
{
	FILE * prdfd;
	FILE * pwrfd;
	UINT8 * rd_buf;
	UINT32 rd_buf_sz;
	UINT8 * wr_buf;
	UINT32 wr_buf_sz;
} io_mgr_t;

typedef struct ver_st
{
	UINT32 major;
	UINT32 minor;
	char * bldtm;
} ver_t;

//wireshark pcap header
typedef struct pcap_hdr_st {
	UINT32 magic_number;   /* magic number */
	UINT16 version_major;  /* major version number */
	UINT16 version_minor;  /* minor version number */
	INT32  thiszone;       /* GMT to local correction */
	UINT32 sigfigs;        /* accuracy of timestamps */
	UINT32 snaplen;        /* max length of captured packets, in octets */
	UINT32 network;        /* data link type */
} pcap_hdr_t;

//wireshark pcaket header
typedef struct pcap_pkt_hdr_st {
	UINT32 ts_sec;         /* timestamp seconds */
	UINT32 ts_usec;        /* timestamp microseconds */
	UINT32 cap_len;       /* number of octets of packet saved in file */
	UINT32 pkt_len;       /* actual length of packet */
} pcap_pkt_hdr_t;

typedef struct pcap_fmt_st
{
	pcap_hdr_t pcap_hdr;
	pcap_pkt_hdr_t pcap_pkt_hdr;
} pcap_fmt_t;


typedef struct dataroot_st
{
	cfg_t * pcfg;
	io_mgr_t * pio_mgr;
	ver_t * pver;
	pcap_fmt_t * ppcap_fmt;
} dataroot_t;

typedef struct conv_stat_st
{
	//0x1 if file end, 0 no, 1 yes
	//0x2 if rd_buf has complete packet: 0 no, 1yes.
	UINT32 rd_fflag;
	UINT8 * rd_buf_ust; //used block start
	UINT32 rd_buf_ulen; //used block length.
	UINT32 rd_buf_lcpkt_end; //last complete pakct end offset.
	UINT32 wr_buf_ulen; //how many bytes used in wr_buf
	UINT32 wr_buf_pkt_count; //how many packets convert to bin
}conv_stat_t;

cfg_t cfg={
	.optstring=OPT_STR,
};
io_mgr_t io_mgr;
ver_t ver={
	.major=VER_MAJOR,
	.minor=VER_MINOR,
	.bldtm=BLDTM, //passed by gcc
};

static pcap_fmt_t pcap_fmt=
{
	{
		.magic_number = 0xa1b2c3d4,
		.version_major = 0x2,
		.version_minor = 0x4,
		.thiszone = 0x0,
		.sigfigs = 0x0,
		.snaplen = 0xffff,
		.network = 0x1,
	},
	{
		.ts_sec=0,
		.ts_usec=0,
		.cap_len=0,
		.pkt_len=0,
	}
};

static dataroot_t dataroot={
	.pcfg=&cfg,
	.pio_mgr=&io_mgr,
	.pver=&ver,
	.ppcap_fmt=&pcap_fmt,
};
dataroot_t * pdataroot=&dataroot;

//parse premeters
static int prmt_ps(int argc, char * argv[], cfg_t * pcfg);
//convert entry
static int conv_main(dataroot_t * pdataroot);
//print version
static int print_ver(void);
//print help
static int print_help(void);

//alloc mem, open file
static int conv_init(dataroot_t * pdataroot);
//free mem, close file
static int conv_exit(dataroot_t * pdataroot);
//read file to buf
static int conv_rd(cfg_t * pcfg, io_mgr_t * pio_mgr, conv_stat_t * pconv_stat);
//convert process
static int conv_do(dataroot_t * pdataroot, conv_stat_t * pconv_stat);
//write to file
static int conv_wr(cfg_t * pcfg, io_mgr_t * pio_mgr, conv_stat_t * pconv_stat);

//delete space and not HEX chars
static int conv_pproc(cfg_t * pcfg, io_mgr_t * pio_mgr, conv_stat_t * pconv_stat);

//err_op is action when (ret) is err. err_op can be func or oprator; err_op_obj can be value or label;
#define CHK_RET(ret, err_op, err_op_obj) \
do{\
	if((ret) < RET_OK)\
	{\
		err_op err_op_obj;\
	}\
}while(0)

#define GET_YES_OR_NO(def_val, in_char) \
do{\
	scanf("%c", &(in_char));\
	if((in_char) == '\n')\
	{\
		(in_char)=(def_val);\
		break;\
	}\
	if((in_char) == 'y' || (in_char) == 'n')\
		break;\
}while(1)

//hex check and convert
#define HEX_CHK_09(x) ((x)>='0' && (x)<='9')
#define HEX_CHK_af(x) ((x)>='a' && (x)<='f')
#define HEX_CHK_AF(x) ((x)>='A' && (x)<='F')
#define HEX_CHK(x) ((HEX_CHK_09(x)) || (HEX_CHK_af(x)) || (HEX_CHK_AF(x)))

#define HEX2BIN(hex, bin)\
do{\
	(bin)[0]=0x0;\
	if(HEX_CHK_09((hex)[1]))\
		(bin)[0]|=(hex)[1]-'0';\
	else if(HEX_CHK_af((hex)[1]))\
		(bin)[0]|=(hex)[1]-'a'+0xa;\
	else if(HEX_CHK_AF((hex)[1]))\
		(bin)[0]|=(hex)[1]-'A'+0xa;\
	if(HEX_CHK_09((hex)[0]))\
		(bin)[0]|=(((hex)[0]-'0')<<4);\
	else if(HEX_CHK_af((hex)[0]))\
		(bin)[0]|=(((hex)[0]-'a'+0xa)<<4);\
	else if(HEX_CHK_AF((hex)[0]))\
		(bin)[0]|=(((hex)[0]-'A'+0xa)<<4);\
}while(0)

#define PCAP_GEN_PKT_TS(ts_sec, ts_usec) \
do{\
	(ts_usec)+=PCAP_DEF_PKT_GAP;\
	if((ts_usec) >= 1000000)\
	{\
		(ts_usec)-=1000000;\
		(ts_sec)+=1;\
	}\
}while(0);

int main(int argc, char * argv[])
{
	int ret=RET_OK;

	ret=prmt_ps(argc, argv, pdataroot->pcfg);
	CHK_RET(ret, TRY_HELP(), );
	CHK_RET(ret, return, ret);

	ret=conv_main(pdataroot);
	CHK_RET(ret, TRY_HELP(), );
	CHK_RET(ret, return, ret);

	return RET_OK;
}

extern char *optarg;
extern int optind, opterr, optopt;
static int prmt_ps(int argc, char * argv[], cfg_t * pcfg)
{
	int optkey=0;

	//init
	pcfg->conv_mod.src_fmt='s';
	pcfg->conv_mod.des_fmt='p';
	pcfg->conv_mod.opt='\0';

	while((optkey=getopt(argc, argv, pcfg->optstring))!=-1)
	{
		switch(optkey)
		{
		case 'v':
			print_ver();
			exit(RET_OK);
		case 'h':
			print_help();
			exit(RET_OK);
		case 'q':
			pcfg->quiet='q';
			break;
		case 'm': //how to convert
			if(optopt == '?') //missing permeter of -m
			{
				CHK_RET(RET_PMT_ERR, return, (RET_PMT_ERR));
			}
			else
			{
				if(optarg[0]!='s'||optarg[1]!='p'||optarg[2]!='\0')
				{
					CHK_RET(RET_PMT_ERR, return, (RET_PMT_ERR));
				}
				pcfg->conv_mod.src_fmt=optarg[0];
				pcfg->conv_mod.des_fmt=optarg[1];
				pcfg->conv_mod.opt=&optarg[2];
			}
			break;
		default:
			//getopt will give error message.
			break;
		}
	}
	//here all options parsed
	if(optind+1 != argc-1) // 2 not optoin premeters
	{
		CHK_RET(RET_PMT_ERR, return, (RET_PMT_ERR));
	}
	else
	{
		pcfg->src_pth=argv[optind];
		pcfg->des_pth=argv[optind+1];
	}

	return RET_OK;
}

static int conv_main(dataroot_t * pdataroot)
{
	int ret=RET_OK;
	conv_stat_t conv_stat;

	memset(&conv_stat, 0, sizeof(conv_stat));
	conv_stat.rd_buf_ust=pdataroot->pio_mgr->rd_buf;

	ret=conv_init(pdataroot);
	CHK_RET(ret, goto, fatal_error);
	if(pdataroot->pcfg->conv_mod.src_fmt=='s' && pdataroot->pcfg->conv_mod.des_fmt=='p')
	{
		while((conv_stat.rd_fflag&0x1) != 0x1) //not read file to end
		{
			//read still rd_buf is full
			ret=conv_rd(pdataroot->pcfg, pdataroot->pio_mgr, &conv_stat);
			CHK_RET(ret, goto, fatal_error);

			//deal with by packet
			while((conv_stat.rd_fflag&0x2) == 0x2) //rd_buf have complete packet
			{
				ret=conv_do(pdataroot, &conv_stat);
				CHK_RET(ret, goto, fatal_error);

				if(conv_stat.wr_buf_ulen > 0)
				{
					ret=conv_wr(pdataroot->pcfg, pdataroot->pio_mgr, &conv_stat);
					CHK_RET(ret, goto, fatal_error);
				}
			}
		}
		//have no complete packet but rd_buf is still used. so there is uncomplete packet.
		if((conv_stat.rd_fflag&0x2) != 0x2 && conv_stat.rd_buf_ulen!=0)
		{
			fprintf(stderr, "WARNING: ignored uncomplete pakcet in file end!\n");
		}
	}

	//need to release
	fatal_error:
	ret=conv_exit(pdataroot);
	CHK_RET(ret, return, ret);

	return RET_OK;
}

static int print_ver(void)
{
	printf("Ver %u.%u build in %s\n",
		pdataroot->pver->major,
		pdataroot->pver->minor,
		pdataroot->pver->bldtm);
	return RET_OK;
}

static int print_help(void)
{
	printf("%s", HELP_STR);
	return RET_OK;
}

static int conv_init(dataroot_t * pdataroot)
{
	char in_char='\0';

	//open IN_FILE
	if(pdataroot->pcfg->src_pth[0] == '-')
	{
		pdataroot->pio_mgr->prdfd=stdin;
	}
	else
	{
		pdataroot->pio_mgr->prdfd=fopen(pdataroot->pcfg->src_pth, "r");
		if(pdataroot->pio_mgr->prdfd==NULL)
		{
			perror("open IN_FILE error: ");
			return RET_IO_ERR;
		}
	}
	//open OUT_FILE
	if(pdataroot->pcfg->des_pth[0] == '-')
	{
		pdataroot->pio_mgr->pwrfd=stdout;
	}
	else
	{
		if(pdataroot->pcfg->quiet!='q' && access(pdataroot->pcfg->des_pth, F_OK)==0) //OUT_FILE exsits.
		{
			fprintf(stderr, "WARNING: OUT_FILE %s already exsits, overwrite?(y/n)[n]:", pdataroot->pcfg->des_pth);
			GET_YES_OR_NO('n', in_char);
			if(in_char == 'n')
				return RET_IO_ERR;
		}
		pdataroot->pio_mgr->pwrfd=fopen(pdataroot->pcfg->des_pth, "w");
		if(pdataroot->pio_mgr->pwrfd==NULL)
		{
			perror("ERROR: open OUT_FILE: ");
			return RET_IO_ERR;
		}
	}

	//alloc buf
	pdataroot->pio_mgr->rd_buf=malloc(SP_RD_BUF_SZ);
	if(pdataroot->pio_mgr->rd_buf==NULL)
	{
		perror("ERROR: mem allocate:");
		return RET_NO_MEM;
	}
	pdataroot->pio_mgr->rd_buf_sz=SP_RD_BUF_SZ;

	pdataroot->pio_mgr->wr_buf=malloc(SP_WR_BUF_SZ);
	if(pdataroot->pio_mgr->wr_buf==NULL)
	{
		perror("ERROR: mem allocate:");
		return RET_NO_MEM;
	}
	pdataroot->pio_mgr->wr_buf_sz=SP_WR_BUF_SZ;

	return RET_OK;
}

static int conv_exit(dataroot_t * pdataroot)
{
	if(pdataroot->pio_mgr->prdfd != NULL)
	{
		fclose(pdataroot->pio_mgr->prdfd);
	}

	if(pdataroot->pio_mgr->pwrfd != NULL)
	{
		fclose(pdataroot->pio_mgr->pwrfd);
	}

	if(pdataroot->pio_mgr->rd_buf != NULL)
	{
		free(pdataroot->pio_mgr->rd_buf);
	}

	if(pdataroot->pio_mgr->wr_buf != NULL)
	{
		free(pdataroot->pio_mgr->wr_buf);
	}

	return RET_OK;
}

static int conv_rd(cfg_t * pcfg, io_mgr_t * pio_mgr, conv_stat_t * pconv_stat)
{
	int i=0;
	int ret=RET_OK;

	while((pconv_stat->rd_fflag&0x2) != 0x2) //rd_buf have no complete packet
	{
		if((pconv_stat->rd_fflag&0x1)==0x1) //file end
		{
			fprintf(stderr, "ERROR: Uncomplete packet end\n");
			TRY_HELP();
			return RET_FMT_ERR;
		}

		if(pconv_stat->rd_buf_ulen > (PKT_MAX_SZ*2+4)) //too larger packet string
		{
			fprintf(stderr, "ERROR: Packet size is too larger! more than %u bytes.\n", PKT_MAX_SZ);
			TRY_HELP();
			return RET_FMT_ERR;
		}

		//move used block to top of rd_buf.
		if(pio_mgr->rd_buf!=pconv_stat->rd_buf_ust && pconv_stat->rd_buf_ulen!=0)
		{
			for(i=0; i < pconv_stat->rd_buf_ulen; i++)
			{
				pio_mgr->rd_buf[i]=pconv_stat->rd_buf_ust[i];
			}
		}
		pconv_stat->rd_buf_ust=pio_mgr->rd_buf;

		//read file to buf
		pconv_stat->rd_buf_ulen += fread(pio_mgr->rd_buf + pconv_stat->rd_buf_ulen,
			1, pio_mgr->rd_buf_sz-1 - pconv_stat->rd_buf_ulen, pio_mgr->prdfd);
		if(pconv_stat->rd_buf_ulen < pio_mgr->rd_buf_sz-1)
		{
			pconv_stat->rd_fflag|=0x1; //file end
		}
		pio_mgr->rd_buf[pconv_stat->rd_buf_ulen]='\0';

		ret=conv_pproc(pcfg, pio_mgr, pconv_stat);
		CHK_RET(ret, return, ret);
	}

	return RET_OK;
}

static int conv_do(dataroot_t * pdataroot, conv_stat_t * pconv_stat)
{
	UINT32 uind=0;
	UINT32 pkt_len=0;
	UINT32 pcap_pkt_hdr_os=0; //packet header offset
	UINT32 pcap_pkt_os=0;

	if(pconv_stat->wr_buf_pkt_count==0)
	{
		//file pcap header
		memcpy(pdataroot->pio_mgr->wr_buf, &pdataroot->ppcap_fmt->pcap_hdr, sizeof(pcap_hdr_t));
		pcap_pkt_hdr_os=sizeof(pcap_hdr_t);
	}
	pcap_pkt_os = pcap_pkt_hdr_os+sizeof(pcap_pkt_hdr_t);
	pconv_stat->wr_buf_ulen=pcap_pkt_os;

	//convert 1 packet
	uind = 0;
	while(1)
	{
		//current location over last complete paket
		if(&pconv_stat->rd_buf_ust[uind] >= &pdataroot->pio_mgr->rd_buf[pconv_stat->rd_buf_lcpkt_end])
		{
			pconv_stat->rd_fflag&=(~0x2); //set to no complete packet in rd_buf
			pconv_stat->wr_buf_ulen=0; //no bin out
			return RET_OK;
		}

		if(pconv_stat->rd_buf_ust[uind]=='\n' && pconv_stat->rd_buf_ust[uind+1]=='\n') //packet end
		{
			uind+=2;
			pconv_stat->rd_buf_ulen-=uind;
			pconv_stat->rd_buf_ust+=uind;
			pconv_stat->wr_buf_pkt_count+=1;

			//fill pcap packet header
			PCAP_GEN_PKT_TS(pdataroot->ppcap_fmt->pcap_pkt_hdr.ts_sec, pdataroot->ppcap_fmt->pcap_pkt_hdr.ts_usec);
			pkt_len = pconv_stat->wr_buf_ulen-pcap_pkt_os;
			if(pkt_len < pdataroot->ppcap_fmt->pcap_hdr.snaplen)
			{
				pdataroot->ppcap_fmt->pcap_pkt_hdr.cap_len=pkt_len;
			}
			else
			{
				pdataroot->ppcap_fmt->pcap_pkt_hdr.cap_len=pdataroot->ppcap_fmt->pcap_hdr.snaplen;
			}
			pdataroot->ppcap_fmt->pcap_pkt_hdr.pkt_len=pkt_len;
			memcpy(&pdataroot->pio_mgr->wr_buf[pcap_pkt_hdr_os], &pdataroot->ppcap_fmt->pcap_pkt_hdr, sizeof(pcap_pkt_hdr_t));

			return RET_OK;
		}
		else if(pconv_stat->rd_buf_ust[uind]=='\0' || pconv_stat->rd_buf_ust[uind+1]=='\0')
		{
			fprintf(stderr, "ERROR: uncomplete packet!\n");
			return RET_FMT_ERR;
		}

		//convert hex to bin
		HEX2BIN(&pconv_stat->rd_buf_ust[uind], &(pdataroot->pio_mgr->wr_buf[pconv_stat->wr_buf_ulen]));
		pconv_stat->wr_buf_ulen+=1;
		uind+=2;
	}

	return RET_OK;
}

static int conv_wr(cfg_t * pcfg, io_mgr_t * pio_mgr, conv_stat_t * pconv_stat)
{
	UINT32 len;

	if(pcfg->conv_mod.src_fmt=='s' && pcfg->conv_mod.des_fmt=='p')
	{
		len=fwrite(pio_mgr->wr_buf, 1, pconv_stat->wr_buf_ulen, pio_mgr->pwrfd);
		if(len != pconv_stat->wr_buf_ulen)
		{
			return RET_IO_ERR;
		}
	}
	else
	{
		fprintf(stderr, "%s on this format undefined!\n", __FUNCTION__);
		return RET_UNDEF_VAL;
	}

	return RET_OK;
}

static int conv_pproc(cfg_t * pcfg, io_mgr_t * pio_mgr, conv_stat_t * pconv_stat)
{
	UINT32 i=0;
	UINT32 del_count=0;
	UINT32 nl_count=0;

	if(pcfg->conv_mod.src_fmt=='s' && pcfg->conv_mod.des_fmt=='p')
	{
		//delete not (HEX and '\n')
		for(i=0; i <= pconv_stat->rd_buf_ulen; i++) //becareful, i will reach '\0';
		{
			if(pio_mgr->rd_buf[i] == '\n') //count '\n'
			{
				nl_count++;
			}
			else if(!(HEX_CHK(pio_mgr->rd_buf[i]) || pio_mgr->rd_buf[i]=='\0')) //not HEX or '\n' or '\0'
			{
				del_count++;
			}
			else if(nl_count>0) //here it must be HEX, check '\n' counter
			{
				del_count += nl_count;
				if(nl_count>=2) //packet end
				{
					pconv_stat->rd_fflag|=0x2; //rd_buf have complete packet;
					//del \n\n... to \n\n
					pio_mgr->rd_buf[i-del_count]='\n';
					pio_mgr->rd_buf[i-del_count+1]='\n';
					del_count-=2;
					pconv_stat->rd_buf_lcpkt_end=i-del_count; //the last pkt end
				}
				pio_mgr->rd_buf[i-del_count]=pio_mgr->rd_buf[i];
				nl_count=0;
			}
			else //no '\n' before, here is just HEXs.
			{
				pio_mgr->rd_buf[i-del_count]=pio_mgr->rd_buf[i];
			}
		}
		pconv_stat->rd_buf_ulen-=del_count;
	}
	else
	{
		fprintf(stderr, "%s on this format undefined!\n", __FUNCTION__);
		return RET_UNDEF_VAL;
	}

	return RET_OK;
}

