#include<Windows.h>
#include<stdio.h>
#include<conio.h>
#include<random>
#include<math.h>
/*
		//2.207989 MHz 0.452900807023948 us
		//bits		overflow in
		//8			0.115942606598131 ms
		//10		0.463770426392523 ms		2156.2392578125 Hz
		//16		29.6813072891215 ms			33.6912384033202 times per second
		//32		32.4199025749977 minutes
		//64		264739.564413875 years	???

http://stackoverflow.com/questions/30473376/can-i-generate-cryptographically-secure-random-data-from-a-combination-of-random
MT19937 is insecure		 32bit seed		2 QPC throws
AES-CTR					128bit key		8 QPC throws

press 8 times, build key
when key is complete, start showing sequence
while user presses more, build new key
when new key is complete reset sequence with new key

taking any deterministic function of a random variable does not make it more random

1000bits worth of passwords generated using a 16bit true ND seed is like a single 16bit password
each new 16 output bits must be affected by new 16 true ND input bits
but user wants a sea of randomness with a few presses?
parallel channels	choose a channel
//*/

//QPC AES ^ stdlib rand(QPC)
#if 1
class	AES
{
	static unsigned char (*key)[4][4], Dkey[11][4][4];
	static unsigned char mult_gf_2_8(unsigned char a, unsigned char b);
	static unsigned char mult_by_4_gf_2_8(unsigned char x){return mult_by_2[mult_by_2[x]];}
	static unsigned char mult_by_8_gf_2_8(unsigned char x){return mult_by_2[mult_by_2[mult_by_2[x]]];}
	static int leftmost_up_bit_pos(int x);
	static int mult_gf_2(int a, int b);
	static int divide_gf_2(int a, int b, int *r);
	static bool mult_inv_gf_2_8(unsigned char x, unsigned char &x_1);
	static void s_box_step_4(unsigned char &x);
	static void s_box_1_step_3(unsigned char &x);
	static void add_round_key(int round);
	static void substitute_bytes();
	static void inverse_sub_bytes();
	static void shift_rows();
	static void inverse_shift_rows();
	static void mix_columns();
	static void inverse_mix_columns();
public:
	static unsigned char s_box[256], s_box_1[256], mult_by_2[256], x_pow_i_4_1[11];
	static unsigned int DK0[256], DK1[256], DK2[256], DK3[256], E0[256], E1[256], E2[256], E3[256], SBS8[256], SBS16[256], SBS24[256], D0[256], D1[256], D2[256], D3[256], SB1S8[256], SB1S16[256], SB1S24[256];
	static void initiate();
	static void expand_key(unsigned char *key);
	static void encrypt(unsigned char *text);
	static void encrypt(unsigned char *text, unsigned char *key);
	static void decrypt(unsigned char *text);
	static void decrypt(unsigned char *text, unsigned char *key);
};
unsigned char	AES::s_box[256], AES::s_box_1[256], AES::mult_by_2[256], AES::x_pow_i_4_1[11];
unsigned int	AES::DK0[256], AES::DK1[256], AES::DK2[256], AES::DK3[256], AES::E0[256], AES::E1[256], AES::E2[256], AES::E3[256], AES::SBS8[256], AES::SBS16[256], AES::SBS24[256], AES::D0[256], AES::D1[256], AES::D2[256], AES::D3[256], AES::SB1S8[256], AES::SB1S16[256], AES::SB1S24[256];
unsigned char	(*AES::key)[4][4], AES::Dkey[11][4][4];
unsigned char	AES::mult_gf_2_8(unsigned char a, unsigned char b)
{
	int result=0;
	for(int k=0;k<8;++k)
	{
		if(b&1<<k)
			result^=a;
		a=a&0x80?a<<1^0x1B:a<<1;
	}
	return result;
}
int			AES::leftmost_up_bit_pos(int x)
{
	int k=31;
	for(;k>=0;--k)
		if(x&1<<k)
			break;
	return k;
}
int			AES::mult_gf_2(int a, int b)
{
	int result=0;
	for(int k=0;k<32;++k)
		if(b&1<<k)
			result^=a<<k;
	return result;
}
int			AES::divide_gf_2(int a, int b, int *r=0)
{
	int q=0;
	for(int xb=leftmost_up_bit_pos(b);a>=b;)
	{
		int xa_b=leftmost_up_bit_pos(a)-xb;
		q^=1<<xa_b, a^=b<<xa_b;
	}
	if(r)
		*r=a;
	return q;
}
bool		AES::mult_inv_gf_2_8(unsigned char x, unsigned char &x_1)
{
	int Q, A[3]={1, 0, 0x11B}, B[3]={0, 1, x}, T[3];
	for(;B[2]!=1&&B[2]!=0;)
	{
		Q=divide_gf_2(A[2], B[2]);
		T[0]=A[0], T[1]=A[1], T[2]=A[2];
		A[0]=B[0], A[1]=B[1], A[2]=B[2];
		B[0]=T[0]^mult_gf_2(Q, B[0]), B[1]=T[1]^mult_gf_2(Q, B[1]), B[2]=T[2]^mult_gf_2(Q, B[2]);
	}
	if(B[2])
	{
		x_1=B[1];
		return true;
	}
	return false;
}
void		AES::s_box_step_4(unsigned char &x)
{
	int result=0, c=0x63;
	for(int k=0;k<8;++k)
		result^=(x>>k&1^x>>(k+4)%8&1^x>>(k+5)%8&1^x>>(k+6)%8&1^x>>(k+7)%8&1^c>>k&1)<<k;
	x=result;
}
void		AES::s_box_1_step_3(unsigned char &x)
{
	int result=0, d=0x05;
	for(int k=0;k<8;++k)
		result^=(x>>(k+2)%8&1^x>>(k+5)%8&1^x>>(k+7)%8&1^d>>k&1)<<k;
	x=result;
}
void		AES::initiate()
{
	for(int k=0;k<256;++k)
	{
		s_box[k]=k;
		mult_inv_gf_2_8(s_box[k], s_box[k]);
		s_box_step_4(s_box[k]);

		s_box_1[k]=k;
		s_box_1_step_3(s_box_1[k]);
		mult_inv_gf_2_8(s_box_1[k], s_box_1[k]);
	/*	printf("%02X ", (unsigned char)s_box_1[k]);
		if(!((k+1)%16))
			printf("\n");*/

		mult_by_2[k]=mult_gf_2_8(k, 2);
	}
	for(int k=0;k<256;++k)//2113	3211	1321	1132
	{
		unsigned char c=s_box[k], c2=mult_by_2[c], c3=c2^c;
		E0[k]=c2|c<<8|c<<16|c3<<24, E1[k]=c3|c2<<8|c<<16|c<<24, E2[k]=c|c3<<8|c2<<16|c<<24, E3[k]=c|c<<8|c3<<16|c2<<24, SBS8[k]=c<<8, SBS16[k]=c<<16, SBS24[k]=c<<24;
	}
	for(int k=0;k<256;++k)//E9DB	BE9D	DBE9	9DBE
	{
		unsigned char c=k, c2=mult_by_2[c], c3=c2^c, c4=mult_by_2[c2], c8=mult_by_2[c4], c9=c8^c, cB=c8^c3, cC=c8^c4, cD=cC^c, cE=cC^c2;
		DK0[k]=cE|c9<<8|cD<<16|cB<<24, DK1[k]=cB|cE<<8|c9<<16|cD<<24, DK2[k]=cD|cB<<8|cE<<16|c9<<24, DK3[k]=c9|cD<<8|cB<<16|cE<<24;
	}
	for(int k=0;k<256;++k)//E9DB	BE9D	DBE9	9DBE
	{
		unsigned char c=s_box_1[k], c2=mult_by_2[c], c3=c2^c, c4=mult_by_2[c2], c8=mult_by_2[c4], c9=c8^c, cB=c8^c3, cC=c8^c4, cD=cC^c, cE=cC^c2;
		D0[k]=cE|c9<<8|cD<<16|cB<<24, D1[k]=cB|cE<<8|c9<<16|cD<<24, D2[k]=cD|cB<<8|cE<<16|c9<<24, D3[k]=c9|cD<<8|cB<<16|cE<<24, SB1S8[k]=c<<8, SB1S16[k]=c<<16, SB1S24[k]=c<<24;
	}
	{
		unsigned char smiley=0x8D;
		for(int k=0;k<11;++k)
			smiley=mult_by_2[x_pow_i_4_1[k]=smiley];
	}
}
void		AES::expand_key(unsigned char *key)
{
	*(unsigned char**)&AES::key=key;
	for(int k=16;k<176;k+=4)
	{
		if(!(k%16))
			key[k  ]=s_box[key[k-3]]^x_pow_i_4_1[k/16]^key[k-16],
			key[k+1]=s_box[key[k-2]]^key[k-15],
			key[k+2]=s_box[key[k-1]]^key[k-14],
			key[k+3]=s_box[key[k-4]]^key[k-13];
		else
			key[k  ]=key[k-4]^key[k-16],
			key[k+1]=key[k-3]^key[k-15],
			key[k+2]=key[k-2]^key[k-14],
			key[k+3]=key[k-1]^key[k-13];
	}
	for(int k=0;k<16;k+=4)
		*(int*)((char*)Dkey+k)=*(int*)(key+160+k);
	for(int k=16;k<160;k+=16)
		for(int k2=0;k2<16;k2+=4)
			*(int*)((char*)Dkey+k+k2)=DK0[key[160-k+k2]]^DK1[key[160-k+k2+1]]^DK2[key[160-k+k2+2]]^DK3[key[160-k+k2+3]];
	for(int k=0;k<16;k+=4)
		*(int*)((char*)Dkey+160+k)=*(int*)(key+k);

/*	for(int k=0;k<16;k+=4)
		*(int*)((char*)Dkey+k)=*(int*)(key+k);
	for(int k=16;k<160;k+=4)
		*(int*)((char*)Dkey+k)=DK0[key[k]]^DK1[key[k+1]]^DK2[key[k+2]]^DK3[key[k+3]];
	for(int k=160;k<176;k+=4)
		*(int*)((char*)Dkey+k)=*(int*)(key+k);*/
}
void		AES::encrypt(unsigned char *text, unsigned char *key){expand_key(key), encrypt(text);}
void		AES::encrypt(unsigned char text[16])//http://software.intel.com/en-us/articles/optimizing-performance-of-the-aes-algorithm-for-the-intel-pentiumr-4-processor/
{
//	unsigned char text2[16];
//	for(int k=0;k<16;++k)
//		text2[k]=text[k];

	unsigned char temp0[4][4], temp1[4][4];

//	*(long long*)temp0[0]=*(long long*) text   ^*(long long*)key[0][0];
//	*(long long*)temp0[2]=*(long long*)(text+8)^*(long long*)key[0][2];

	*(int*)temp0[0]=*(int*)key[0][0]^*(int*) text    ;
	*(int*)temp0[1]=*(int*)key[0][1]^*(int*)(text+ 4);
	*(int*)temp0[2]=*(int*)key[0][2]^*(int*)(text+ 8);
	*(int*)temp0[3]=*(int*)key[0][3]^*(int*)(text+12);
	for(int r=1;r<8;r+=2)
	{
		*(int*)temp1[0]=*(int*)key[r  ][0]^E0[temp0[0][0]]^E1[temp0[1][1]]^E2[temp0[2][2]]^E3[temp0[3][3]];
		*(int*)temp1[1]=*(int*)key[r  ][1]^E0[temp0[1][0]]^E1[temp0[2][1]]^E2[temp0[3][2]]^E3[temp0[0][3]];
		*(int*)temp1[2]=*(int*)key[r  ][2]^E0[temp0[2][0]]^E1[temp0[3][1]]^E2[temp0[0][2]]^E3[temp0[1][3]];
		*(int*)temp1[3]=*(int*)key[r  ][3]^E0[temp0[3][0]]^E1[temp0[0][1]]^E2[temp0[1][2]]^E3[temp0[2][3]];
		*(int*)temp0[0]=*(int*)key[r+1][0]^E0[temp1[0][0]]^E1[temp1[1][1]]^E2[temp1[2][2]]^E3[temp1[3][3]];
		*(int*)temp0[1]=*(int*)key[r+1][1]^E0[temp1[1][0]]^E1[temp1[2][1]]^E2[temp1[3][2]]^E3[temp1[0][3]];
		*(int*)temp0[2]=*(int*)key[r+1][2]^E0[temp1[2][0]]^E1[temp1[3][1]]^E2[temp1[0][2]]^E3[temp1[1][3]];
		*(int*)temp0[3]=*(int*)key[r+1][3]^E0[temp1[3][0]]^E1[temp1[0][1]]^E2[temp1[1][2]]^E3[temp1[2][3]];
	}
	*(int*)temp1[0]=*(int*)key[9][0]^E0[temp0[0][0]]^E1[temp0[1][1]]^E2[temp0[2][2]]^E3[temp0[3][3]];
	*(int*)temp1[1]=*(int*)key[9][1]^E0[temp0[1][0]]^E1[temp0[2][1]]^E2[temp0[3][2]]^E3[temp0[0][3]];
	*(int*)temp1[2]=*(int*)key[9][2]^E0[temp0[2][0]]^E1[temp0[3][1]]^E2[temp0[0][2]]^E3[temp0[1][3]];
	*(int*)temp1[3]=*(int*)key[9][3]^E0[temp0[3][0]]^E1[temp0[0][1]]^E2[temp0[1][2]]^E3[temp0[2][3]];
	*(int*) text    =*(int*)key[10][0]^s_box[temp1[0][0]]^SBS8[temp1[1][1]]^SBS16[temp1[2][2]]^SBS24[temp1[3][3]];
	*(int*)(text+ 4)=*(int*)key[10][1]^s_box[temp1[1][0]]^SBS8[temp1[2][1]]^SBS16[temp1[3][2]]^SBS24[temp1[0][3]];
	*(int*)(text+ 8)=*(int*)key[10][2]^s_box[temp1[2][0]]^SBS8[temp1[3][1]]^SBS16[temp1[0][2]]^SBS24[temp1[1][3]];
	*(int*)(text+12)=*(int*)key[10][3]^s_box[temp1[3][0]]^SBS8[temp1[0][1]]^SBS16[temp1[1][2]]^SBS24[temp1[2][3]];

//	for(int k=0;k<16;++k)text2[k]=((char*)temp0)[k];

/*	add_round_key(0);//round 0
	for(int k=1;k<10;++k)//rounds 1~9
	{
		substitute_bytes();
		shift_rows();
		mix_columns();
		add_round_key(k);
	}
	substitute_bytes();//round 10
	shift_rows();
	add_round_key(10);*/
}
void		AES::decrypt(unsigned char *text, unsigned char *key){expand_key(key), decrypt(text);}
void		AES::decrypt(unsigned char *text)
{
	unsigned char temp0[4][4], temp1[4][4];

//	*(long long*)temp[0]=*(long long*)text^*(long long*)key[round][0];
//	*(long long*)temp[2]=*(long long*)(text+8)^*(long long*)key[round][2];

	*(int*)temp0[0]=*(int*) text    ^*(int*)Dkey[0][0];
	*(int*)temp0[1]=*(int*)(text+ 4)^*(int*)Dkey[0][1];
	*(int*)temp0[2]=*(int*)(text+ 8)^*(int*)Dkey[0][2];
	*(int*)temp0[3]=*(int*)(text+12)^*(int*)Dkey[0][3];
	for(int r=1;r<8;r+=2)
	{
		*(int*)temp1[0]=*(int*)Dkey[r  ][0]^D0[temp0[0][0]]^D1[temp0[3][1]]^D2[temp0[2][2]]^D3[temp0[1][3]];
		*(int*)temp1[1]=*(int*)Dkey[r  ][1]^D0[temp0[1][0]]^D1[temp0[0][1]]^D2[temp0[3][2]]^D3[temp0[2][3]];
		*(int*)temp1[2]=*(int*)Dkey[r  ][2]^D0[temp0[2][0]]^D1[temp0[1][1]]^D2[temp0[0][2]]^D3[temp0[3][3]];
		*(int*)temp1[3]=*(int*)Dkey[r  ][3]^D0[temp0[3][0]]^D1[temp0[2][1]]^D2[temp0[1][2]]^D3[temp0[0][3]];
		*(int*)temp0[0]=*(int*)Dkey[r+1][0]^D0[temp1[0][0]]^D1[temp1[3][1]]^D2[temp1[2][2]]^D3[temp1[1][3]];
		*(int*)temp0[1]=*(int*)Dkey[r+1][1]^D0[temp1[1][0]]^D1[temp1[0][1]]^D2[temp1[3][2]]^D3[temp1[2][3]];
		*(int*)temp0[2]=*(int*)Dkey[r+1][2]^D0[temp1[2][0]]^D1[temp1[1][1]]^D2[temp1[0][2]]^D3[temp1[3][3]];
		*(int*)temp0[3]=*(int*)Dkey[r+1][3]^D0[temp1[3][0]]^D1[temp1[2][1]]^D2[temp1[1][2]]^D3[temp1[0][3]];
	}
	*(int*)temp1[0]=*(int*)Dkey[9][0]^D0[temp0[0][0]]^D1[temp0[3][1]]^D2[temp0[2][2]]^D3[temp0[1][3]];
	*(int*)temp1[1]=*(int*)Dkey[9][1]^D0[temp0[1][0]]^D1[temp0[0][1]]^D2[temp0[3][2]]^D3[temp0[2][3]];
	*(int*)temp1[2]=*(int*)Dkey[9][2]^D0[temp0[2][0]]^D1[temp0[1][1]]^D2[temp0[0][2]]^D3[temp0[3][3]];
	*(int*)temp1[3]=*(int*)Dkey[9][3]^D0[temp0[3][0]]^D1[temp0[2][1]]^D2[temp0[1][2]]^D3[temp0[0][3]];
	*(int*) text    =*(int*)Dkey[10][0]^s_box_1[temp1[0][0]]^SB1S8[temp1[3][1]]^SB1S16[temp1[2][2]]^SB1S24[temp1[1][3]];
	*(int*)(text+ 4)=*(int*)Dkey[10][1]^s_box_1[temp1[1][0]]^SB1S8[temp1[0][1]]^SB1S16[temp1[3][2]]^SB1S24[temp1[2][3]];
	*(int*)(text+ 8)=*(int*)Dkey[10][2]^s_box_1[temp1[2][0]]^SB1S8[temp1[1][1]]^SB1S16[temp1[0][2]]^SB1S24[temp1[3][3]];
	*(int*)(text+12)=*(int*)Dkey[10][3]^s_box_1[temp1[3][0]]^SB1S8[temp1[2][1]]^SB1S16[temp1[1][2]]^SB1S24[temp1[0][3]];

/*	*(int*)temp0[0]=*(int*) text    ^*(int*)Dkey[10][0];
	*(int*)temp0[1]=*(int*)(text+ 4)^*(int*)Dkey[10][1];
	*(int*)temp0[2]=*(int*)(text+ 8)^*(int*)Dkey[10][2];
	*(int*)temp0[3]=*(int*)(text+12)^*(int*)Dkey[10][3];
	for(int r=9;r>2;r-=2)
	{
		*(int*)temp1[0]=*(int*)Dkey[r  ][0]^D0[temp0[0][0]]^D1[temp0[3][1]]^D2[temp0[2][2]]^D3[temp0[1][3]];
		*(int*)temp1[1]=*(int*)Dkey[r  ][1]^D0[temp0[1][0]]^D1[temp0[0][1]]^D2[temp0[3][2]]^D3[temp0[2][3]];
		*(int*)temp1[2]=*(int*)Dkey[r  ][2]^D0[temp0[2][0]]^D1[temp0[1][1]]^D2[temp0[0][2]]^D3[temp0[3][3]];
		*(int*)temp1[3]=*(int*)Dkey[r  ][3]^D0[temp0[3][0]]^D1[temp0[2][1]]^D2[temp0[1][2]]^D3[temp0[0][3]];
		*(int*)temp0[0]=*(int*)Dkey[r-1][0]^D0[temp1[0][0]]^D1[temp1[3][1]]^D2[temp1[2][2]]^D3[temp1[1][3]];
		*(int*)temp0[1]=*(int*)Dkey[r-1][1]^D0[temp1[1][0]]^D1[temp1[0][1]]^D2[temp1[3][2]]^D3[temp1[2][3]];
		*(int*)temp0[2]=*(int*)Dkey[r-1][2]^D0[temp1[2][0]]^D1[temp1[1][1]]^D2[temp1[0][2]]^D3[temp1[3][3]];
		*(int*)temp0[3]=*(int*)Dkey[r-1][3]^D0[temp1[3][0]]^D1[temp1[2][1]]^D2[temp1[1][2]]^D3[temp1[0][3]];
	}
	*(int*)temp1[0]=*(int*)Dkey[1][0]^D0[temp0[0][0]]^D1[temp0[3][1]]^D2[temp0[2][2]]^D3[temp0[1][3]];
	*(int*)temp1[1]=*(int*)Dkey[1][1]^D0[temp0[1][0]]^D1[temp0[0][1]]^D2[temp0[3][2]]^D3[temp0[2][3]];
	*(int*)temp1[2]=*(int*)Dkey[1][2]^D0[temp0[2][0]]^D1[temp0[1][1]]^D2[temp0[0][2]]^D3[temp0[3][3]];
	*(int*)temp1[3]=*(int*)Dkey[1][3]^D0[temp0[3][0]]^D1[temp0[2][1]]^D2[temp0[1][2]]^D3[temp0[0][3]];
	*(int*) text    =*(int*)Dkey[0][0]^s_box_1[temp1[0][0]]^SB1S8[temp1[3][1]]^SB1S16[temp1[2][2]]^SB1S24[temp1[1][3]];
	*(int*)(text+ 4)=*(int*)Dkey[0][1]^s_box_1[temp1[1][0]]^SB1S8[temp1[0][1]]^SB1S16[temp1[3][2]]^SB1S24[temp1[2][3]];
	*(int*)(text+ 8)=*(int*)Dkey[0][2]^s_box_1[temp1[2][0]]^SB1S8[temp1[1][1]]^SB1S16[temp1[0][2]]^SB1S24[temp1[3][3]];
	*(int*)(text+12)=*(int*)Dkey[0][3]^s_box_1[temp1[3][0]]^SB1S8[temp1[2][1]]^SB1S16[temp1[1][2]]^SB1S24[temp1[0][3]];*/

/*	add_round_key(10);//round 0
	for(int k=9;k>0;--k)//rounds 1~9
	{
		inverse_shift_rows();
		inverse_sub_bytes();
		add_round_key(k);
		inverse_mix_columns();
	}
	inverse_shift_rows();//round 10
	inverse_sub_bytes();
	add_round_key(0);*/
}

int charToHex(char c)
{
	if(c>='0'&&c<='9')
		return c-'0';
	if(c>='a'&&c<='f')
		return 0xa+c-'a';
	if(c>='A'&&c<'F')
		return 0xA+c-'A';
	return -1;
}
const int bitHistogram_size=32;
int bitHistogram[bitHistogram_size]={0};
//const int resolution=100;
//int varHist[resolution], varHistStart=75000, varHistEnd=107000;
//int dotHist[resolution], dotHistStart=-15000, dotHistEnd=12000;
int histogram[128]={0};
unsigned char key[11*16], text[7][16];
_LARGE_INTEGER li={0, 0};
long long oldTime=0;
int passwordLength=20, passwordsPerLine=5;
char separator=' ';
#if 1
char print_stream_convert(char const *ranges, int oEnd, int offset)
{
	for(int o=0;o<oEnd;o+=2)
	{
		auto c=ranges[o]+offset;
		if(c<=ranges[o+1])
		{
			++histogram[c];
			return c;
		}
		offset-=ranges[o+1]+1-ranges[o];
	}
	char c=ranges[oEnd]+offset;
	++histogram[c];
	return c;
}
void print_stream(char const *ranges)
{
	auto lltext=(unsigned long long*)text;
	const int size=sizeof(text)/sizeof(unsigned long long),
		charsPerStream=9;
	
	int rangeSize=0, ro=0;//calculate range size
	for(;ranges[ro]&&ranges[ro+1];ro+=2)
		rangeSize+=ranges[ro+1]+1-ranges[ro];//closed set
	int oEnd=ro-1;

//	if(passwordsPerLine>5)//several lines
//		putchar('\n');
	for(int k0=0, k0End=size-2*(passwordsPerLine==5),//if 5 just print 6 streams
			nChars=0, nPasswords=0;
		k0<k0End;//redundant anti-crash
		++k0)
	{
		auto stream=lltext[k0];
		for(int k=0;k<charsPerStream;++k, ++nChars)//decode 64bits -> 9 chars
		{
			int offset=(stream^rand())%rangeSize;
		//	int offset=stream%rangeSize;
			stream/=rangeSize;
			if(nChars&&!(nChars%passwordLength))
		//	int K=charsPerStream*k0+k;
		//	if(K&&!(K%passwordLength))
			{
				++nPasswords;
				if(passwordsPerLine!=5)//if 5 just print 6 streams
				{
					if(nPasswords==passwordsPerLine)
						return;
					if(passwordsPerLine>5&&k0>=size-3)
					{
						AES::encrypt(&text[0][0]);
						AES::encrypt(&text[1][0]);
						AES::encrypt(&text[2][0]);
						AES::encrypt(&text[3][0]);
						AES::encrypt(&text[4][0]);
						AES::encrypt(&text[5][0]);
						AES::encrypt(&text[6][0]);
					//	stream=lltext[k0];
						k0=-1;
					}
					if(!(nPasswords%5))
						putchar('\n');
					else
						putchar(separator);
				}
				else
					putchar(separator);
			/*	if(passwordsPerLine!=5)//if 5 just print 6 streams
				{
					if(nPasswords==passwordsPerLine)
						return;
					if(passwordsPerLine>5&&k0==size-1)
					{
						AES::encrypt(&text[0][0]);
						AES::encrypt(&text[1][0]);
						AES::encrypt(&text[2][0]);
						AES::encrypt(&text[3][0]);
						AES::encrypt(&text[4][0]);
						AES::encrypt(&text[5][0]);
						AES::encrypt(&text[6][0]);
						k0=-1;
					}
				}
				putchar(separator);//*/
			}
			putchar(print_stream_convert(ranges, oEnd, offset));
		/*	for(int o=0;o<oEnd;o+=2)
			{
				auto c=ranges[o]+offset;
				if(c<=ranges[o+1])
				{
					++histogram[c];
					putchar(c);
					goto convert_done;//UNIQUE LABEL
				}
				offset-=ranges[o+1]+1-ranges[o];
			}
			char c=ranges[oEnd]+offset;
			++histogram[c];
			putchar(c);
convert_done:;//UNIQUE LABEL//*/
		}
	}
}
#endif
#if 0
bool print_stream_dec_start(unsigned long long &stream, int &offset, int rangeSize, int k0, int k, int charsPerStream)//decode 64bits -> 9 chars
{
	offset=(stream^rand())%rangeSize;
//	int offset=stream%rangeSize;
	stream/=rangeSize;
	int K=charsPerStream*k0+k;
	return K&&!(K%passwordLength);
}
char print_stream_convert(char const *ranges, int oEnd, int offset)
{
	for(int o=0;o<oEnd;o+=2)
	{
		auto c=ranges[o]+offset;
		if(c<=ranges[o+1])
		{
			++histogram[c];
			return c;
		}
		offset-=ranges[o+1]+1-ranges[o];
	}
	char c=ranges[oEnd]+offset;
	++histogram[c];
	return c;
}
void print_stream(char const *ranges)
{
	auto lltext=(unsigned long long*)text;
	const int size=sizeof(text)/sizeof(unsigned long long),
		charsPerStream=9;
	
	int rangeSize=0, ro=0;
	for(;ranges[ro]&&ranges[ro+1];ro+=2)
		rangeSize+=ranges[ro+1]+1-ranges[ro];//closed set
	int oEnd=ro-1;

	if(passwordsPerLine==5)
	{
		for(int k0=0, nPasswords=0;k0<size-2;++k0)
		{
			auto stream=lltext[k0];
			for(int k=0;k<charsPerStream;++k)
			{
				int offset;
				if(print_stream_dec_start(stream, offset, rangeSize, k0, k, charsPerStream))
					putchar(separator);
				putchar(print_stream_convert(ranges, oEnd, offset));
			}
		}
	}
	else
	{
		if(passwordsPerLine>5)
			putchar('\n');
		for(int k0=0, nPasswords=0;k0<size;++k0)
		{
			auto stream=lltext[k0];
			for(int k=0;k<charsPerStream;++k)
			{
				if(print_stream_dec_start(stream, offset, rangeSize, k0, k, charsPerStream))
				{
					++nPasswords;
					if(nPasswords==passwordsPerLine)
						return;
					if(passwordsPerLine>5&&k0==size-1)
					{
						AES::encrypt(&text[0][0]);
						AES::encrypt(&text[1][0]);
						AES::encrypt(&text[2][0]);
						AES::encrypt(&text[3][0]);
						AES::encrypt(&text[4][0]);
						AES::encrypt(&text[5][0]);
						AES::encrypt(&text[6][0]);
						k0=-1;
					}
					putchar(separator);
				}
				putchar(print_stream_convert(ranges, oEnd, offset));
			}
		}
	}
}
#endif
#if 0
void print_stream(char const *ranges)
{
	auto lltext=(unsigned long long*)text;
	const int size=sizeof(text)/sizeof(unsigned long long),
		charsPerStream=9;
	
	int rangeSize=0, ro=0;
	for(;ranges[ro]&&ranges[ro+1];ro+=2)
		rangeSize+=ranges[ro+1]+1-ranges[ro];//closed set
	int oEnd=ro-1;

	if(passwordsPerLine==5)
	{
		for(int k0=0, nPasswords=0;k0<size-2;++k0)
		{
			auto stream=lltext[k0];
			for(int k=0;k<charsPerStream;++k)//decode 64bits -> 9 chars
			{
				int offset=(stream^rand())%rangeSize;
			//	int offset=stream%rangeSize;
				stream/=rangeSize;
				int K=charsPerStream*k0+k;
				if(K&&!(K%passwordLength))
					putchar(separator);

				for(int o=0;o<oEnd;o+=2)
				{
					auto c=ranges[o]+offset;
					if(c<=ranges[o+1])
					{
						++histogram[c];
						putchar(c);
						goto convert_done_1;
					}
					offset-=ranges[o+1]+1-ranges[o];
				}
				char c=ranges[oEnd]+offset;
				++histogram[c];
				putchar(c);
	convert_done_1:;
			}
		}
	}
	else
	{
		if(passwordsPerLine>5)
			putchar('\n');
		for(int k0=0, nPasswords=0;k0<size;++k0)
		{
			auto stream=lltext[k0];
			for(int k=0;k<charsPerStream;++k)//decode 64bits -> 9 chars
			{
				int offset=(stream^rand())%rangeSize;
			//	int offset=stream%rangeSize;
				stream/=rangeSize;
				int K=charsPerStream*k0+k;
				if(K&&!(K%passwordLength))
				{
					++nPasswords;
					if(nPasswords==passwordsPerLine)
						return;
					if(passwordsPerLine>5&&k0==size-1)
					{
						AES::encrypt(&text[0][0]);
						AES::encrypt(&text[1][0]);
						AES::encrypt(&text[2][0]);
						AES::encrypt(&text[3][0]);
						AES::encrypt(&text[4][0]);
						AES::encrypt(&text[5][0]);
						AES::encrypt(&text[6][0]);
						k0=-1;
					}
					putchar(separator);
				}

				for(int o=0;o<oEnd;o+=2)
				{
					auto c=ranges[o]+offset;
					if(c<=ranges[o+1])
					{
						++histogram[c];
						putchar(c);
						goto convert_done;
					}
					offset-=ranges[o+1]+1-ranges[o];
				}
				char c=ranges[oEnd]+offset;
				++histogram[c];
				putchar(c);
	convert_done:;
			}
		}
	}

/*	int rangeSize=0, ro=0;
	for(;ranges[ro]&&ranges[ro+1];ro+=2)
		rangeSize+=ranges[ro+1]+1-ranges[ro];//closed set
	int oEnd=ro-1;

	for(int k0=0;k0<size;++k0)
	{
		auto stream=pstream[k0];
		for(int k=0;k<9;++k)
		{
			int offset=(stream^rand())%rangeSize;
		//	int offset=stream%rangeSize;
			stream/=rangeSize;
			int K=9*k0+k;
			if(K&&!(K%passwordLength))
				putchar(separator);

			for(int o=0;o<oEnd;o+=2)
			{
				auto c=ranges[o]+offset;
				if(c<=ranges[o+1])
				{
					++histogram[c];
					putchar(c);
					goto convert_done;
				}
				offset-=ranges[o+1]+1-ranges[o];
			}
			char c=ranges[oEnd]+offset;
			++histogram[c];
			putchar(c);
convert_done:;
		}
	}//*/
}
#endif
#if 0
void print_stream(char const *ranges, unsigned long long *pstream, int size)
{
	int rangeSize=0, ro=0;
	for(;ranges[ro]&&ranges[ro+1];ro+=2)
		rangeSize+=ranges[ro+1]+1-ranges[ro];//closed set
	int oEnd=ro-1;
	for(int k0=0;k0<size;++k0)
	{
		auto stream=pstream[k0];
	//	auto &stream=pstream[k0];
		for(int k=0;k<9;++k)
		{
			int offset=(stream^rand())%rangeSize;
		//	int offset=stream%rangeSize;
			stream/=rangeSize;
			int K=9*k0+k;
			if(K&&!(K%passwordLength))
				putchar(separator);
		//	offset^=(unsigned short)rand();//
		//	offset^=(unsigned char)rand();		//non-uniform
		//	offset^=rand()%rangeSize;			//non-uniform
		//	offset=int(offset*rangeSize/256.);	//non-uniform
			offset%=rangeSize;//256/94=2.7
		//	offset=rangeSize-1-offset;//AES QPC only: halves !"#$%&'()*+,-./0123456789:
		//	int offset=rand_mod(rangeSize);
			for(int o=0;o<oEnd;o+=2)
			{
				auto c=ranges[o]+offset;
				if(c<=ranges[o+1])
				{
					++histogram[c];
					putchar(c);
					goto convert_done;
				}
				offset-=ranges[o+1]+1-ranges[o];
			}
			char c=ranges[oEnd]+offset;
			++histogram[c];
			putchar(c);
		/*	for(int o=0;o<oEnd;o+=2)
			{
				auto c=ranges[o]+offset;
				if(c<=ranges[o+1])
					return c;
				offset-=ranges[o+1]+1-ranges[o];
			}
			return ranges[oEnd]+offset;//*/
convert_done:;
		}
	}
}
#endif
void main()
{
	printf(	"PASSWORD GENERATOR (AES(QPC)^rand(QPC) T=0.46ms)\n"
			"\n"
		//	"  press space...  8 times to fill key (T=0.46ms)\n"
			"	space...  all characters\n"
			"	   enter  alphanumeric\n"
			"	       a  letters\n"
			"	       b  small letters\n"
			"	       B  capital letters\n"
			"	       h  hexadecimal\n"
			"	       9  decimal\n"
			"	       7  octal\n"
			"	       1  binary\n"
			"	       !  symbols\n"
			"	       n  histogram\n"
			"	       t  print stream\n"
			"	       x  ascii to hex\n"
			"	       z  hex to ascii\n"
			"	     esc  exit\n"
			"\n");//*/
/*	printf(	"PASSWORD GENERATOR (QPC AES ^ stdlib rand(QPC))\n"
			"\n"
			"  press space...  8 times to fill key (T=29.6ms)\n"
		//	"	       x  ascii to hex\n"
		//	"	       z  hex to ascii\n"
			"	     esc  exit\n");//*/
/*	printf(	"PASSWORD GENERATOR (stdlib rand())\n"
			"\n"
			"	space...  all characters\n"
			"	   enter  alphanumeric\n"
			"	       a  letters\n"
			"	       b  small letters\n"
			"	       B  capital letters\n"
			"	       h  hexadecimal\n"
			"	       9  decimal\n"
			"	       7  octal\n"
			"	       1  binary\n"
			"	       !  symbols\n"
			"	       x  ascii to hex\n"
			"	       z  hex to ascii\n"
			"	     esc  exit\n"
			"\n"
			"press space... 8 times to fill key\n"
			"	     esc  exit\n"
			"\n");//*/
/*	printf(	"PASSWORD GENERATOR\n"
			"\n"
			"	all characters   space...\n"
			"	alphanumeric     enter\n"
			"	letters          a\n"
			"	small letters    b\n"
			"	capital letters  B\n"
			"	hexadecimal      h\n"
			"	decimal          9\n"
			"	octal            7\n"
			"	binary           1\n"
			"	symbols          !\n"
			"	ascii to hex     x\n"
			"	hex to ascii     z\n"
			"	exit             esc\n"
			"\n");//*/
/*	int cmd_w, cmd_h;
	{
		CONSOLE_SCREEN_BUFFER_INFO csbi;
		GetConsoleScreenBufferInfo(GetStdHandle(STD_OUTPUT_HANDLE), &csbi);
		cmd_w=csbi.srWindow.Right-csbi.srWindow.Left+1;
		cmd_h=csbi.srWindow.Bottom-csbi.srWindow.Top+1;
	}//*/
	AES::initiate();
/*	for(int k=0;k<8;++k)
	{
		if(_getch()==0x1B)
			return;
		putchar('1'+k);
		QueryPerformanceCounter(&li);
		((unsigned short*)key)[k]=unsigned short(li.QuadPart-oldTime);
		oldTime=li.QuadPart;
	}
	AES::expand_key(key);//*/
/*	printf(	"\n"
			"	space...  all characters\n"
			"	   enter  alphanumeric\n"
			"	       a  letters\n"
			"	       b  small letters\n"
			"	       B  capital letters\n"
			"	       h  hexadecimal\n"
			"	       9  decimal\n"
			"	       7  octal\n"
			"	       1  binary\n"
			"	       !  symbols\n"
			"	       n  histogram\n"
			"	       x  ascii to hex\n"
			"	       z  hex to ascii\n"
			"	     esc  exit\n"
			"\n");//*/
	int index_ping=7;
	bool descending=true;
	int k_press=0, k_refill=0, k2_refill=0;
	for(char c='4';c!=0x1B;++k_press, ++k_refill, c=_getch())
//	for(char c;(c=_getch())!=0x1B;++k_press, ++k_refill)
	{
		QueryPerformanceCounter(&li);
		srand(li.LowPart);
		auto var=(unsigned short)(li.QuadPart-oldTime);
		{
			auto ivar=int(li.QuadPart-oldTime);
			for(int k0=0;k0<32;++k0)
				bitHistogram[k0]+=ivar>>k0&1;
		}
		if(!(k_refill%32))		//each 32 presses: refill key for 8 presses
	//	if(k_refill==16)		//after 16 presses: refill key
		{
			if(k2_refill==8)
				k_refill=0, k2_refill=0;
			else
			{
				printf("%d ", k2_refill);//
				((unsigned short*)key)[k2_refill]=var;
				AES::expand_key(key);
				k_refill=-1, ++k2_refill;
			//	k_refill=16-1, ++k2_refill;
			}
		}
	/*	if(k_refill==31)		//after 32 presses: refill key, freeze text
		{
			for(int k2_refill=0;k2_refill<8;++k2_refill)
			{
				QueryPerformanceCounter(&li);
				((unsigned short*)key)[k2_refill]=li.QuadPart-oldTime;
				AES::expand_key(key);
				AES::encrypt(&text[0][0]);
				AES::encrypt(&text[1][0]);
				AES::encrypt(&text[2][0]);
				AES::encrypt(&text[3][0]);
				AES::encrypt(&text[4][0]);
				AES::encrypt(&text[5][0]);
				AES::encrypt(&text[6][0]);

				oldTime=li.QuadPart;
				if(_getch()==0x1B)
					return;
			}
			k_refill=0;
		}
		QueryPerformanceCounter(&li);
		unsigned short var=li.QuadPart-oldTime;//*/

		text[0][var>>6&8|var>>5&4|var>>4&2|var>>3&1]  = var<<1&0x80|var<<3&0x40|var>>5&0x20|var   &0x10|var<<2&8|var   &4|var>>7&2|var   &1;//[9753] = 63A41280
		text[1][var>>4&8|var>>1&4|var>>4&2|var>>1&1] ^= var<<5&0x80|var<<5&0x40|var<<1&0x20|var>>5&0x10|var>>7&8|var>>4&4|var>>7&2|var   &1;//[7351] = 2149A680
		text[2][var<<3&8|var>>4&4|var>>2&2|var>>9&1]  = var<<6&0x80|var>>1&0x40|var<<1&0x20|var<<2&0x10|var<<3&8|var>>6&4|var>>9&2|var>>5&1;//[0639] = 174208A5
		text[3][var   &0xC		 |var>>7&3		   ] ^= var>>3&0x80|var<<1&0x40|var<<5&0x20|var>>2&0x10|var   &8|var>>7&4|var   &2|var>>4&1;//[3287] = A5063914
		text[4][var>>1&8|var>>8&4|var<<1&2|var>>5&1]  = var<<5&0x80|var>>1&0x40|var>>3&0x20|var<<4&0x10|var>>3&8|var<<1&4|var>>2&2|var>>9|1;//[4A05] = 27806139
	/*	text[0][var>>12] = var>>4;//&0x00FF;																//[fedc]  = ba987654 //3210		fedcba98 76543210
		text[1][var>>12&8|var>>11&4|var>>10&2|var>>9&1] ^= var>>7&0x80|var>>6&0x40|var>>5&0x20|var>>4&0x1F;	//[fdb9] ^= eca87654 //3210
		text[2][var>>12&0xC|var>>6&3] = var>>6&0xF0|var>>2&0x0F;											//[fe76]  = dcba5432 //9810		fedcba98 76543210
		text[3][var>>8&0xF] ^= var>>8&0xF0|var>>4&0x0F;														//[ba98] ^= fedc7654 //3210
		text[4][var>>8&8|var>>7&4|var>>6&2|var>>5&1] = var>>8&0xF0|var>>7&8|var>>6&4|var>>5&2|var>>4&1;		//[b975]  = fedca864 //3210		fedcba98 76543210
		//*/
		((unsigned short*)(&text[5][0]))[index_ping] ^= var;		//[descending ping] ^= fedcba98 76543210
		descending&=index_ping!=0, descending|=index_ping==7;
		index_ping+=!descending-descending;
	/*	if(descending)
			--ping;
		else
			++ping;//*/
	//	descending=descending&&ping!=0||ping==7;
	//	descending=descending&&ping!=0||ping==7&&ping!=0;
	//	descending=(descending||ping==7)&&ping!=0;
	//	descending=(descending||ping==7)&&!(ping==0);
	//	descending|=ping==7;
	//	descending&=!(ping==0);
	/*	if(ping==7)
			descending=true;
		if(ping==0)
			descending=false;//*/
	//	descending=ping!=0||ping==7;//X
	/*	if(descending)
		{
			if(ping==0)
				descending=false, ++ping;
			else
				--ping;
		}
		else//ascending
		{
			if(ping==7)
				descending=true, --ping;
			else
				++ping;
		}//*/
		text[6][var>>4&8|var>>6&4|var>>8&2|var   &1]  = var<<5&0x80|var<<5&0x40|var<<1&0x30            |var>>8&8|var>>5&7;//[7890] = 2143A765		fedcb a98 76543210
	//	text[6][var>>11&8|var>>10&4|var>>9&2|var>>8&1] ^= var>>8&0x80|var>>7&0x40|var>>6&0x20|var>>5&0x10|var>>4&0xF;	//[eca8] ^= fdb97654 //3210		fedcba98 76543210

	//	((unsigned long long*)&text[0][0])[0]=0x0706050403020100;
	//	((unsigned long long*)&text[0][0])[1]=0x0F0E0D0C0B0A0908;
	/*	putchar('\n');
		for(int k0=0;k0<7;++k0)
		{
			for(int k1=0;k1<16;++k1)
				printf("%4d ", (&text[k0][0])[k1]);
			putchar('\n');
		}//*/
	//	unsigned char LOL_1[]={(&text[0][0])[15], (&text[1][0])[15], (&text[2][0])[15], (&text[3][0])[15], (&text[4][0])[15], (&text[5][0])[15], (&text[6][0])[15]};
		AES::encrypt(&text[0][0]);
		AES::encrypt(&text[1][0]);
		AES::encrypt(&text[2][0]);
		AES::encrypt(&text[3][0]);
		AES::encrypt(&text[4][0]);
		AES::encrypt(&text[5][0]);
		AES::encrypt(&text[6][0]);
	/*	putchar('\n');
		for(int k0=0;k0<7;++k0)
		{
			for(int k1=0;k1<16;++k1)
				printf("%4d ", text[k0][k1]);
			putchar('\n');
		}//*/

		const int stream_size=12;
		auto ctext=(unsigned long long*)&text[0][0];
		switch(c)
		{
		case ',':case '<':
			if(passwordsPerLine>0)
				--passwordsPerLine;
			print_stream("!~"		);
		//	print_stream("!~"		, ctext, stream_size);
			break;
		case '.':case '>':
			if(passwordsPerLine>0)
				++passwordsPerLine;
			print_stream("!~"		);
		//	print_stream("!~"		, ctext, stream_size);
			break;
		case '\r':			print_stream("09AZaz"	);break;//alphanumeric
		case 'a':case 'A':	print_stream("AZaz"		);break;//letters
		case 'b':			print_stream("az"		);break;//small letters
		case 'B':			print_stream("AZ"		);break;//capital letters
		case 'h':			print_stream("09AF"		);break;//hexadecimal
		case 'H':			print_stream("09af"		);break;//hexadecimal
		case '9':			print_stream("09"		);break;//decimal
		case '7':			print_stream("07"		);break;//octal
		case '1':			print_stream("01"		);break;//binary
		case '!':			print_stream("!/:@[`{~"	);break;//symbols
	/*	case '\r':			print_stream("09AZaz"	, ctext, stream_size);break;//alphanumeric
		case 'a':case 'A':	print_stream("AZaz"		, ctext, stream_size);break;//letters
		case 'b':			print_stream("az"		, ctext, stream_size);break;//small letters
		case 'B':			print_stream("AZ"		, ctext, stream_size);break;//capital letters
		case 'h':			print_stream("09AF"		, ctext, stream_size);break;//hexadecimal
		case 'H':			print_stream("09af"		, ctext, stream_size);break;//hexadecimal
		case '9':			print_stream("09"		, ctext, stream_size);break;//decimal
		case '7':			print_stream("07"		, ctext, stream_size);break;//octal
		case '1':			print_stream("01"		, ctext, stream_size);break;//binary
		case '!':			print_stream("!/:@[`{~"	, ctext, stream_size);break;//symbols//*/
		case 'n':
			{
				printf("\n%d presses\n", k_press);
				const int graphChars=50;
				int max=0;
				for(int k0=0;k0<bitHistogram_size;++k0)
					if(max<bitHistogram[k0])
						max=bitHistogram[k0];
				if(max)
				{
					for(int k0=0;k0<bitHistogram_size;++k0)
					{
						printf("%2d %4d  ", k0, bitHistogram[k0]);
						int k1=0;
						for(int nDots=graphChars*bitHistogram[k0]/max;k1<nDots;++k1)
							putchar('1');
						for(;k1<graphChars;++k1)
							putchar('0');
						putchar('\n');
						if(k0==15)
							putchar('\n');
					}
				}
				putchar('\n');
				max=0;
				for(int k0=0;k0<128;++k0)
					if(max<histogram[k0])
						max=histogram[k0];
				if(max)
				{
					for(int k0=33;k0<127;++k0)
					{
						printf("\'%c\' %4d  ", k0, histogram[k0]);
						int k1=0;
						for(int nDots=graphChars*histogram[k0]/max;k1<nDots;++k1)
							putchar('*');
						for(;k1<graphChars;++k1)
							putchar('-');
						putchar('\n');
					}
				}
			}
			break;
		case 't':
			putchar('\n');
			for(int k0=0;k0<7;++k0)
			{
				for(int k1=0;k1<16;++k1)
					printf("%4d ", (&text[k0][0])[k1]);
				putchar('\n');
			}
			break;
		case 'x':
			printf(	"\n"
					"Ascii to hex (esc (0x1B) to stop)\n");
			for(char c;(c=_getch())!=0x1B;)
				printf("%c\t0x%X\n", c, c);
			break;
		case 'z':
			printf(	"\n"
					"Hex to ascii\n");
			for(char d, d2, e, e2;;)
			{
				d=_getch();
				if((d2=charToHex(d))>=0)
				{
					printf("0x%c", d);
					e=_getch();
					if((e2=charToHex(e))>=0)
					{
						printf("%c\t%c\n", e, d2<<4|e2);
						continue;
					}
				}
				putchar('\n');
				break;
			}
			break;
		default:			print_stream("!~"		);break;//all characters
	//	default:			print_stream("!~"		, ctext, stream_size);break;//all characters
		}
#if 0
		auto ctext=&text[0][0];
		switch(c)
		{
		case ',':case '<':
			if(passwordsPerLine>0)
				--passwordsPerLine;
			RandRange("!~"			);for(int k0=0;k0<112;++k0){if(k0&&!(k0%20))putchar(separator);		putchar(RandRange::convert(ctext[k0]));}
		//	{RandRange("!~"			);for(int k0=0;k0<passwordsPerLine;k0++){for(int k=0;k<20;k++)putchar(RandRange::get());putchar(separator);}}
			break;
		case '.':case '>':
			if(passwordsPerLine>0)
				++passwordsPerLine;
			RandRange("!~"			);for(int k0=0;k0<112;++k0){if(k0&&!(k0%20))putchar(separator);		putchar(RandRange::convert(ctext[k0]));}
		//	{RandRange("!~"			);for(int k0=0;k0<passwordsPerLine;k0++){for(int k=0;k<20;k++)putchar(RandRange::get());putchar(separator);}}
			break;
		case '\r':			RandRange("09AZaz"	);for(int k0=0;k0<112;++k0){if(k0&&!(k0%20))putchar(separator);		putchar(RandRange::convert(ctext[k0]));}break;//alphanumeric
		case 'a':case 'A':	RandRange("AZaz"	);for(int k0=0;k0<112;++k0){if(k0&&!(k0%20))putchar(separator);		putchar(RandRange::convert(ctext[k0]));}break;//letters
		case 'b':			RandRange("az"		);for(int k0=0;k0<112;++k0){if(k0&&!(k0%20))putchar(separator);		putchar(RandRange::convert(ctext[k0]));}break;//small letters
		case 'B':			RandRange("AZ"		);for(int k0=0;k0<112;++k0){if(k0&&!(k0%20))putchar(separator);		putchar(RandRange::convert(ctext[k0]));}break;//capital letters
		case 'h':			RandRange("09AF"	);for(int k0=0;k0<112;++k0){if(k0&&!(k0%20))putchar(separator);		putchar(RandRange::convert(ctext[k0]));}break;//hexadecimal
		case 'H':			RandRange("09af"	);for(int k0=0;k0<112;++k0){if(k0&&!(k0%20))putchar(separator);		putchar(RandRange::convert(ctext[k0]));}break;//hexadecimal
		case '9':			RandRange("09"		);for(int k0=0;k0<112;++k0){if(k0&&!(k0%20))putchar(separator);		putchar(RandRange::convert(ctext[k0]));}break;//decimal
		case '7':			RandRange("07"		);for(int k0=0;k0<112;++k0){if(k0&&!(k0%20))putchar(separator);		putchar(RandRange::convert(ctext[k0]));}break;//octal
		case '1':			RandRange("01"		);for(int k0=0;k0<112;++k0){if(k0&&!(k0%20))putchar(separator);		putchar(RandRange::convert(ctext[k0]));}break;//binary
		case '!':			RandRange("!/:@[`{~");for(int k0=0;k0<112;++k0){if(k0&&!(k0%20))putchar(separator);		putchar(RandRange::convert(ctext[k0]));}break;//symbols
	/*	case '\r':			{RandRange("09AZaz"		);for(int k0=0;k0<passwordsPerLine;k0++){for(int k=0;k<20;k++)putchar(RandRange::get());putchar(separator);}}break;//alphanumeric
		case 'a':case 'A':	{RandRange("AZaz"		);for(int k0=0;k0<passwordsPerLine;k0++){for(int k=0;k<20;k++)putchar(RandRange::get());putchar(separator);}}break;//letters
		case 'b':			{RandRange("az"			);for(int k0=0;k0<passwordsPerLine;k0++){for(int k=0;k<20;k++)putchar(RandRange::get());putchar(separator);}}break;//small letters
		case 'B':			{RandRange("AZ"			);for(int k0=0;k0<passwordsPerLine;k0++){for(int k=0;k<20;k++)putchar(RandRange::get());putchar(separator);}}break;//capital letters
		case 'h':			{RandRange("09AF"		);for(int k0=0;k0<passwordsPerLine;k0++){for(int k=0;k<20;k++)putchar(RandRange::get());putchar(separator);}}break;//hexadecimal
		case 'H':			{RandRange("09af"		);for(int k0=0;k0<passwordsPerLine;k0++){for(int k=0;k<20;k++)putchar(RandRange::get());putchar(separator);}}break;//hexadecimal
		case '9':			{RandRange("09"			);for(int k0=0;k0<passwordsPerLine;k0++){for(int k=0;k<20;k++)putchar(RandRange::get());putchar(separator);}}break;//decimal
		case '7':			{RandRange("07"			);for(int k0=0;k0<passwordsPerLine;k0++){for(int k=0;k<20;k++)putchar(RandRange::get());putchar(separator);}}break;//octal
		case '1':			{RandRange("01"			);for(int k0=0;k0<passwordsPerLine;k0++){for(int k=0;k<20;k++)putchar(RandRange::get());putchar(separator);}}break;//binary
		case '!':			{RandRange("!/:@[`{~"	);for(int k0=0;k0<passwordsPerLine;k0++){for(int k=0;k<20;k++)putchar(RandRange::get());putchar(separator);}}break;//symbols//*/
		case 'n':
			{
				printf("\n%d presses\n", k_press);
				const int graphChars=50;
				int max=0;
				for(int k0=0;k0<bitHistogram_size;++k0)
					if(max<bitHistogram[k0])
						max=bitHistogram[k0];
				if(max)
				{
					for(int k0=0;k0<bitHistogram_size;++k0)
					{
						printf("%2d %4d  ", k0, bitHistogram[k0]);
						int k1=0;
						for(int nDots=graphChars*bitHistogram[k0]/max;k1<nDots;++k1)
							putchar('1');
						for(;k1<graphChars;++k1)
							putchar('0');
						putchar('\n');
						if(k0==15)
							putchar('\n');
					}
				}
				putchar('\n');
				max=0;
				for(int k0=0;k0<128;++k0)
					if(max<histogram[k0])
						max=histogram[k0];
				if(max)
				{
					for(int k0=33;k0<127;++k0)
					{
						printf("\'%c\' %4d  ", k0, histogram[k0]);
						int k1=0;
						for(int nDots=graphChars*histogram[k0]/max;k1<nDots;++k1)
							putchar('*');
						for(;k1<graphChars;++k1)
							putchar('-');
						putchar('\n');
					}
				}
			}
			break;
		case 't':
			putchar('\n');
			for(int k0=0;k0<7;++k0)
			{
				for(int k1=0;k1<16;++k1)
					printf("%4d ", (&text[k0][0])[k1]);
				putchar('\n');
			}
			break;
		case 'x':
			printf(	"\n"
					"Ascii to hex (esc (0x1B) to stop)\n");
			for(char c;(c=_getch())!=0x1B;)
				printf("%c\t0x%X\n", c, c);
			break;
		case 'z':
			printf(	"\n"
					"Hex to ascii\n");
			for(char d, d2, e, e2;;)
			{
				d=_getch();
				if((d2=charToHex(d))>=0)
				{
					printf("0x%c", d);
					e=_getch();
					if((e2=charToHex(e))>=0)
					{
						printf("%c\t%c\n", e, d2<<4|e2);
						continue;
					}
				}
				putchar('\n');
				break;
			}
			break;
		default:			RandRange("!~"		);for(int k0=0;k0<112;++k0){if(k0&&!(k0%20))putchar(separator);		putchar(RandRange::convert(ctext[k0]));}break;//all characters
	//	default:			{RandRange("!~"			);for(int k0=0;k0<passwordsPerLine;k0++){for(int k=0;k<20;k++)putchar(RandRange::get());putchar(separator);}}break;//all characters
		}
#endif
		putchar('\n');
	/*	for(int k3=0;k3<112;++k3)
		{
			putchar(streamToChar(ctext[k3]^rand(), c));
		//	putchar(streamToChar(ctext[k3], c));
			if(!(k3%20))
				putchar(' ');
		}
		putchar('\n');//*/

		oldTime=li.QuadPart;
	}
}
#endif

//turbo QPC histogram
#if 0
const int resolution=100;
int varHist[resolution], varHistStart=75000, varHistEnd=107000;
int dotHist[resolution], dotHistStart=-15000, dotHistEnd=12000;
void main()
{
	_LARGE_INTEGER li;
	long long oldTime=0;
	for(char c;(c=_getch())!=0x1B;)
	{
		int var=li.QuadPart-oldTime;
		if(
	}

/*	_LARGE_INTEGER li;
	long long oldTime=0;
	int oldVar=0;
	int min=0x7FFFFFFF, max=0x80000001, minDot=0x7FFFFFFF, maxDot=0x80000001, timeout=200, timetostabilize=3;
	int count=0;
	for(char c;(c=_getch())!=0x1B;)
	{
		QueryPerformanceCounter(&li);
		int var=li.QuadPart-oldTime;
		int varDot=var-oldVar;
		if(minDot>varDot)
			minDot=varDot;
		if(maxDot<varDot)
			maxDot=varDot;
		if(min>var)
			min=var;
		if(max<var)
			max=var;
		++count%=timeout;
		printf("%d\t%d\t%d\t%d\t\t%d\t%d\t%d\n", count, var, min, max, varDot, minDot, maxDot);
		if(count==timetostabilize)
		{
			min=0x7FFFFFFF, max=0x80000001, minDot=0x7FFFFFFF, maxDot=0x80000001;
			printf("count\tx\tmin\tmax\tmean\n");
		}
		oldVar=var;
		oldTime=li.QuadPart;
	}//*/
}
#endif
#if 0//var	~[75000 107000]		varDot ~[-15000 12000]
void main()
{
	_LARGE_INTEGER li;
	long long oldTime=0;
	int oldVar=0;
	int min=0x7FFFFFFF, max=0x80000001, minDot=0x7FFFFFFF, maxDot=0x80000001, timeout=200, timetostabilize=3;
	int count=0;
	for(;_getch()!=0x1B;)
	{
		QueryPerformanceCounter(&li);
		int var=li.QuadPart-oldTime;
		int varDot=var-oldVar;
		if(minDot>varDot)
			minDot=varDot;
		if(maxDot<varDot)
			maxDot=varDot;
		if(min>var)
			min=var;
		if(max<var)
			max=var;
		++count%=timeout;
		printf("%d\t%d\t%d\t%d\t\t%d\t%d\t%d\n", count, var, min, max, varDot, minDot, maxDot);
		if(count==timetostabilize)
		{
			min=0x7FFFFFFF, max=0x80000001, minDot=0x7FFFFFFF, maxDot=0x80000001;
			printf("count\tx\tmin\tmax\tmean\n");
		}
		oldVar=var;
		oldTime=li.QuadPart;
	}
/*	_LARGE_INTEGER li;
	long long oldTime=0;
	int oldVar=0;
	int min=0x7FFFFFFF, max=0x80000001, timeout=200, timetostabilize=3;
	unsigned long long sum=0;
	int count=0;
	for(;_getch()!=0x1B;)
	{
		QueryPerformanceCounter(&li);
		int theVar=li.QuadPart-oldTime;
		int varDot=theVar-oldVar;
		if(min>varDot)
			min=varDot;
		if(max<varDot)
			max=varDot;
		sum+=varDot;
		if(++count==timeout)
			count=0, sum=0;
	//	++count%=timeout;
		printf("%d\t%d\t%d\t%d\t%d\t%lf\n", count, theVar, varDot, min, max, double(sum)/count);
		if(count==timetostabilize)
		{
			min=0x7FFFFFFF, max=0x80000001;
		//	min=0x7FFFFFFF, max=0x80000001, sum=0;
			printf("count\tx\tmin\tmax\tmean\n");
		}
		oldVar=theVar;
		oldTime=li.QuadPart;
	}//*/
}
#endif
#if 0
void main()
{
	_LARGE_INTEGER li;
	long long oldTime=0;
	int oldVar=0;

	int min=0x7FFFFFFF, max=0, timeout=200;//100
	unsigned long long sum=0;
	int count=timeout-1;
	for(;_getch()!=0x1B;)
	{
		QueryPerformanceCounter(&li);
		int theVar=li.QuadPart-oldTime;
		int absVarDot=abs(theVar-oldVar);
		if(min>absVarDot)
			min=absVarDot;
		if(max<absVarDot)
			max=absVarDot;
		sum+=absVarDot;
		++count;
		printf("%d\t%d\t%d\t%d\t%d\t%lf\n", count, theVar, absVarDot, min, max, double(sum)/count);
		if(count==timeout)
		{
			min=0x7FFFFFFF, max=0, sum=0, count=0;
			printf("count\tx\tmin\tmax\tmean\n");
		}//*/
	/*	QueryPerformanceCounter(&li);
		int theVar=li.QuadPart-oldTime;
		int absVarDot=abs(theVar-oldVar);
		if(min>theVar)
			min=theVar;
		if(max<theVar)
			max=theVar;
		sum+=theVar;
		++count;
		printf("%d\t%d\t%d\t%d\t%d\t%lf\n", count, theVar, absVarDot, min, max, double(sum)/count);
		if(count==timeout)
		{
			min=0x7FFFFFFF, max=0, sum=0, count=0;
			printf("count\tx\tmin\tmax\tmean\n");
		}//*/
	//	printf("%d\t", theVar);

		oldVar=theVar;
		oldTime=li.QuadPart;

	//	auto input=(unsigned short)li.LowPart;
	}
}
#endif

//<random> uniform_distribution(from, to)(mt19937(QPC))		20160213
#if 0
_LARGE_INTEGER	li={0, 0};
long long frequency;
int charToHex(char c)
{
	if(c>='0'&&c<='9')
		return c-'0';
	if(c>='a'&&c<='f')
		return 0xa+c-'a';
	if(c>='A'&&c<'F')
		return 0xA+c-'A';
	return -1;
}
int histogram[128]={0};
int prevLowPart=0;
class RandCharBag
{
	char const *ranges;
	int rangeSize, oEnd;
	std::uniform_int_distribution<int> distr;
	int calculateRangeSize()
	{
		rangeSize=0;
		int ro=0;
		for(;ranges[ro]&&ranges[ro+1];ro+=2)
			rangeSize+=ranges[ro+1]+1-ranges[ro];
		oEnd=ro-1;
		return rangeSize;
	}
public:
	RandCharBag(char const *ranges):ranges(ranges), distr(0, calculateRangeSize()-1){}
	char get(std::mt19937 &rng)
	{
		QueryPerformanceCounter(&li);
		int offset=(li.LowPart-prevLowPart)%rangeSize;
		prevLowPart=li.LowPart;

	//	QueryPerformanceCounter(&li);
	//	int offset=li.LowPart%rangeSize;

	//	int offset=distr(rng);

		for(int o=0;o<oEnd;o+=2)
		{
			auto c=ranges[o]+offset;
			if(c<=ranges[o+1])
			{
				++histogram[c];
				return c;
			}
			offset-=ranges[o+1]+1-ranges[o];
		}
		char c=ranges[oEnd]+offset;
		++histogram[c];
		return c;//*/

	/*	QueryPerformanceCounter(&li);
		int offset=li.LowPart%rangeSize;
	//	int offset=distr(rng);
		for(int o=0;o<oEnd;o+=2)
		{
			auto c=ranges[o]+offset;
			if(c<=ranges[o+1])
				return c;
			offset-=ranges[o+1]+1-ranges[o];
		}
		return ranges[oEnd]+offset;//*/
	}
};
void main()
{
//	QueryPerformanceFrequency(&li);
//	frequency=li.QuadPart;//fixed at system boot


	printf(	"PASSWORD GENERATOR (MT19937)\n"
			"\n"
			"First, press space... to roll the dice.\n"//make a system that dynamically seeds from input, once
			"	     esc  exit\n");
	if(_getch()==0x1B)
		return;
	QueryPerformanceCounter(&li);
	unsigned long seed=li.LowPart&0xFFFF;
	printf(	"\n"
			"\n"
			"	space...  all characters\n"
			"	   enter  alphanumeric\n"
			"	       a  letters\n"
			"	       b  small letters\n"
			"	       B  capital letters\n"
			"	       h  hexadecimal\n"
			"	       9  decimal\n"
			"	       7  octal\n"
			"	       1  binary\n"
			"	       !  symbols\n"
			"	       x  ascii to hex\n"
			"	       z  hex to ascii\n"
			"	       n  histogram (normalized)\n"//
			"	       N  histogram\n"//
			"	     esc  exit\n"
			"\n");
	char c=_getch();
	QueryPerformanceCounter(&li);
	seed|=(li.LowPart&0xFFFF)<<16;
	std::mt19937 rng(seed);
	RandCharBag
		all			("!~"		),//94
		alphanumeric("09AZaz"	),//62
		letters		("AZaz"		),//52
		symbols		("!/:@[`{~"	),//32
		smalls		("az"		), capitals("AZ"	),//26
		hexCapital	("09AF"		), hexSmall("09af"	),//16
		decimal		("09"		),//10
		octal		("07"		),//8
		binary		("01"		);//2
	
	int passwordsPerLine=5;
	char separator=' ';
	for(;c!=0x1B//esc
		;c=_getch())
	{
	//	QueryPerformanceCounter(&li);
	//	srand(li.LowPart);
		switch(c)
		{
		case 'n':
			{
				printf("\n\nNormalized histogram\n");
				int max=0;
				for(int k=33;k<127;++k)
					max=(max+histogram[k]+abs(max-histogram[k]))/2;
				for(int k=33;k<127;++k)
				{
					printf("\n%c ", k);
				//	printf("\n\'%c\' ", k);
					for(int k2=0, k2End=histogram[k]*64/max;k2<k2End;++k2)
						putchar('*');
				}
			}
			printf("\n");
			break;
		case 'N':
			printf("\n\nHistogram\n");
			for(int k=33;k<127;++k)
			{
				printf("\n%c ", k);
			//	printf("\n\'%c\' ", k);
				for(int k2=0, k2End=histogram[k];k2<k2End;++k2)
					putchar('*');
			}
			printf("\n");
			break;
		case 'x':
			printf(	"\n"
					"Ascii to hex (esc (0x1B) to stop)\n");
			for(char c;(c=_getch())!=0x1B;)
				printf("%c\t0x%X\n", c, c);
			break;
		case 'z':
			printf(	"\n"
					"Hex to ascii\n");
			for(char d, d2, e, e2;;)
			{
				d=_getch();
				if((d2=charToHex(d))>=0)
				{
					printf("0x%c", d);
					e=_getch();
					if((e2=charToHex(e))>=0)
					{
						printf("%c\t%c\n", e, d2<<4|e2);
						continue;
					}
				}
				putchar('\n');
				break;
			}
			break;
		case ',':case '<':
			passwordsPerLine-=passwordsPerLine>0;
			for(int k0=0;k0<passwordsPerLine;k0++){for(int k=0;k<20;k++)putchar(all.get(rng));putchar(separator);}
			break;
		case '.':case '>':
			passwordsPerLine+=passwordsPerLine>0;
			for(int k0=0;k0<passwordsPerLine;k0++){for(int k=0;k<20;k++)putchar(all.get(rng));putchar(separator);}
			break;
		case '\r':			for(int k0=0;k0<passwordsPerLine;k0++){for(int k=0;k<20;k++)putchar(alphanumeric.get(rng));putchar(separator);}break;//alphanumeric
		case 'a':case 'A':	for(int k0=0;k0<passwordsPerLine;k0++){for(int k=0;k<20;k++)putchar(letters		.get(rng));putchar(separator);}break;//letters
		case 'b':			for(int k0=0;k0<passwordsPerLine;k0++){for(int k=0;k<20;k++)putchar(smalls		.get(rng));putchar(separator);}break;//small letters
		case 'B':			for(int k0=0;k0<passwordsPerLine;k0++){for(int k=0;k<20;k++)putchar(capitals	.get(rng));putchar(separator);}break;//capital letters
		case 'h':			for(int k0=0;k0<passwordsPerLine;k0++){for(int k=0;k<20;k++)putchar(hexCapital	.get(rng));putchar(separator);}break;//hexadecimal
		case 'H':			for(int k0=0;k0<passwordsPerLine;k0++){for(int k=0;k<20;k++)putchar(hexSmall	.get(rng));putchar(separator);}break;//hexadecimal
		case '9':			for(int k0=0;k0<passwordsPerLine;k0++){for(int k=0;k<20;k++)putchar(decimal		.get(rng));putchar(separator);}break;//decimal
		case '7':			for(int k0=0;k0<passwordsPerLine;k0++){for(int k=0;k<20;k++)putchar(octal		.get(rng));putchar(separator);}break;//octal
		case '1':			for(int k0=0;k0<passwordsPerLine;k0++){for(int k=0;k<20;k++)putchar(binary		.get(rng));putchar(separator);}break;//binary
		case '!':			for(int k0=0;k0<passwordsPerLine;k0++){for(int k=0;k<20;k++)putchar(symbols		.get(rng));putchar(separator);}break;//symbols
		default:			for(int k0=0;k0<passwordsPerLine;k0++){for(int k=0;k<20;k++)putchar(all			.get(rng));putchar(separator);}break;//all characters
		}
		putchar('\n');
	}
}
#endif

/*//<stdlib.h> srand(QPC) rand() histogram
#if 1
const int resolution=100;
int varHist[resolution], varHistStart=75000, varHistEnd=107000;
int dotHist[resolution], dotHistStart=-15000, dotHistEnd=12000;
#endif//*/

//<stdlib.h> srand(QPC) rand()
#if 0
/*#include<stdio.h>
void main()
{
	const int ball=2+10;
	int goodDay=ball*100+ball-ball/2;
	ball+=100+20*3/6+10;
	printf("%d, %d", ball, goodDay);
}*/
//#include		<Windows.h>
//#include		<stdio.h>
//#include		<conio.h>
//#include<random>
_LARGE_INTEGER	li={0, 0};
int charToHex(char c)
{
	if(c>='0'&&c<='9')
		return c-'0';
	if(c>='a'&&c<='f')
		return 0xa+c-'a';
	if(c>='A'&&c<'F')
		return 0xA+c-'A';
	return -1;
}
char rand_range1			(int r, char const *l){return l[0]+r%(l[1]+1-l[0]);}
char rand_range2			(int r, char const *l)
{
	int offset=r%(
		l[1]+1-l[0]+
		l[3]+1-l[2]);
	if(l[0]+offset<=l[1])
		return l[0]+offset;
	offset-=l[1]+1-l[0];
	return l[2]+offset;
}
char rand_range3			(int r, char const *l)
{
	const int
		n1=l[1]+1-l[0],
		n2=l[3]+1-l[2];
	int offset=r%(n1+n2+l[5]+1-l[4]);

	if(l[0]+offset<=l[1])
		return l[0]+offset;
	offset-=n1;

	if(l[2]+offset<=l[3])
		return l[2]+offset;
	offset-=n2;

	return l[4]+offset;

	//const int n[3]={l[1]+1-l[0], l[3]+1-l[2], l[5]+1-l[4]};
	//int offset=r%(n[0]+n[1]+n[2]);
	//if(l[0]+offset<=l[1])
	//	return l[0]+offset;
	//offset-=n[0];
	//if(l[2]+offset<=l[3])
	//	return l[2]+offset;
	//offset-=n[1];
	//return l[4]+offset;

	//int offset=r%(
	//	l[1]+1-l[0]+
	//	l[3]+1-l[2]+
	//	l[5]+1-l[4]);
	//if(l[0]+offset<=l[1])
	//	return l[0]+offset;
	//offset-=l[1]+1-l[0];
	//if(l[2]+offset<=l[3])
	//	return l[2]+offset;
	//offset-=l[3]+1-l[2];
	//return l[4]+offset;
}
char rand_range4			(int r, char const *l)
{
	const int
		n1=l[1]+1-l[0],
		n2=l[3]+1-l[2],
		n3=l[5]+1-l[4];
	int offset=r%(n1+n2+l[7]+1-l[6]);

	if(l[0]+offset<=l[1])
		return l[0]+offset;
	offset-=n1;

	if(l[2]+offset<=l[3])
		return l[2]+offset;
	offset-=n2;

	if(l[4]+offset<=l[5])
		return l[4]+offset;
	offset-=n3;

	return l[6]+offset;
}
int rand_mod(int range)//uniform rand
{
	//http://stackoverflow.com/questions/14689914/uniformly-distributed-random-number-generation
	auto top=(RAND_MAX-range+1)/range*range-1+range;
	int r;
	while((r=rand())>top);
	return r%range;//*/
}
class RandRange
{
	static char const *ranges;
	static int rangeSize, oEnd;
public:
	RandRange(char const *ranges)
	{
		RandRange::ranges=ranges;
		rangeSize=0;
		int ro=0;
		for(;ranges[ro]&&ranges[ro+1];ro+=2)
			rangeSize+=ranges[ro+1]+1-ranges[ro];
		oEnd=ro-1;
	}
	static char get()
	{
		int offset=rand_mod(rangeSize);
		for(int o=0;o<oEnd;o+=2)
		{
			auto c=ranges[o]+offset;
			if(c<=ranges[o+1])
				return c;
			offset-=ranges[o+1]+1-ranges[o];
		}
		return ranges[oEnd]+offset;
	}
};//*/
char const *RandRange::ranges;
int RandRange::rangeSize, RandRange::oEnd;
/*class RandRange
{
	char const *ranges;
	int rangeSize, oEnd;
public:
	void operator()(char const *ranges)
	{
		this->ranges=ranges;
		rangeSize=0;
		int ro=0;
		for(;ranges[ro]&&ranges[ro+1];ro+=2)
			rangeSize+=ranges[ro+1]+1-ranges[ro];
		oEnd=ro-1;
	}
	//RandRange(char const *ranges):ranges(ranges)
	//{
	//	rangeSize=0;
	//	int ro=0;
	//	for(;ranges[ro]&&ranges[ro+1];ro+=2)
	//		rangeSize+=ranges[ro+1]+1-ranges[ro];
	//	oEnd=ro-1;
	//}
	char operator()()
	{
		int offset=rand_mod(rangeSize);
		for(int o=0;o<oEnd;o+=2)
		{
			auto c=ranges[o]+offset;
			if(c<=ranges[o+1])
				return c;
			offset-=ranges[o+1]+1-ranges[o];
		}
		return ranges[oEnd]+offset;
	}
};//*/
char rand_ranges			(int randomNumber, char const *ranges)
{
	int k=0, offset;
	{
		int rangeSize=0;
		for(;ranges[k]&&ranges[k+1];k+=2)
			rangeSize+=ranges[k+1]+1-ranges[k];
		offset=randomNumber%rangeSize;
	}
	for(int o=0, oEnd=k-2;o<oEnd;o+=2)
	{
		auto c=ranges[o]+offset;
		if(c<=ranges[o+1])
			return c;
		offset-=ranges[o+1]+1-ranges[o];
	}
	return ranges[k-2]+offset;//*/

/*	int nLen=0, rangeSize=0;
	for(int c=0;ranges[c]&&ranges[c+1];c+=2)
		rangeSize+=ranges[c+1]+1-ranges[c], ++nLen;
	int offset=randomNumber%rangeSize;
	for(int ro=0, roEnd=(nLen-1)*2;ro<roEnd;ro+=2)
	{
		auto c=ranges[ro]+offset;
		if(c<=ranges[ro+1])
			return c;
		offset-=ranges[c+1]+1-ranges[c];
	}
	return ranges[nLen*2-1]+offset;//*/

/*	int lLen=strlen(ranges), nLen=lLen/2;
	int rangeSize=0;
	for(int lOffset=0, lEnd=nLen*2;lOffset<lEnd;lOffset+=2)
		rangeSize+=ranges[lOffset+1]+1-ranges[lOffset];//*/

//	int nLen=strlen(l)/2, *n=new int[nLen];

/*	const int
		n1=l[1]+1-l[0],
		n2=l[3]+1-l[2],
		n3=l[5]+1-l[4];
	int offset=r%(n1+n2+l[7]+1-l[6]);

	if(l[0]+offset<=l[1])
		return l[0]+offset;
	offset-=n1;

	if(l[2]+offset<=l[3])
		return l[2]+offset;
	offset-=n2;

	if(l[4]+offset<=l[5])
		return l[4]+offset;
	offset-=n3;

	return l[6]+offset;//*/
}
char randToChar(int c, int r)
{
	switch(c)
	{
	case '1':
		return '0'+r%('9'+1-'0');
		break;
	case '2':
		{
			int offset=r%('Z'+1-'A'+'z'+1-'a');
			return 'A'+offset>'Z'?'a'+offset-('Z'+1-'A'):'A'+offset;
		}
	case '3':
		{
			int offset=r%('9'+1-'0'+'Z'+1-'A'+'z'+1-'a');
			return '0'+offset>'9'?'A'+offset-('9'+1-'0')>'Z'?'a'+offset-('9'+1-'0'+'Z'+1-'A'):'A'+offset-('9'+1-'0'):'0'+offset;
		}
	}
	return '!'+r%('~'+1-'!');
}
void main()
{
/*	for(;;)
	{
		QueryPerformanceFrequency(&li);//fixed at system boot			QPC: counts since program start
		li.QuadPart=li.QuadPart;
		//2.207989 MHz 0.452900807023948 us
		//bits		overflow in
		//8			0.115942606598131 ms
		//16		29.6813072891215 ms			33.6912384033202 times per second
		//32		32.4199025749977 minutes
		//64		264739.564413875 years	???
	}//*/
	printf(	"PASSWORD GENERATOR (stdlib rand())\n"
			"\n"
			"	space...  all characters\n"
			"	   enter  alphanumeric\n"
			"	       a  letters\n"
			"	       b  small letters\n"
			"	       B  capital letters\n"
			"	       h  hexadecimal\n"
			"	       9  decimal\n"
			"	       7  octal\n"
			"	       1  binary\n"
			"	       !  symbols\n"
			"	       x  ascii to hex\n"
			"	       z  hex to ascii\n"
			"	     esc  exit\n"
			"\n");//*/
/*	printf(	"PASSWORD GENERATOR\n"
			"\n"
			"	all characters   space...\n"
			"	alphanumeric     enter\n"
			"	letters          a\n"
			"	small letters    b\n"
			"	capital letters  B\n"
			"	hexadecimal      h\n"
			"	decimal          9\n"
			"	octal            7\n"
			"	binary           1\n"
			"	symbols          !\n"
			"	ascii to hex     x\n"
			"	hex to ascii     z\n"
			"	exit             esc\n"
			"\n");//*/
	int passwordsPerLine=5;
	char separator=' ';
	for(__int8 c='4';c!=0x1B//esc
							;c=_getch())
	{
		QueryPerformanceCounter(&li);
		srand(li.LowPart);
		switch(c)
		{
		case ',':case '<':
			if(passwordsPerLine>0)
				--passwordsPerLine;
			{RandRange("!~"			);for(int k0=0;k0<passwordsPerLine;k0++){for(int k=0;k<20;k++)putchar(RandRange::get());putchar(separator);}}
			break;
		case '.':case '>':
			if(passwordsPerLine>0)
				++passwordsPerLine;
			{RandRange("!~"			);for(int k0=0;k0<passwordsPerLine;k0++){for(int k=0;k<20;k++)putchar(RandRange::get());putchar(separator);}}
			break;
		case '\r':			{RandRange("09AZaz"		);for(int k0=0;k0<passwordsPerLine;k0++){for(int k=0;k<20;k++)putchar(RandRange::get());putchar(separator);}}break;//alphanumeric
		case 'a':case 'A':	{RandRange("AZaz"		);for(int k0=0;k0<passwordsPerLine;k0++){for(int k=0;k<20;k++)putchar(RandRange::get());putchar(separator);}}break;//letters
		case 'b':			{RandRange("az"			);for(int k0=0;k0<passwordsPerLine;k0++){for(int k=0;k<20;k++)putchar(RandRange::get());putchar(separator);}}break;//small letters
		case 'B':			{RandRange("AZ"			);for(int k0=0;k0<passwordsPerLine;k0++){for(int k=0;k<20;k++)putchar(RandRange::get());putchar(separator);}}break;//capital letters
		case 'h':			{RandRange("09AF"		);for(int k0=0;k0<passwordsPerLine;k0++){for(int k=0;k<20;k++)putchar(RandRange::get());putchar(separator);}}break;//hexadecimal
		case 'H':			{RandRange("09af"		);for(int k0=0;k0<passwordsPerLine;k0++){for(int k=0;k<20;k++)putchar(RandRange::get());putchar(separator);}}break;//hexadecimal
		case '9':			{RandRange("09"			);for(int k0=0;k0<passwordsPerLine;k0++){for(int k=0;k<20;k++)putchar(RandRange::get());putchar(separator);}}break;//decimal
		case '7':			{RandRange("07"			);for(int k0=0;k0<passwordsPerLine;k0++){for(int k=0;k<20;k++)putchar(RandRange::get());putchar(separator);}}break;//octal
		case '1':			{RandRange("01"			);for(int k0=0;k0<passwordsPerLine;k0++){for(int k=0;k<20;k++)putchar(RandRange::get());putchar(separator);}}break;//binary
		case '!':			{RandRange("!/:@[`{~"	);for(int k0=0;k0<passwordsPerLine;k0++){for(int k=0;k<20;k++)putchar(RandRange::get());putchar(separator);}}break;//symbols
		case 'x':
			printf(	"\n"
					"Ascii to hex (esc (0x1B) to stop)\n");
			for(char c;(c=_getch())!=0x1B;)
				printf("%c\t0x%X\n", c, c);
			break;
		case 'z':
			printf(	"\n"
					"Hex to ascii\n");
			for(char d, d2, e, e2;;)
			{
				d=_getch();
				if((d2=charToHex(d))>=0)
				{
					printf("0x%c", d);
					e=_getch();
					if((e2=charToHex(e))>=0)
					{
						printf("%c\t%c\n", e, d2<<4|e2);
						continue;
					}
				}
				putchar('\n');
				break;
			}
			break;
		default:			{RandRange("!~"			);for(int k0=0;k0<passwordsPerLine;k0++){for(int k=0;k<20;k++)putchar(RandRange::get());putchar(separator);}}break;//all characters
		}//*/
	/*	switch(c)
		{
		case '\r':			{RandRange("09AZaz"		);for(int k=0;k<20;k++)putchar(RandRange::get());}break;//alphanumeric
		case 'a':case 'A':	{RandRange("AZaz"		);for(int k=0;k<20;k++)putchar(RandRange::get());}break;//letters
		case 'b':			{RandRange("az"			);for(int k=0;k<20;k++)putchar(RandRange::get());}break;//small letters
		case 'B':			{RandRange("AZ"			);for(int k=0;k<20;k++)putchar(RandRange::get());}break;//capital letters
		case 'h':			{RandRange("09AF"		);for(int k=0;k<20;k++)putchar(RandRange::get());}break;//hexadecimal
		case 'H':			{RandRange("09af"		);for(int k=0;k<20;k++)putchar(RandRange::get());}break;//hexadecimal
		case '9':			{RandRange("09"			);for(int k=0;k<20;k++)putchar(RandRange::get());}break;//decimal
		case '7':			{RandRange("07"			);for(int k=0;k<20;k++)putchar(RandRange::get());}break;//octal
		case '1':			{RandRange("01"			);for(int k=0;k<20;k++)putchar(RandRange::get());}break;//binary
		case '!':			{RandRange("!/:@[`{~"	);for(int k=0;k<20;k++)putchar(RandRange::get());}break;//symbols
		case 'x':
			printf(	"\n"
					"Ascii to hex (esc (0x1B) to stop)\n");
			for(char c;(c=_getch())!=0x1B;)
				printf("%c\t0x%X\n", c, c);
			break;
		case 'z':
			printf(	"\n"
					"Hex to ascii\n");
			for(char d, d2, e, e2;;)
			{
				d=_getch();
				if((d2=charToHex(d))>=0)
				{
					printf("0x%c", d);
					e=_getch();
					if((e2=charToHex(e))>=0)
					{
						printf("%c\t%c\n", e, d2<<4|e2);
						continue;
					}
				}
				putchar('\n');
				break;
			}
			break;
		default:			{RandRange("!~"			);for(int k=0;k<20;k++)putchar(RandRange::get());}break;//all characters
		}//*/
	/*	switch(c)
		{
		case '\r':			for(int k=0;k<20;k++)putchar(rand_ranges(rand(), "09AZaz"	));break;//alphanumeric
		case 'a':case 'A':	for(int k=0;k<20;k++)putchar(rand_ranges(rand(), "AZaz"		));break;//letters
		case 'b':			for(int k=0;k<20;k++)putchar(rand_ranges(rand(), "az"		));break;//small letters
		case 'B':			for(int k=0;k<20;k++)putchar(rand_ranges(rand(), "AZ"		));break;//capital letters
		case 'h':			for(int k=0;k<20;k++)putchar(rand_ranges(rand(), "09AF"		));break;//hexadecimal
		case 'H':			for(int k=0;k<20;k++)putchar(rand_ranges(rand(), "09af"		));break;//hexadecimal
		case '9':			for(int k=0;k<20;k++)putchar(rand_ranges(rand(), "09"		));break;//decimal
		case '7':			for(int k=0;k<20;k++)putchar(rand_ranges(rand(), "07"		));break;//octal
		case '1':			for(int k=0;k<20;k++)putchar(rand_ranges(rand(), "01"		));break;//binary
		case '!':			for(int k=0;k<20;k++)putchar(rand_ranges(rand(), "!/:@[`{~"	));break;//symbols
		case 'x':
			printf(	"\n"
					"Ascii to hex (esc (0x1B) to stop)\n");
			for(char c;(c=_getch())!=0x1B;)
				printf("%c\t0x%X\n", c, c);
			break;
		case 'z':
			printf(	"\n"
					"Hex to ascii\n");
			for(char d, d2, e, e2;;)
			{
				d=_getch();
				if((d2=charToHex(d))>=0)
				{
					printf("0x%c", d);
					e=_getch();
					if((e2=charToHex(e))>=0)
					{
						printf("%c\t%c\n", e, d2<<4|e2);
						continue;
					}
				}
				putchar('\n');
				break;
			}
			break;
		default:			for(int k=0;k<20;k++)putchar(rand_ranges(rand(), "!~"		));break;//all characters
		}//*/
		putchar('\n');
	}

/*	printf(	"PASSWORD GENERATOR\n"
			"\n"
			"	  1 binary\n"
			"	  7 octal\n"
			"	  9 decimal\n"
			"	  h hexadecimal\n"
			"	  a small letters\n"
			"	  A capital letters\n"
			"	  b letters\n"
			"	  c alphanumerical\n"
			"	  x ascii to hex\n"
			"	  z hex to ascii\n"
			"	... all\n"
			"	esc exit\n"
			"\n");

	//printf(	"PASSWORD GENERATOR\n"
	//		"\n"
	//		"	1 binary		  a small letters\n"
	//		"	7 octal			  A capital letters\n"
	//		"	9 decimal		  b letters\n"
	//		"	h hexadecimal		  c alphanumerical\n"
	//		"\n"
	//		"	x ascii to hex		... all\n"
	//		"	z hex to ascii		esc exit\n"
	//		"\n");

	//printf(	"1 binary\n"
	//		"7 octal\n"
	//		"9 decimal\n"
	//		"h hexadecimal\n"
	//		"a small letters\n"
	//		"A capital letters\n"
	//		"b letters\n"
	//		"c alphanumerical\n"
	//		"x ascii to hex\n"
	//		"z hex to ascii\n"
	//		"... all\n"
	//		"esc exit\n"
	//		"\n");
	for(__int8 c='4';c!=0x1B;c=_getch())
	{
		QueryPerformanceCounter(&li);
		srand(li.LowPart);
		switch(c)
		{
		case '1':	for(int k=0;k<20;k++)putchar(rand_range	(rand(), "01"		));break;
		case '7':	for(int k=0;k<20;k++)putchar(rand_range	(rand(), "07"		));break;
		case '9':	for(int k=0;k<20;k++)putchar(rand_range	(rand(), "09"		));break;
		case 'h':	for(int k=0;k<20;k++)putchar(rand_range2(rand(), "09AF"		));break;
		case 'a':	for(int k=0;k<20;k++)putchar(rand_range	(rand(), "af"		));break;
		case 'A':	for(int k=0;k<20;k++)putchar(rand_range	(rand(), "AF"		));break;
		case 'b':	for(int k=0;k<20;k++)putchar(rand_range2(rand(), "AFaf"		));break;
		case 'c':	for(int k=0;k<20;k++)putchar(rand_range3(rand(), "09AFaf"	));break;
		case 'x':
			printf("\nAscii to hex (esc (0x1B) to stop)\n");
			for(char c;(c=_getch())!=0x1B;)
				printf("%c\t0x%X\n", c, c);
			break;
		case 'z':
			printf("\nHex to ascii\n");
			for(char d, d2, e, e2;;)
			{
				d=_getch();
				if((d2=charToHex(d))>=0)
				{
					printf("0x%c", d);
				//	printf("%c %d", d, d2);
					e=_getch();
					if((e2=charToHex(e))>=0)
					{
						printf("%c\t%c\n", e, d2<<4|e2);
					//	printf(" %c %d %c\n", e, e2, d2<<4|e2);
						continue;
					}
				}
				printf("\n");
				break;
			}
		//	for(char d, e;(d=charToHex(_getch()))>=0&&(e=charToHex(_getch()))>=0;)
		//		printf("%c %c %c", d, e, d<<4|e);
		//	printf("\n");
			break;
		default:	for(int k=0;k<20;k++)putchar(rand_range	(rand(), "!~"		));break;
		}
		printf(	"\t179haAbcxz...");
		putchar('\n');
	}//*/

/*	for(__int8 c='4';c!='x'&&c!='X';c=_getch())
	{
		printf(	"0 decimal\n"
				"a letter\n"
				"3 alphanumerical\n"
				"h hexadecimal\n"
				"8 octal\n"
				"... all\n"
				"\n");
		QueryPerformanceCounter(&li);
		srand(li.LowPart);
		for(int k=0;k<20;k++)
			putchar(randToChar(c, rand()));
		putchar('\n');
	}//*/

/*	printf(	"Type to place random characters.\n"
			"1 digit, 2 letter, 3 alphanumerical, ... all\n"
			"\n");*/
//	FILE *outFile=fopen("D:\\C++\\Password generator\\pg_out.txt", "w");

/*	for(int k=0;k<500000&&_getch()!='x';k++)
	{
		printf_s("%d\n", k);
		QueryPerformanceCounter(&li);
		fprintf_s(outFile, "%c", li.LowPart&0xFF);
	}*/
/*	C:\Users\Ayman>D:\random\Release\ent.exe -b D:\pg_out.txt	Entropy = 1.000000 bits per bit.	Optimum compression would reduce the size of this 4015216 bit file by 0 percent.	Chi square distribution for 4015216 samples is 2.14, and randomly would exceed this value 14.31 percent of the times.				Arithmetic mean value of data bits is 0.4996 (0.5 = random).		Monte Carlo value for Pi is 3.149408249 (error 0.25 percent).	Serial correlation coefficient is -0.000508 (totally uncorrelated = 0.0).
	C:\Users\Ayman>D:\random\Release\ent.exe D:\pg_out.txt		Entropy = 7.997484 bits per byte.	Optimum compression would reduce the size of this 501902 byte file by 0 percent.	Chi square distribution for 501902 samples is 2196.05, and randomly would exceed this value less than 0.01 percent of the times.	Arithmetic mean value of data bytes is 127.0727 (127.5 = random).	Monte Carlo value for Pi is 3.149408249 (error 0.25 percent).	Serial correlation coefficient is 0.008380 (totally uncorrelated = 0.0).
	*/

/*	for(__int8 c=_getch(), k=0, k2=0;c!='x'&&c!='X';c=_getch(), k=(k+1)%20, k2=(k2+1)%128)
	{
		QueryPerformanceCounter(&li);
		int r=li.LowPart&0xFF;
	//	printf("%08X\n", r);
		putchar(randToChar(c, r));
		if(k==19)
			putchar('\n');
	}*/
/*	ent.exe
	All:
		Entropy = 6.439181 bits per byte.
		Optimum compression would reduce the size of this 720 byte file by 19 percent.
		Chi square distribution for 720 samples is 1541.33, and randomly would exceed this value less than 0.01 percent of the times.
		Arithmetic mean value of data bytes is 75.4042 (127.5 = random).
		Monte Carlo value for Pi is 4.000000000 (error 27.32 percent).
		Serial correlation coefficient is -0.022160 (totally uncorrelated = 0.0).

	Letters:
		Value Char Occurrences Fraction
		 97   a           48   0.030769
		 98   b           60   0.038462
		 99   c           58   0.037179
		100   d           70   0.044872
		101   e           49   0.031410
		102   f           61   0.039103
		103   g           65   0.041667
		104   h           64   0.041026
		105   i           72   0.046154
		106   j           59   0.037821
		107   k           71   0.045513
		108   l           53   0.033974
		109   m           69   0.044231
		110   n           68   0.043590
		111   o           72   0.046154
		112   p           55   0.035256
		113   q           60   0.038462
		114   r           57   0.036538
		115   s           71   0.045513
		116   t           70   0.044872
		117   u           52   0.033333
		118   v           56   0.035897
		119   w           44   0.028205
		120   x           46   0.029487
		121   y           54   0.034615
		122   z           56   0.035897
		Total:          1560   1.000000

		Entropy = 4.685984 bits per byte.
		Optimum compression would reduce the size of this 1560 byte file by 41 percent.
		Chi square distribution for 1560 samples is 14104.25, and randomly would exceed this value less than 0.01 percent of the times.
		Arithmetic mean value of data bytes is 109.2724 (127.5 = random).
		Monte Carlo value for Pi is 4.000000000 (error 27.32 percent).
		Serial correlation coefficient is -0.019435 (totally uncorrelated = 0.0).
	*/

/*	for(__int8 c=_getch(), k=0, k2=0;c!='x'&&c!='X';c=_getch(), k=(k+1)%20, k2=(k2+1)%128)
	{
		QueryPerformanceCounter(&li);
		int seed=li.LowPart&0xFFFF;
		c=_getch();
		if(c=='x'||c=='X')
			break;
		QueryPerformanceCounter(&li);
		seed|=(li.LowPart&0xFFFF)<<16;
	//	printf("%08X\n", seed);
		srand(seed);
		int r=rand();
	//	printf("%08X\n", r);
		putchar(randToChar(c, r));
		if(k==19)
			putchar('\n');
	}*/
/*	ent.exe

	Letters:
		Value Char Occurrences Fraction
		 97   a           30   0.039474
		 98   b           31   0.040789
		 99   c           27   0.035526
		100   d           21   0.027632
		101   e           42   0.055263
		102   f           20   0.026316
		103   g           26   0.034211
		104   h           28   0.036842
		105   i           22   0.028947
		106   j           34   0.044737
		107   k           27   0.035526
		108   l           31   0.040789
		109   m           28   0.036842
		110   n           15   0.019737
		111   o           23   0.030263
		112   p           31   0.040789
		113   q           29   0.038158
		114   r           29   0.038158
		115   s           38   0.050000
		116   t           33   0.043421
		117   u           21   0.027632
		118   v           41   0.053947
		119   w           28   0.036842
		120   x           31   0.040789
		121   y           32   0.042105
		122   z           42   0.055263
		Total:           760   1.000000

		Entropy = 4.662979 bits per byte.
		Optimum compression would reduce the size of this 760 byte file by 41 percent.
		Chi square distribution for 760 samples is 7106.61, and randomly would exceed this value less than 0.01 percent of the times.
		Arithmetic mean value of data bytes is 109.9934 (127.5 = random).
		Monte Carlo value for Pi is 4.000000000 (error 27.32 percent).
		Serial correlation coefficient is -0.045272 (totally uncorrelated = 0.0).
	*/

/*	for(__int8 c=_getch(), k=0, k2=0;c!='x'&&c!='X';c=_getch(), k=(k+1)%20, k2=(k2+1)%128)
	{
	//	int t=li.LowPart;
		QueryPerformanceCounter(&li);
	//	printf("%016X\n", li.LowPart);
		srand(li.LowPart);
		int r=rand();
		switch(c)
		{
		case '1':
			putchar('0'+r%('9'+1-'0'));
			break;
		case '2':
			{
				int offset=r%('Z'+1-'A'+'z'+1-'a');
				putchar('A'+offset>'Z'?'a'+offset-('Z'+1-'A'):'A'+offset);
			}
			break;
		case '3':
			{
				int offset=r%('9'+1-'0'+'Z'+1-'A'+'z'+1-'a');
				putchar('0'+offset>'9'?'A'+offset-('9'+1-'0')>'Z'?'a'+offset-('9'+1-'0'+'Z'+1-'A'):'A'+offset-('9'+1-'0'):'0'+offset);
			}
			break;
		default:
			putchar('!'+r%('~'+1-'!'));
			break;
		}
		if(k==19)
			putchar('\n');
	}*/

/*	for(__int8 c=_getch(), k=0;c!='x'&&c!='X';c=_getch(), k=(k+1)%20)
	{
		QueryPerformanceCounter(&li);
		srand(li.LowPart);
		putchar('!'+rand()%('~'-'!'));
		if(k==19)
			putchar('\n');
	}*/

/*	for(__int8 c=0;c!='x'&&c!='X';c=_getch())
	{
		QueryPerformanceCounter(&li);
		srand(li.LowPart);
		for(int k=0;k<20;k++)
		{
			char _c='!'+rand()%('~'-'!');
			putchar(_c);
			fprintf_s(outFile, "%c", _c);
		}
	//	putchar('!'+rand()%('~'-'!'));
		putchar('\n');
	}*/
/*	ent.exe
	All:
		Entropy = 6.465092 bits per byte.
		Optimum compression would reduce the size of this 6578 byte file by 19 percent.
		Chi square distribution for 6578 samples is 15572.89, and randomly would exceed this value less than 0.01 percent of the times.
		Arithmetic mean value of data bytes is 72.6741 (127.5 = random).
		Monte Carlo value for Pi is 4.000000000 (error 27.32 percent).
		Serial correlation coefficient is 0.164957 (totally uncorrelated = 0.0).

		Entropy = 6.475253 bits per byte.
		Optimum compression would reduce the size of this 860 byte file by 19 percent.
		Chi square distribution for 860 samples is 1721.43, and randomly would exceed this value less than 0.01 percent of the times.
		Arithmetic mean value of data bytes is 78.7570 (127.5 = random).
		Monte Carlo value for Pi is 4.000000000 (error 27.32 percent).
		Serial correlation coefficient is -0.065615 (totally uncorrelated = 0.0).
	*/

/*	for(int k=0;k<500000/20;k++)
	{
		_getch();
		QueryPerformanceCounter(&li);
	//	printf("%d\n", li.LowPart);
		srand(li.LowPart);
		for(int k=0;k<20;k++)
			fprintf_s(outFile, "%c", rand()%256);//'!'+rand()%('~'-'!')
	}*/
/*	fuck this*/

/*	QueryPerformanceCounter(&li);
	srand(li.LowPart);
	for(int k=0;k<500000/20;k++)
	{
		for(int k=0;k<20;k++)
			fprintf_s(outFile, "%c", rand()%256);//'!'+rand()%('~'-'!')
	}*/
/*	C:\Users\Ayman>D:\random\Release\ent.exe -b D:\pg_out.txt	Entropy = 0.999999 bits per bit.	Optimum compression would reduce the size of this 4015248 bit file by 0 percent.	Chi square distribution for 4015248 samples is 4.00, and randomly would exceed this value 4.56 percent of the times.				Arithmetic mean value of data bits is 0.4995 (0.5 = random).		Monte Carlo value for Pi is 3.150231318 (error 0.27 percent).	Serial correlation coefficient is 0.000193 (totally uncorrelated = 0.0).
	C:\Users\Ayman>D:\random\Release\ent.exe D:\pg_out.txt		Entropy = 7.997461 bits per byte.	Optimum compression would reduce the size of this 501906 byte file by 0 percent.	Chi square distribution for 501906 samples is 2213.04, and randomly would exceed this value less than 0.01 percent of the times.	Arithmetic mean value of data bytes is 127.0982 (127.5 = random).	Monte Carlo value for Pi is 3.150231318 (error 0.27 percent).	Serial correlation coefficient is 0.009076 (totally uncorrelated = 0.0).
	*/

/*	for(int k=0;k<500000/20;k++)
	{
		QueryPerformanceCounter(&li);
	//	printf("%d\n", li.LowPart);
		srand(li.LowPart);
		for(int k=0;k<20;k++)
			fprintf_s(outFile, "%c", rand()%256);//'!'+rand()%('~'-'!')
	}*/
/*	C:\Users\Ayman>D:\random\Release\ent.exe -b D:\pg_out.txt	Entropy = 0.999999 bits per bit.	Optimum compression would reduce the size of this 4015664 bit file by 0 percent.	Chi square distribution for 4015664 samples is 6.65, and randomly would exceed this value 0.99 percent of the times.				Arithmetic mean value of data bits is 0.4994 (0.5 = random).		Monte Carlo value for Pi is 3.150169139 (error 0.27 percent).	Serial correlation coefficient is 0.000329 (totally uncorrelated = 0.0).
	C:\Users\Ayman>D:\random\Release\ent.exe D:\pg_out.txt		Entropy = 7.997644 bits per byte.	Optimum compression would reduce the size of this 501958 byte file by 0 percent.	Chi square distribution for 501958 samples is 2047.65, and randomly would exceed this value less than 0.01 percent of the times.	Arithmetic mean value of data bytes is 127.0534 (127.5 = random).	Monte Carlo value for Pi is 3.150169139 (error 0.27 percent).	Serial correlation coefficient is 0.010589 (totally uncorrelated = 0.0).

	C:\Users\Ayman>D:\random\Release\ent.exe -b D:\pg_out.txt	Entropy = 1.000000 bits per bit.	Optimum compression would reduce the size of this 4015928 bit file by 0 percent.	Chi square distribution for 4015928 samples is 2.09, and randomly would exceed this value 14.87 percent of the times.				Arithmetic mean value of data bits is 0.4996 (0.5 = random).		Monte Carlo value for Pi is 3.147887408 (error 0.20 percent).	Serial correlation coefficient is 0.000225 (totally uncorrelated = 0.0).
	C:\Users\Ayman>D:\random\Release\ent.exe D:\pg_out.txt		Entropy = 7.997427 bits per byte.	Optimum compression would reduce the size of this 501991 byte file by 0 percent.	Chi square distribution for 501991 samples is 2245.85, and randomly would exceed this value less than 0.01 percent of the times.	Arithmetic mean value of data bytes is 127.0495 (127.5 = random).	Monte Carlo value for Pi is 3.147887408 (error 0.20 percent).	Serial correlation coefficient is 0.008843 (totally uncorrelated = 0.0).

	C:\Users\Ayman>D:\random\Release\ent.exe -b D:\pg_out.txt	Entropy = 0.999999 bits per bit.	Optimum compression would reduce the size of this 4015184 bit file by 0 percent.	Chi square distribution for 4015184 samples is 3.06, and randomly would exceed this value 8.03 percent of the times.				Arithmetic mean value of data bits is 0.4996 (0.5 = random).		Monte Carlo value for Pi is 3.160109505 (error 0.59 percent).	Serial correlation coefficient is 0.000175 (totally uncorrelated = 0.0).
	C:\Users\Ayman>D:\random\Release\ent.exe D:\pg_out.txt		Entropy = 7.997663 bits per byte.	Optimum compression would reduce the size of this 501898 byte file by 0 percent.	Chi square distribution for 501898 samples is 2023.10, and randomly would exceed this value less than 0.01 percent of the times.	Arithmetic mean value of data bytes is 127.0377 (127.5 = random).	Monte Carlo value for Pi is 3.160109505 (error 0.59 percent).	Serial correlation coefficient is 0.009745 (totally uncorrelated = 0.0).

	C:\Users\Ayman>D:\random\Release\ent.exe -b D:\pg_out.txt	Entropy = 1.000000 bits per bit.	Optimum compression would reduce the size of this 4015312 bit file by 0 percent.	Chi square distribution for 4015312 samples is 1.58, and randomly would exceed this value 20.82 percent of the times.				Arithmetic mean value of data bits is 0.4997 (0.5 = random).		Monte Carlo value for Pi is 3.153349591 (error 0.37 percent).	Serial correlation coefficient is 0.000355 (totally uncorrelated = 0.0).
	C:\Users\Ayman>D:\random\Release\ent.exe D:\pg_out.txt		Entropy = 7.997502 bits per byte.	Optimum compression would reduce the size of this 501914 byte file by 0 percent.	Chi square distribution for 501914 samples is 2172.18, and randomly would exceed this value less than 0.01 percent of the times.	Arithmetic mean value of data bytes is 126.9748 (127.5 = random).	Monte Carlo value for Pi is 3.153349591 (error 0.37 percent).	Serial correlation coefficient is 0.008483 (totally uncorrelated = 0.0).

	C:\Users\Ayman>D:\random\Release\ent.exe -b D:\pg_out.txt	Entropy = 0.999999 bits per bit.	Optimum compression would reduce the size of this 4014960 bit file by 0 percent.	Chi square distribution for 4014960 samples is 5.52, and randomly would exceed this value 1.88 percent of the times.				Arithmetic mean value of data bits is 0.4994 (0.5 = random).		Monte Carlo value for Pi is 3.142423337 (error 0.03 percent).	Serial correlation coefficient is 0.000600 (totally uncorrelated = 0.0).
	C:\Users\Ayman>D:\random\Release\ent.exe D:\pg_out.txt		Entropy = 7.997676 bits per byte.	Optimum compression would reduce the size of this 501870 byte file by 0 percent.	Chi square distribution for 501870 samples is 1994.19, and randomly would exceed this value less than 0.01 percent of the times.	Arithmetic mean value of data bytes is 127.1466 (127.5 = random).	Monte Carlo value for Pi is 3.142423337 (error 0.03 percent).	Serial correlation coefficient is 0.006780 (totally uncorrelated = 0.0).

	C:\Users\Ayman>D:\random\Release\ent.exe -b D:\pg_out.txt	Entropy = 0.999998 bits per bit.	Optimum compression would reduce the size of this 4015568 bit file by 0 percent.	Chi square distribution for 4015568 samples is 9.57, and randomly would exceed this value 0.20 percent of the times.				Arithmetic mean value of data bits is 0.4992 (0.5 = random).		Monte Carlo value for Pi is 3.151822322 (error 0.33 percent).	Serial correlation coefficient is 0.000019 (totally uncorrelated = 0.0).

	C:\Users\Ayman>D:\random\Release\ent.exe -b D:\pg_out.txt	Entropy = 1.000000 bits per bit.	Optimum compression would reduce the size of this 4015872 bit file by 0 percent.	Chi square distribution for 4015872 samples is 1.29, and randomly would exceed this value 25.52 percent of the times.				Arithmetic mean value of data bits is 0.4997 (0.5 = random).		Monte Carlo value for Pi is 3.138028304 (error 0.11 percent).	Serial correlation coefficient is -0.000157 (totally uncorrelated = 0.0).
	C:\Users\Ayman>D:\random\Release\ent.exe D:\pg_out.txt		Entropy = 7.997305 bits per byte.	Optimum compression would reduce the size of this 502038 byte file by 0 percent.	Chi square distribution for 502038 samples is 2368.10, and randomly would exceed this value less than 0.01 percent of the times.	Arithmetic mean value of data bytes is 127.0685 (127.5 = random).	Monte Carlo value for Pi is 3.150645967 (error 0.29 percent).	Serial correlation coefficient is 0.011124 (totally uncorrelated = 0.0).

																Entropy = 6.539017 bits per byte.	Optimum compression would reduce the size of this 500000 byte file by 18 percent.	Chi square distribution for 500000 samples is 876615.89, and randomly would exceed this value less than 0.01 percent of the times.	Arithmetic mean value of data bytes is 78.9393 (127.5 = random).	Monte Carlo value for Pi is 4.000000000 (error 27.32 percent).	Serial correlation coefficient is 0.000118 (totally uncorrelated = 0.0).
	*/

//	fclose(outFile);
//	_getch();
}
/*#include<string>
#include<fstream>
void main()
{
	auto encode_utf8=[](int cp, std::string &str)
	{
		if(cp<0)
			return;
		if(cp<0x80)
			str+=cp;
		else if(cp<0x800)
			str+=0xC0|cp>>6, str+=0x80|cp&0x3F;
		else if(cp<0x10000)
			str+=0xE0|cp>>12, str+=0x80|cp>> 6&0x3F, str+=0x80|cp&0x3F;
		else if(cp<0x200000)
			str+=0xF0|cp>>18, str+=0x80|cp>>12&0x3F, str+=0x80|cp>>6&0x3F, str+=0x80|cp&0x3F;
		else if(cp<0x4000000)
			str+=0xF8|cp>>24, str+=0x80|cp>>18&0x3F, str+=0x80|cp>>12&0x3F, str+=0x80|cp>>6&0x3F, str+=0x80|cp&0x3F;
		else
			str+=0xFC|cp>>30, str+=0x80|cp>>24&0x3F, str+=0x80|cp>>18&0x3F, str+=0x80|cp>>12&0x3F, str+=0x80|cp>>6&0x3F, str+=0x80|cp&0x3F;
	};
	auto print_unicode_range=[&](int start, int end, std::string &str)
	{
		const int buf_size=1024;
		char a[buf_size];
		int linelen=100;
		for(int k=start;k<end;)
		{
			sprintf_s(a, "[0x%04X, %d]", k, k);
			str+=a;
			int kNext=linelen*((k+linelen)/linelen);
			for(int k2=k;k2<kNext;k2++)
				encode_utf8(k2, str);
			str+="\n";
		//	str+="\r\n";
			k=kNext;
		}
	};
	std::string str;
	print_unicode_range(1, 0x30000, str);
	print_unicode_range(0xE0000, 0x110000, str);
	std::ofstream file("D:/1.txt", std::ios::out|std::ios::binary);
	unsigned char smarker[]={0xEF, 0xBB, 0xBF, 0};//http://stackoverflow.com/questions/3973582/how-do-i-write-a-utf-8-encoded-string-to-a-file-in-windows-in-c
	file<<smarker;
	file<<str;
	file.close();
}//*/
/*#include<fstream>
#include<string>
void main()
{
	wchar_t a[1024];
	std::wstring wstr;
	for(int k=1;k<0x10000;)
	{
		swprintf(a, L"[0x%04X, %d]", k, k);
		wstr+=a;
		int kNext=100*((k+100)/100);
		for(int k2=k;k2<kNext;k2++)
		{
			wstr+=wchar_t(k2);
		}
		wstr+=L"\n";
		k=kNext;
	}
	std::wofstream f=std::wofstream("D:/1.txt");
	f<<wstr;
	f.close();
}*/
#endif