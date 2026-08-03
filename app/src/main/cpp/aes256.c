/* aes256.c — AES-256-GCM, self-contained, no OpenSSL.
 * FIPS 197 AES core + NIST SP 800-38D GCM mode. */
#include "aes256.h"
#include "mem_wipe.h"
#include <string.h>
#include <stdlib.h>

static const uint8_t SB[256]={
0x63,0x7c,0x77,0x7b,0xf2,0x6b,0x6f,0xc5,0x30,0x01,0x67,0x2b,0xfe,0xd7,0xab,0x76,
0xca,0x82,0xc9,0x7d,0xfa,0x59,0x47,0xf0,0xad,0xd4,0xa2,0xaf,0x9c,0xa4,0x72,0xc0,
0xb7,0xfd,0x93,0x26,0x36,0x3f,0xf7,0xcc,0x34,0xa5,0xe5,0xf1,0x71,0xd8,0x31,0x15,
0x04,0xc7,0x23,0xc3,0x18,0x96,0x05,0x9a,0x07,0x12,0x80,0xe2,0xeb,0x27,0xb2,0x75,
0x09,0x83,0x2c,0x1a,0x1b,0x6e,0x5a,0xa0,0x52,0x3b,0xd6,0xb3,0x29,0xe3,0x2f,0x84,
0x53,0xd1,0x00,0xed,0x20,0xfc,0xb1,0x5b,0x6a,0xcb,0xbe,0x39,0x4a,0x4c,0x58,0xcf,
0xd0,0xef,0xaa,0xfb,0x43,0x4d,0x33,0x85,0x45,0xf9,0x02,0x7f,0x50,0x3c,0x9f,0xa8,
0x51,0xa3,0x40,0x8f,0x92,0x9d,0x38,0xf5,0xbc,0xb6,0xda,0x21,0x10,0xff,0xf3,0xd2,
0xcd,0x0c,0x13,0xec,0x5f,0x97,0x44,0x17,0xc4,0xa7,0x7e,0x3d,0x64,0x5d,0x19,0x73,
0x60,0x81,0x4f,0xdc,0x22,0x2a,0x90,0x88,0x46,0xee,0xb8,0x14,0xde,0x5e,0x0b,0xdb,
0xe0,0x32,0x3a,0x0a,0x49,0x06,0x24,0x5c,0xc2,0xd3,0xac,0x62,0x91,0x95,0xe4,0x79,
0xe7,0xc8,0x37,0x6d,0x8d,0xd5,0x4e,0xa9,0x6c,0x56,0xf4,0xea,0x65,0x7a,0xae,0x08,
0xba,0x78,0x25,0x2e,0x1c,0xa6,0xb4,0xc6,0xe8,0xdd,0x74,0x1f,0x4b,0xbd,0x8b,0x8a,
0x70,0x3e,0xb5,0x66,0x48,0x03,0xf6,0x0e,0x61,0x35,0x57,0xb9,0x86,0xc1,0x1d,0x9e,
0xe1,0xf8,0x98,0x11,0x69,0xd9,0x8e,0x94,0x9b,0x1e,0x87,0xe9,0xce,0x55,0x28,0xdf,
0x8c,0xa1,0x89,0x0d,0xbf,0xe6,0x42,0x68,0x41,0x99,0x2d,0x0f,0xb0,0x54,0xbb,0x16};

static const uint8_t RC[11]={0x01,0x02,0x04,0x08,0x10,0x20,0x40,0x80,0x1b,0x36,0x6c};

static uint8_t gm(uint8_t a,uint8_t b){
    uint8_t r=0;int i;
    for(i=0;i<8;i++){if(b&1)r^=a;uint8_t h=a>>7;a<<=1;if(h)a^=0x1b;b>>=1;}
    return r;
}

typedef struct{uint8_t rk[240];}AES_CTX;

static void expand(AES_CTX*c,const uint8_t k[32]){
    uint8_t*w=c->rk; memcpy(w,k,32); int i;
    for(i=8;i<60;i++){
        uint8_t t[4]; memcpy(t,w+(i-1)*4,4);
        if(i%8==0){uint8_t tmp=t[0];t[0]=SB[t[1]]^RC[i/8-1];t[1]=SB[t[2]];t[2]=SB[t[3]];t[3]=SB[tmp];}
        else if(i%8==4){t[0]=SB[t[0]];t[1]=SB[t[1]];t[2]=SB[t[2]];t[3]=SB[t[3]];}
        int j;for(j=0;j<4;j++)w[i*4+j]=w[(i-8)*4+j]^t[j];
    }
}

static void enc_block(const AES_CTX*c,const uint8_t in[16],uint8_t out[16]){
    uint8_t s[16],t[16];int r,i;
    for(i=0;i<16;i++)s[i]=in[i]^c->rk[i];
    for(r=1;r<14;r++){
        t[0]=SB[s[0]];t[1]=SB[s[5]];t[2]=SB[s[10]];t[3]=SB[s[15]];
        t[4]=SB[s[4]];t[5]=SB[s[9]];t[6]=SB[s[14]];t[7]=SB[s[3]];
        t[8]=SB[s[8]];t[9]=SB[s[13]];t[10]=SB[s[2]];t[11]=SB[s[7]];
        t[12]=SB[s[12]];t[13]=SB[s[1]];t[14]=SB[s[6]];t[15]=SB[s[11]];
        for(i=0;i<4;i++){uint8_t a=t[i*4],b=t[i*4+1],cv=t[i*4+2],d=t[i*4+3];
            s[i*4]=gm(a,2)^gm(b,3)^cv^d;s[i*4+1]=a^gm(b,2)^gm(cv,3)^d;
            s[i*4+2]=a^b^gm(cv,2)^gm(d,3);s[i*4+3]=gm(a,3)^b^cv^gm(d,2);}
        for(i=0;i<16;i++)s[i]^=c->rk[r*16+i];
    }
    t[0]=SB[s[0]];t[1]=SB[s[5]];t[2]=SB[s[10]];t[3]=SB[s[15]];
    t[4]=SB[s[4]];t[5]=SB[s[9]];t[6]=SB[s[14]];t[7]=SB[s[3]];
    t[8]=SB[s[8]];t[9]=SB[s[13]];t[10]=SB[s[2]];t[11]=SB[s[7]];
    t[12]=SB[s[12]];t[13]=SB[s[1]];t[14]=SB[s[6]];t[15]=SB[s[11]];
    for(i=0;i<16;i++)out[i]=t[i]^c->rk[14*16+i];
}

static void gmul128(const uint8_t X[16],const uint8_t Y[16],uint8_t Z[16]){
    uint8_t z[16]={0},v[16];int i,j;
    memcpy(v,Y,16);
    for(i=0;i<16;i++)for(j=7;j>=0;j--){
        if((X[i]>>j)&1){int k;for(k=0;k<16;k++)z[k]^=v[k];}
        uint8_t lsb=v[15]&1;int k;
        for(k=15;k>0;k--)v[k]=(v[k]>>1)|(v[k-1]<<7);
        v[0]>>=1;if(lsb)v[0]^=0xe1;
    }
    memcpy(Z,z,16);
}

static void ghash(const uint8_t H[16],const uint8_t*aad,size_t al,
                  const uint8_t*ct,size_t cl,uint8_t tag[16]){
    uint8_t X[16]={0};size_t i;
    for(i=0;i<al;){uint8_t b[16]={0};size_t n=al-i<16?al-i:16;
        memcpy(b,aad+i,n);i+=n;int k;for(k=0;k<16;k++)X[k]^=b[k];gmul128(X,H,X);}
    for(i=0;i<cl;){uint8_t b[16]={0};size_t n=cl-i<16?cl-i:16;
        memcpy(b,ct+i,n);i+=n;int k;for(k=0;k<16;k++)X[k]^=b[k];gmul128(X,H,X);}
    uint8_t lb[16];uint64_t ab=(uint64_t)al*8,cb=(uint64_t)cl*8;
    int k;for(k=0;k<8;k++){lb[k]=(uint8_t)(ab>>((7-k)*8));lb[8+k]=(uint8_t)(cb>>((7-k)*8));}
    for(k=0;k<16;k++)X[k]^=lb[k];gmul128(X,H,X);memcpy(tag,X,16);
}

static void ctr(const AES_CTX*c,const uint8_t iv[12],uint32_t start,
                const uint8_t*in,size_t len,uint8_t*out){
    uint8_t J[16]={0},ks[16];memcpy(J,iv,12);uint32_t n=start;size_t i=0;
    while(i<len){J[12]=(n>>24)&0xff;J[13]=(n>>16)&0xff;J[14]=(n>>8)&0xff;J[15]=n&0xff;n++;
        enc_block(c,J,ks);size_t b=len-i<16?len-i:16;size_t j;for(j=0;j<b;j++)out[i+j]=in[i+j]^ks[j];i+=b;}
}

int aes256_gcm_encrypt(const uint8_t*key,const uint8_t*iv,
                       const uint8_t*aad,size_t al,const uint8_t*plain,size_t pl,
                       uint8_t*cipher,uint8_t tag[16]){
    AES_CTX c;expand(&c,key);
    uint8_t H[16]={0};enc_block(&c,H,H);
    ctr(&c,iv,2,plain,pl,cipher);
    uint8_t S[16];ghash(H,aad,al,cipher,pl,S);
    uint8_t J0[16]={0};memcpy(J0,iv,12);J0[15]=1;uint8_t E[16];enc_block(&c,J0,E);
    int i;for(i=0;i<16;i++)tag[i]=S[i]^E[i];
    secure_wipe(&c,sizeof(c));return 1;
}

int aes256_gcm_decrypt(const uint8_t*key,const uint8_t*iv,
                       const uint8_t*aad,size_t al,const uint8_t*cipher,size_t cl,
                       const uint8_t tag[16],uint8_t*plain){
    AES_CTX c;expand(&c,key);
    uint8_t H[16]={0};enc_block(&c,H,H);
    uint8_t S[16];ghash(H,aad,al,cipher,cl,S);
    uint8_t J0[16]={0};memcpy(J0,iv,12);J0[15]=1;uint8_t E[16];enc_block(&c,J0,E);
    uint8_t ct[16];int i;for(i=0;i<16;i++)ct[i]=S[i]^E[i];
    uint8_t diff=0;for(i=0;i<16;i++)diff|=(ct[i]^tag[i]);
    if(diff!=0){secure_wipe(&c,sizeof(c));return 0;}
    ctr(&c,iv,2,cipher,cl,plain);
    secure_wipe(&c,sizeof(c));return 1;
}
