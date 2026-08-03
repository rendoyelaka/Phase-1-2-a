/* sha256.c — self-contained SHA-256 + HMAC-SHA256 + HKDF-SHA256
 * No external dependencies. Works on Android NDK 25+.
 * RFC 4634 (SHA-256), RFC 2104 (HMAC), RFC 5869 (HKDF). */
#include "sha256.h"
#include <string.h>
#include <stdlib.h>

static const uint32_t K[64] = {
    0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
    0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
    0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
    0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
    0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
    0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
    0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
    0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2
};

#define RR(x,n) (((x)>>(n))|((x)<<(32-(n))))
#define CH(x,y,z)  (((x)&(y))^(~(x)&(z)))
#define MAJ(x,y,z) (((x)&(y))^((x)&(z))^((y)&(z)))
#define S0(x) (RR(x,2)^RR(x,13)^RR(x,22))
#define S1(x) (RR(x,6)^RR(x,11)^RR(x,25))
#define G0(x) (RR(x,7)^RR(x,18)^((x)>>3))
#define G1(x) (RR(x,17)^RR(x,19)^((x)>>10))

static void compress(uint32_t s[8], const uint8_t b[64]) {
    uint32_t W[64],a,bv,c,d,e,f,g,h,T1,T2; int i;
    for(i=0;i<16;i++) W[i]=((uint32_t)b[i*4]<<24)|((uint32_t)b[i*4+1]<<16)|((uint32_t)b[i*4+2]<<8)|(uint32_t)b[i*4+3];
    for(i=16;i<64;i++) W[i]=G1(W[i-2])+W[i-7]+G0(W[i-15])+W[i-16];
    a=s[0];bv=s[1];c=s[2];d=s[3];e=s[4];f=s[5];g=s[6];h=s[7];
    for(i=0;i<64;i++){T1=h+S1(e)+CH(e,f,g)+K[i]+W[i];T2=S0(a)+MAJ(a,bv,c);h=g;g=f;f=e;e=d+T1;d=c;c=bv;bv=a;a=T1+T2;}
    s[0]+=a;s[1]+=bv;s[2]+=c;s[3]+=d;s[4]+=e;s[5]+=f;s[6]+=g;s[7]+=h;
}

void sha256(const uint8_t* data, size_t len, uint8_t digest[32]) {
    uint32_t s[8]={0x6a09e667,0xbb67ae85,0x3c6ef372,0xa54ff53a,0x510e527f,0x9b05688c,0x1f83d9ab,0x5be0cd19};
    uint8_t buf[64]; int bl=0; uint64_t cnt=0; size_t i;
    for(i=0;i<len;i++){buf[bl++]=(uint8_t)data[i];cnt++;if(bl==64){compress(s,buf);bl=0;}}
    uint64_t bits=cnt*8; buf[bl++]=0x80;
    while(bl!=56){if(bl==64){compress(s,buf);bl=0;}buf[bl++]=0;}
    for(i=0;i<8;i++) buf[56+i]=(uint8_t)(bits>>((7-i)*8));
    compress(s,buf);
    for(i=0;i<8;i++){digest[i*4]=(uint8_t)(s[i]>>24);digest[i*4+1]=(uint8_t)(s[i]>>16);digest[i*4+2]=(uint8_t)(s[i]>>8);digest[i*4+3]=(uint8_t)s[i];}
}

void hmac_sha256(const uint8_t* key, size_t klen, const uint8_t* msg, size_t mlen, uint8_t digest[32]) {
    uint8_t k[64]={0},ipad[64],opad[64],inner[32]; size_t i;
    if(klen>64){sha256(key,klen,k);}else{memcpy(k,key,klen);}
    for(i=0;i<64;i++){ipad[i]=k[i]^0x36;opad[i]=k[i]^0x5c;}
    uint32_t s1[8]={0x6a09e667,0xbb67ae85,0x3c6ef372,0xa54ff53a,0x510e527f,0x9b05688c,0x1f83d9ab,0x5be0cd19};
    uint8_t b1[64]; int l1=0; uint64_t c1=0;
    for(i=0;i<64;i++){b1[l1++]=ipad[i];c1++;if(l1==64){compress(s1,b1);l1=0;}}
    for(i=0;i<mlen;i++){b1[l1++]=msg[i];c1++;if(l1==64){compress(s1,b1);l1=0;}}
    {uint64_t bits=c1*8;b1[l1++]=0x80;while(l1!=56){if(l1==64){compress(s1,b1);l1=0;}b1[l1++]=0;}
    for(i=0;i<8;i++)b1[56+i]=(uint8_t)(bits>>((7-i)*8));compress(s1,b1);}
    for(i=0;i<8;i++){inner[i*4]=(uint8_t)(s1[i]>>24);inner[i*4+1]=(uint8_t)(s1[i]>>16);inner[i*4+2]=(uint8_t)(s1[i]>>8);inner[i*4+3]=(uint8_t)s1[i];}
    uint32_t s2[8]={0x6a09e667,0xbb67ae85,0x3c6ef372,0xa54ff53a,0x510e527f,0x9b05688c,0x1f83d9ab,0x5be0cd19};
    uint8_t b2[64]; int l2=0; uint64_t c2=0;
    for(i=0;i<64;i++){b2[l2++]=opad[i];c2++;if(l2==64){compress(s2,b2);l2=0;}}
    for(i=0;i<32;i++){b2[l2++]=inner[i];c2++;if(l2==64){compress(s2,b2);l2=0;}}
    {uint64_t bits=c2*8;b2[l2++]=0x80;while(l2!=56){if(l2==64){compress(s2,b2);l2=0;}b2[l2++]=0;}
    for(i=0;i<8;i++)b2[56+i]=(uint8_t)(bits>>((7-i)*8));compress(s2,b2);}
    for(i=0;i<8;i++){digest[i*4]=(uint8_t)(s2[i]>>24);digest[i*4+1]=(uint8_t)(s2[i]>>16);digest[i*4+2]=(uint8_t)(s2[i]>>8);digest[i*4+3]=(uint8_t)s2[i];}
}

void hkdf_sha256(const uint8_t* salt, size_t salt_len, const uint8_t* ikm, size_t ikm_len,
                 const uint8_t* info, size_t info_len, uint8_t* okm, size_t okm_len) {
    static const uint8_t zeros[32]={0};
    if(!salt||salt_len==0){salt=zeros;salt_len=32;}
    uint8_t prk[32]; hmac_sha256(salt,salt_len,ikm,ikm_len,prk);
    uint8_t t[32]={0}; size_t done=0; uint8_t ctr=1;
    while(done<okm_len){
        size_t blen=0;
        uint8_t* buf=(uint8_t*)malloc((ctr>1?32:0)+info_len+1);
        if(!buf)return;
        if(ctr>1){memcpy(buf,t,32);blen+=32;}
        if(info&&info_len>0){memcpy(buf+blen,info,info_len);blen+=info_len;}
        buf[blen++]=ctr++;
        hmac_sha256(prk,32,buf,blen,t);
        free(buf);
        size_t cp=okm_len-done; if(cp>32)cp=32;
        memcpy(okm+done,t,cp); done+=cp;
    }
}
