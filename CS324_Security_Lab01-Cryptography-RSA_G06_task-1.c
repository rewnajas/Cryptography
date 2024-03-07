#include <stdio.h>
#include <openssl/bn.h>
#define NBITS 256
void printBN(char *msg, BIGNUM *a){ 
char * number_str = BN_bn2hex(a);
printf("%s %s\n", msg, number_str); 
OPENSSL_free(number_str);
}
int main(){
BN_CTX *ctx = BN_CTX_new();
BIGNUM *p = BN_new();
BIGNUM *q = BN_new();
BIGNUM *e = BN_new();
BIGNUM *d = BN_new();
BIGNUM *r1 = BN_new();
BIGNUM *r2 = BN_new();
BIGNUM *r3 = BN_new();
BIGNUM *one = BN_new();
BN_hex2bn(&p, "F7E75FDC469067FFDC4E847C51F452DF");
BN_hex2bn(&q, "E85CED54AF57E53E092113E62F436F4F");
BN_hex2bn(&e, "0D88C3");
BN_dec2bn(&one,"1");
BN_sub(r1, p, one);
BN_sub(r2, q, one);
BN_mul(r3, r1, r2, ctx);
BN_mod_inverse(d, e, r3, ctx);
printBN("d = ",d);
return 0;
}

