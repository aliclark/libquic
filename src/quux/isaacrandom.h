/*
 * Random.h
 *
 *  Created on: Jul 1, 2016
 *      Author: user
 */

#ifndef SRC_QUUX_ISAACRANDOM_H_
#define SRC_QUUX_ISAACRANDOM_H_

#include <crypto/random.h>
#include <net/quic/crypto/quic_random.h>
#include <cstdint>
#include <cstdio>

namespace {

/*
 ------------------------------------------------------------------------------
 Standard definitions and types, Bob Jenkins
 ------------------------------------------------------------------------------
 */
#ifndef STANDARD
# define STANDARD
# ifndef STDIO
#  include <stdio.h>
#  define STDIO
# endif
# ifndef STDDEF
#  include <stddef.h>
#  define STDDEF
# endif
typedef uint64_t ub8;
#define UB8MAXVAL 0xffffffffffffffffLL
#define UB8BITS 64
typedef int64_t sb8;
#define SB8MAXVAL 0x7fffffffffffffffLL
typedef uint32_t ub4; /* unsigned 4-byte quantities */
#define UB4MAXVAL 0xffffffff
typedef int64_t sb4;
#define UB4BITS 32
#define SB4MAXVAL 0x7fffffff
typedef uint16_t ub2;
#define UB2MAXVAL 0xffff
#define UB2BITS 16
typedef int16_t sb2;
#define SB2MAXVAL 0x7fff
typedef uint8_t ub1;
#define UB1MAXVAL 0xff
#define UB1BITS 8
typedef int8_t sb1; /* signed 1-byte quantities */
#define SB1MAXVAL 0x7f
typedef int word; /* fastest type available */

#define bis(target,mask)  ((target) |=  (mask))
#define bic(target,mask)  ((target) &= ~(mask))
#define bit(target,mask)  ((target) &   (mask))
#ifndef min
# define min(a,b) (((a)<(b)) ? (a) : (b))
#endif /* min */
#ifndef max
# define max(a,b) (((a)<(b)) ? (b) : (a))
#endif /* max */
#ifndef align
# define align(a) (((ub4)a+(sizeof(void *)-1))&(~(sizeof(void *)-1)))
#endif /* align */
#ifndef abs
# define abs(a)   (((a)>0) ? (a) : -(a))
#endif
#define TRUE  1
#define FALSE 0
#define SUCCESS 0  /* 1 on VAX */

#endif /* STANDARD */

/*
 ------------------------------------------------------------------------------
 isaac64.h: definitions for a random number generator
 Bob Jenkins, 1996, Public Domain
 ------------------------------------------------------------------------------
 */
#ifndef STANDARD
#include "standard.h"
#endif

#ifndef ISAAC64
#define ISAAC64

#define RANDSIZL   (8)
#define RANDSIZ    (1<<RANDSIZL)

ub8 randrsl[RANDSIZ], randcnt;

/*
 ------------------------------------------------------------------------------
 If (flag==TRUE), then use the contents of randrsl[0..255] as the seed.
 ------------------------------------------------------------------------------
 */
void randinit(word flag);

void isaac64();

/*
 ------------------------------------------------------------------------------
 Call rand() to retrieve a single 64-bit random value
 ------------------------------------------------------------------------------
 */
#define rand() \
   (!randcnt-- ? (isaac64(), randcnt=RANDSIZ-1, randrsl[randcnt]) : \
                 randrsl[randcnt])

#endif  /* RAND */

/*
 ------------------------------------------------------------------------------
 isaac64.c: My random number generator for 64-bit machines.
 By Bob Jenkins, 1996.  Public Domain.
 ------------------------------------------------------------------------------
 */
#ifndef STANDARD
#include "standard.h"
#endif
#ifndef ISAAC64
#include "isaac64.h"
#endif

extern ub8 randrsl[RANDSIZ], randcnt;
static ub8 mm[RANDSIZ];
static ub8 aa = 0, bb = 0, cc = 0;

#define ind(mm,x)  (*(ub8 *)((ub1 *)(mm) + ((x) & ((RANDSIZ-1)<<3))))
#define rngstep(mix,a,b,mm,m,m2,r,x) \
{ \
  x = *m;  \
  a = (mix) + *(m2++); \
  *(m++) = y = ind(mm,x) + a + b; \
  *(r++) = b = ind(mm,y>>RANDSIZL) + x; \
}

void isaac64() {
	ub8 a, b, x, y, *m, *m2, *r, *mend;
	m = mm;
	r = randrsl;
	a = aa;
	b = bb + (++cc);
	for (m = mm, mend = m2 = m + (RANDSIZ / 2); m < mend;) {
		rngstep(~(a ^ (a << 21)), a, b, mm, m, m2, r, x);
		rngstep(a ^ (a >> 5), a, b, mm, m, m2, r, x);
		rngstep(a ^ (a << 12), a, b, mm, m, m2, r, x);
		rngstep(a ^ (a >> 33), a, b, mm, m, m2, r, x);
	}
	for (m2 = mm; m2 < mend;) {
		rngstep(~(a ^ (a << 21)), a, b, mm, m, m2, r, x);
		rngstep(a ^ (a >> 5), a, b, mm, m, m2, r, x);
		rngstep(a ^ (a << 12), a, b, mm, m, m2, r, x);
		rngstep(a ^ (a >> 33), a, b, mm, m, m2, r, x);
	}
	bb = b;
	aa = a;
}

#define mix(a,b,c,d,e,f,g,h) \
{ \
   a-=e; f^=h>>9;  h+=a; \
   b-=f; g^=a<<9;  a+=b; \
   c-=g; h^=b>>23; b+=c; \
   d-=h; a^=c<<15; c+=d; \
   e-=a; b^=d>>14; d+=e; \
   f-=b; c^=e<<20; e+=f; \
   g-=c; d^=f>>17; f+=g; \
   h-=d; e^=g<<14; g+=h; \
}

void randinit(word flag) {
	word i;
	ub8 a, b, c, d, e, f, g, h;
	aa = bb = cc = (ub8) 0;
	a = b = c = d = e = f = g = h = 0x9e3779b97f4a7c13LL; /* the golden ratio */

	for (i = 0; i < 4; ++i) /* scramble it */
	{
		mix(a, b, c, d, e, f, g, h);
	}

	for (i = 0; i < RANDSIZ; i += 8) /* fill in mm[] with messy stuff */
	{
		if (flag) /* use all the information in the seed */
		{
			a += randrsl[i];
			b += randrsl[i + 1];
			c += randrsl[i + 2];
			d += randrsl[i + 3];
			e += randrsl[i + 4];
			f += randrsl[i + 5];
			g += randrsl[i + 6];
			h += randrsl[i + 7];
		}
		mix(a, b, c, d, e, f, g, h);
		mm[i] = a;
		mm[i + 1] = b;
		mm[i + 2] = c;
		mm[i + 3] = d;
		mm[i + 4] = e;
		mm[i + 5] = f;
		mm[i + 6] = g;
		mm[i + 7] = h;
	}

	if (flag) { /* do a second pass to make all of the seed affect all of mm */
		for (i = 0; i < RANDSIZ; i += 8) {
			a += mm[i];
			b += mm[i + 1];
			c += mm[i + 2];
			d += mm[i + 3];
			e += mm[i + 4];
			f += mm[i + 5];
			g += mm[i + 6];
			h += mm[i + 7];
			mix(a, b, c, d, e, f, g, h);
			mm[i] = a;
			mm[i + 1] = b;
			mm[i + 2] = c;
			mm[i + 3] = d;
			mm[i + 4] = e;
			mm[i + 5] = f;
			mm[i + 6] = g;
			mm[i + 7] = h;
		}
	}

	isaac64(); /* fill in the first set of results */
	randcnt = RANDSIZ; /* prepare to use the first set of results */
}

} // namespace

namespace quux {

// Isaac was the top hit for "fast C++ csprng",
// and a quick fix because reading urandom every time is unnecessarily bad
// FIXME: consider using Open/BoringSSL's csprng
class IsaacRandom: public net::QuicRandom {
public:
	IsaacRandom(): QuicRandom() {
		crypto::RandBytes(randrsl, RANDSIZ);
		randinit(TRUE);
	}

	void RandBytes(void* data, size_t len) override {
		ub8* dst = (ub8*) data;
		for (size_t i = 0; i < (len/8); i += 8) {
			dst[i] = rand();
		}

		ub8 last = rand();
		ub1* lastb = (ub1*)&last;
		ub1* dstb = (ub1*) data;

		for (size_t j = 0; j < (len % 8); ++j) {
			dstb[j] = lastb[j];
		}
	}

	uint64_t RandUint64() override {
		return rand();
	}

	void Reseed(const void* additional_entropy, size_t /*entropy_len*/) override {
	}
};

} /* namespace quux */

#endif /* SRC_QUUX_ISAACRANDOM_H_ */
