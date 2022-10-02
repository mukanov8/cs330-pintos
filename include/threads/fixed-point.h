#ifndef THREADS_FP_H

#define THREADS_FP_H

//f = 2^q = 2^14
#define F (int64_t)16384

#define INT_TO_FP(n) (int64_t) (n * F)
#define FP_TO_NEAREST_INT(x) (int) (x >= 0 ? ((x + F / 2) / F) : ((x - F / 2) / F))
#define FP_TO_INT(x) (int)(x / F)
#define ADD_INT(x, n) (x + n * F)
#define SUB_INT(x, n) (x - n * F)
#define MUL_FP(x, y) ( ((int64_t) x) * y / F )
#define DIV_FP(x, y) ( ((int64_t) x) * F / y )

#endif
