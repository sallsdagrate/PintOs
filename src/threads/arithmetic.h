#ifndef THREADS_ARITHMETIC_H
#define THREADS_ARITHMETIC_H

/*fixed point format*/
#define f (1 << 14)

/*x and y are fixed point numbers, n is an integer*/
#define convert_int_to_fixed_point(n) n * f
#define convert_fixed_point_to_int(x) (x >= 0 ? (x + f/2) / f : (x - f/2) / f)

/*following functions return fixed point numbers*/
#define add_xy(x, y) (x + y)
#define add_xn(x, n) (x + n * f)

/*x - y*/
#define subtract_xy(x, y) (x - y)
/*x - n*/
#define subtract_xn(x, n) (x - n * f)

#define multiply_xy(x, y) (((int64_t) x) * y / f)
#define multiply_xn(x, n) (x * n)

/*x / y*/
#define divide_xy(x, y) (((int64_t) x) * f / y)
/*x / n*/  
#define divide_xn(x, n) (x / n)


#endif /* THREADS_ARITHMETIC_H */
