#ifndef __UTILS_H__
#define __UTILS_H__

/* Thanks to Linux kernel */
/**
 * container_of - cast a member of a structure out to the containing structure
 * @ptr:	the pointer to the member.
 * @type:	the type of the container struct this is embedded in.
 * @member:	the name of the member within the struct.
 *
 */
#define container_of(ptr, type, member) ({			\
	const typeof( ((type *)0)->member ) *__mptr = (ptr);	\
	(type *)( (char *)__mptr - offsetof(type,member) );})

#ifndef array_size
#define array_size(x)	(sizeof(x) / sizeof((x)[0]) + __must_be_array(x))
#endif

#ifndef __must_be_array
#define __must_be_array(x)						\
	build_bug_on_zero(__builtin_types_compatible_p(typeof(x),	\
						       typeof(&x[0])))
#endif

#ifndef build_bug_on_zero
#define build_bug_on_zero(e)	(sizeof(char[1 - 2 * !!(e)]) - 1)
#endif

#ifndef build_bug_on
#define build_bug_on(e)	((void)sizeof(char[1 - 2*!!(e)]))
#endif

#ifndef bug_on
#define bug_on(cond)		assert(!(cond))
#endif

#ifndef bug
#define bug()			assert(0)
#endif

#endif
