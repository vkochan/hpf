#ifndef __HTABLE_H__
#define __HTABLE_H__

#define HTABLE_SIZE 256

struct hentry {
	struct hentry *next;
	unsigned long hash;
};

struct htable {
	int size;
	struct hentry **head;
	struct hentry *cached;
};

unsigned long str_hash(char *str);

struct htable *htable_alloc(int size);
void htable_reset(struct htable *ht);
void htable_free(struct htable *ht);
struct hentry *htable_find(struct htable *ht, unsigned long hash);
struct hentry *htable_find_name(struct htable *ht, char *name);
void htable_insert(struct htable *ht, struct hentry *entry, unsigned long hash);
void htable_insert_name(struct htable *ht, struct hentry *entry, char *name);

#endif
