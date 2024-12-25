// SPDX-License-Identifier: BSD-3-Clause

#include "../utils/osmem.h"
#include <unistd.h>
#include <sys/mman.h>
#include "../utils/printf.h"
#include "../utils/block_meta.h"

#define ALIGN(size)		(((size) + 7) & ~7)
#define MMAP_THRESHOLD	(128 * 1024)
#define HEADER_SIZ		(32)
#define PAGE_SIZE		(4 * 1024)

static struct block_meta *heap_start;
static struct block_meta *heap_end;
static size_t block_counter;

void *find_best(size_t size)
{
	if (!heap_start)
		return NULL;
	struct block_meta *curr_block = heap_start;
	size_t max_min_size = __INT_MAX__;
	struct block_meta *max_min_block = NULL;

	while (curr_block) {
		if (curr_block->status == STATUS_FREE && curr_block->size >= size &&
			curr_block->size < max_min_size) {
			max_min_size = curr_block->size;
			max_min_block = curr_block;
		}
		curr_block = curr_block->next;
	}
	return max_min_block;
}

void coalesce(void *bp, int counter)
{
	struct block_meta *curr_block = (struct block_meta *)bp;
	struct block_meta *next = curr_block->next;
	size_t size = HEADER_SIZ;

	while (next && next->status == STATUS_FREE && counter) {
		size += next->size;
		next = next->next;
		counter--;
	}
	if (size != HEADER_SIZ) {
		curr_block->size += size;
		curr_block->next = next;
	}
	if (next)
		next->prev = curr_block;
	else
		heap_end = curr_block;

	curr_block = (struct block_meta *)bp;
	struct block_meta *prev = curr_block->prev;
	struct block_meta *tmp = NULL;

	size = curr_block->size + HEADER_SIZ;
	while (prev && prev->status == STATUS_FREE && counter) {
		size += prev->size;
		tmp = prev;
		prev = prev->prev;
		counter--;
	}
	if (!tmp)
		return;
	tmp->size = size;
	tmp->next = curr_block->next;
	if (curr_block->next)
		curr_block->next->prev = tmp;
	if (curr_block == heap_end)
		heap_end = tmp;
}


void split_block(struct block_meta *p, size_t block_size, size_t size_left)
{
	struct block_meta *tmp = (struct block_meta *)((char *)p + block_size);

	tmp->size = size_left - HEADER_SIZ;
	tmp->status = STATUS_FREE;
	tmp->prev = p;
	tmp->next = p->next;
	p->next = tmp;
	p->size = block_size - HEADER_SIZ;
	if (p == heap_end)
		heap_end = tmp;
	coalesce(tmp, __INT_MAX__);
}

void *os_malloc(size_t size)
{
	if (size == 0)
		return NULL;
	size_t block_size = ALIGN(size) + HEADER_SIZ;
	struct block_meta *p;

	if (block_counter == 0) {
		if (block_size < MMAP_THRESHOLD) {
			// preallocate chunk of 128kB
			heap_start = sbrk(MMAP_THRESHOLD);
			DIE(heap_start == (void *)-1, "sbrk failed");
			heap_start->size = block_size - HEADER_SIZ;
			heap_start->prev = heap_start->next = NULL;
			heap_start->status = STATUS_ALLOC;
			heap_end = heap_start;
			size_t size_left = MMAP_THRESHOLD - block_size;

			if (size_left >= ALIGN(HEADER_SIZ + 1))
				split_block(heap_start, block_size, size_left);
		} else {
			heap_start = mmap(NULL, block_size, PROT_READ | PROT_WRITE,
							  MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
			DIE(heap_start == (void *)-1, "mmap failed");
			heap_start->next = heap_start->prev = NULL;
			heap_start->size = block_size - HEADER_SIZ;
			heap_start->status = STATUS_MAPPED;
			heap_end = heap_start;
		}
		block_counter++;
		return heap_start + 1;
	}
	if (block_size >= MMAP_THRESHOLD) {
		p = mmap(NULL, block_size, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
		DIE(p == (void *)-1, "mmap failed");
		p->size = block_size - HEADER_SIZ;
		p->status = STATUS_MAPPED;
		p->prev = heap_end;
		p->next = NULL;
		heap_end->next = p;
		heap_end = p;
		block_counter++;
		return p + 1;
	}
	struct block_meta *tmp = heap_start;

	while (tmp) {
		if (tmp->status == STATUS_FREE)
			coalesce(tmp, __INT_MAX__);
		tmp = tmp->next;
	}
	p = find_best(ALIGN(size));
	if (p) {
		p->status = STATUS_ALLOC;
		if (p->size - ALIGN(size) > HEADER_SIZ)
			split_block(p, block_size, p->size - ALIGN(size));
		block_counter++;
		return p + 1;
	}
	struct block_meta *last = heap_end;

	while (last && last->status == STATUS_MAPPED)
		last = last->prev;
	if (last && last->status == STATUS_FREE && last->size < ALIGN(size)) {
		p = sbrk(ALIGN(size) - last->size);
		DIE(p == (void *)-1, "sbrk failed");
		last->size = block_size - HEADER_SIZ;
		last->status = STATUS_ALLOC;
		return last + 1;
	}
	p = sbrk(block_size);
	DIE(p == (void *)-1, "sbrk failed");
	p->size = block_size - HEADER_SIZ;
	p->status = STATUS_ALLOC;
	p->prev = heap_end;
	p->next = NULL;
	heap_end->next = p;
	heap_end = p;
	block_counter++;
	return p + 1;
}

void os_free(void *ptr)
{
	if (!ptr)
		return;
	struct block_meta *curr_block = (struct block_meta *)((char *)ptr - HEADER_SIZ);

	if (curr_block->status == STATUS_MAPPED) {
		if (curr_block->prev)
			curr_block->prev->next = curr_block->next;
		if (curr_block->next)
			curr_block->next->prev = curr_block->prev;
		if (curr_block == heap_start)
			heap_start = curr_block->next;
		if (curr_block == heap_end)
			heap_end = curr_block->prev;
		int res = munmap(curr_block, curr_block->size + HEADER_SIZ);

		DIE(res == -1, "munmap() failed");
		block_counter--;
	} else if (curr_block->status == STATUS_ALLOC) {
		curr_block->status = STATUS_FREE;
		coalesce(curr_block, __INT_MAX__);
	}
}

void *memset(void *source, int value, size_t num)
{
	char *s = (char *) source;

	for (size_t i = 0; i < num; i++)
		s[i] = (char) value;
	return source;
}

void *os_calloc(size_t nmemb, size_t size)
{
	if (!nmemb || !size)
		return NULL;
	struct block_meta *p;
	size_t block_size = ALIGN(nmemb * size) + HEADER_SIZ;

	if (block_size < PAGE_SIZE) {
		p = os_malloc(nmemb * size);
		memset(p, 0, (p - 1)->size);
		return p;
	}
	if (block_counter == 0) {
		heap_start = mmap(NULL, block_size, PROT_READ | PROT_WRITE,
							MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
		DIE(heap_start == (void *)-1, "mmap failed");
		heap_start->next = heap_start->prev = NULL;
		heap_start->size = block_size - HEADER_SIZ;
		heap_start->status = STATUS_MAPPED;
		heap_end = heap_start;
		block_counter++;
		memset(heap_start + 1, 0, heap_start->size);
		return heap_start + 1;
	}
	p = mmap(NULL, block_size, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	DIE(p == (void *)-1, "mmap failed");
	p->size = block_size - HEADER_SIZ;
	p->status = STATUS_MAPPED;
	p->prev = heap_end;
	p->next = NULL;
	heap_end->next = p;
	heap_end = p;
	block_counter++;
	memset(p + 1, 0, p->size);
	return p + 1;
}

void *memcpy(void *destination, const void *source, size_t num)
{
	char *d = (char *)destination;
	const char *s = (const char *)source;
	size_t i = 0;

	while (i < num) {
		*d = *s;
		d++; s++;
		++i;
	}
	return destination;
}

void *os_realloc(void *ptr, size_t size)
{
	if (!ptr)
		return os_malloc(size);
	if (!size) {
		os_free(ptr);
		return NULL;
	}
	struct block_meta *p = (struct block_meta *)ptr - 1;
	struct block_meta *q;

	if (p->size == size)
		return ptr;
	if (p->status == STATUS_FREE)
		return NULL;
	if (p->size < ALIGN(size)) {
		if (p->status == STATUS_MAPPED) {
			block_counter--;
			q = os_malloc(size);
			memcpy(q, p + 1, p->size);
			block_counter++;
			os_free(p + 1);
			return q;
		}
		if (ALIGN(size) >= MMAP_THRESHOLD) {
			printf_("%d\n", heap_end->size);
			block_counter--;
			q = os_malloc(size);
			memcpy(q, p + 1, p->size);
			block_counter++;
			os_free(p + 1);
			return q;
		}
		struct block_meta *last = heap_end;

		while (last && last->status == STATUS_MAPPED)
			last = last->prev;
		if (p == last) {
			p = sbrk(ALIGN(size) - last->size);
			DIE(p == (void *)-1, "sbrk failed");
			last->size = ALIGN(size);
			return last + 1;
		}
		size_t block_size = p->size;
		struct block_meta *q = p->next;

		if (q && q->status == STATUS_FREE) {
			block_size = q->size + p->size + HEADER_SIZ;
			while (q->next && q->next->status == STATUS_FREE && block_size < ALIGN(size)) {
				coalesce(q, 1);
				block_size = q->size + p->size + HEADER_SIZ;
			}
		}
		if (block_size < ALIGN(size)) {
			q = os_malloc(size);
			memcpy(q, p + 1, p->size);
			os_free(p + 1);
			return q;
		}
		if (block_size - ALIGN(size) > HEADER_SIZ) {
			struct block_meta *next = q->next;
			struct block_meta *tmp = (struct block_meta *)((char *)p + ALIGN(size)) + 1;

			tmp->size = block_size - ALIGN(size) - HEADER_SIZ;
			tmp->status = STATUS_FREE;
			tmp->prev = p;
			tmp->next = next;
			p->next = tmp;
			if (p == heap_end)
				heap_end = tmp;
			p->size = ALIGN(size);
			coalesce(tmp, __INT_MAX__);
		} else {
			if (p->next == heap_end)
				heap_end = p;
			p->next = q->next;
			p->size = block_size;
		}
		return p + 1;
	}
	if (p->status == STATUS_MAPPED) {
		block_counter--;
		q = os_malloc(size);
		memcpy(q, p + 1, size);
		block_counter++;
		os_free(p + 1);
		return q;
	}
	if (p->size - ALIGN(size) > HEADER_SIZ) {
		struct block_meta *next = p->next;
		struct block_meta *tmp = (struct block_meta *)((char *)p + ALIGN(size)) + 1;

		tmp->size = p->size - ALIGN(size) - HEADER_SIZ;
		tmp->status = STATUS_FREE;
		tmp->prev = p;
		tmp->next = next;
		p->next = tmp;
		if (p == heap_end)
			heap_end = tmp;
		p->size = ALIGN(size);
		coalesce(tmp, __INT_MAX__);
	}
	return p + 1;
}
