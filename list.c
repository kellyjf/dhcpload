#include <stdlib.h>   // calloc
#include <stdio.h>    // printf
#include "list.h"

#ifdef TEST

typedef struct iter_test {
	int              index;
	struct list_head running;
};

void printlist(struct list_head *head) {
	struct iter_test *curr;
	list_for_each_entry(curr, head, running) {
		printf("head %p curr: %p  Index %d\n", head, curr, curr->index);	
	}
}

struct list_head *lh_for_index(struct list_head *head, int i) {
	struct iter_test *curr;
	list_for_each_entry(curr, head, running) {
		if(curr->index==i) return &curr->running;
	}
	return NULL;
}

int list_main(int argc, char **argv) {

	int   i;
	struct iter_test *curr;
	LIST_HEAD(test_head);
	
	for(i=0; i<10; i++) {
		curr = calloc(1,sizeof(struct iter_test));
		curr->index = i;
		list_add(&curr->running, &test_head);
	}


	printlist(&test_head);		

	for(i=0; i<5; i++) {
		struct list_head *tgt;
		if(tgt=lh_for_index(&test_head, i)) {
			printf("Removing %d\n", i);
			list_del(tgt);
			printlist(&test_head);
		}
		if(tgt=lh_for_index(&test_head, i+5)) {
			printf("Removing %d\n", i+5);
			list_del(tgt);
			printlist(&test_head);
		}
	}	
	return 0;
}
#endif
