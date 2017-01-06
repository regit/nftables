/*
 * Copyright (c) 2017 Elise Lennion <elise.lennion@gmail.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */

#include <stdint.h>
#include <expression.h>
#include <gmputil.h>
#include <list.h>

static int expr_msort_cmp(const struct expr *e1, const struct expr *e2);

static int concat_expr_msort_cmp(const struct expr *e1, const struct expr *e2)
{
	struct list_head *l = (&e2->expressions)->next;
	const struct expr *i1, *i2;
	int ret;

	list_for_each_entry(i1, &e1->expressions, list) {
		i2 = list_entry(l, typeof(struct expr), list);

		ret = expr_msort_cmp(i1, i2);
		if (ret)
			return ret;

		l = l->next;
	}

	return false;
}

static int expr_msort_cmp(const struct expr *e1, const struct expr *e2)
{
	switch (e1->ops->type) {
	case EXPR_SET_ELEM:
		return expr_msort_cmp(e1->key, e2->key);
	case EXPR_VALUE:
		return mpz_cmp(e1->value, e2->value);
	case EXPR_CONCAT:
		return concat_expr_msort_cmp(e1, e2);
	case EXPR_MAPPING:
		return expr_msort_cmp(e1->left, e2->left);
	default:
		BUG("Unknown expression %s\n", e1->ops->name);
	}
}

static void list_splice_sorted(struct list_head *list, struct list_head *head)
{
	struct list_head *h = head->next;
	struct list_head *l = list->next;

	while (l != list) {
		if (h == head ||
		    expr_msort_cmp(list_entry(l, typeof(struct expr), list),
				   list_entry(h, typeof(struct expr), list)) < 0) {
			l = l->next;
			list_add_tail(l->prev, h);
			continue;
		}

		h = h->next;
	}
}

static void list_cut_middle(struct list_head *list, struct list_head *head)
{
	struct list_head *s = head->next;
	struct list_head *e = head->prev;

	while (e != s) {
		e = e->prev;

		if (e != s)
			s = s->next;
	}

	__list_cut_position(list, head, s);
}

void list_expr_sort(struct list_head *head)
{
	struct list_head *list;
	LIST_HEAD(temp);

	list = &temp;

	if (list_empty(head) || list_is_singular(head))
		return;

	list_cut_middle(list, head);

	list_expr_sort(head);
	list_expr_sort(list);

	list_splice_sorted(list, head);
}
