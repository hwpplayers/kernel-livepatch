#ifndef _LIVEPATCH_BSC1133191_MM_H
#define _LIVEPATCH_BSC1133191_MM_H

#include <linux/mm.h>

static inline __must_check bool klp_try_get_page(struct page *page)
{
	page = compound_head(page);
	if (WARN_ON_ONCE(page_ref_count(page) <= 0))
		return false;
	page_ref_inc(page);
	return true;
}

#endif /* _LIVEPATCH_BSC1133191_MM_H */
