#ifndef _LIVEPATCH_BSC1133191_H
#define _LIVEPATCH_BSC1133191_H

#include "livepatch_bsc1133191_generic_gup.h"
#include "livepatch_bsc1133191_x86_gup.h"
#include "livepatch_bsc1133191_splice.h"
#include "livepatch_bsc1133191_fuse.h"

int livepatch_bsc1133191_init(void);
void livepatch_bsc1133191_cleanup(void);

#endif /* _LIVEPATCH_BSC1133191_H */
