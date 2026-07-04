#ifndef LDE_H
# define LDE_H

# include "woody.h"

int lde_run_c(const uint8_t *buf, size_t start, size_t end,
              uint8_t key_out[16], int verbose,
              int lde_bit_log[512], int *lde_bit_log_len);
int lde_bit_at_pos(size_t pos);

#endif