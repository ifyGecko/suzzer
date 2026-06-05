#ifndef LIBCOV_HANDLER_H
#define LIBCOV_HANDLER_H

enum libcov_mode { LIBCOV_MODE_ONESHOT = 0, LIBCOV_MODE_LEAPFROG = 1 };

int handler_install(enum libcov_mode mode);

#endif
