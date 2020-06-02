/*
 * Seccomp sandboxing for virtiofsd
 *
 * Copyright (C) 2019 Red Hat, Inc.
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef VIRTIOFSD_SECCOMP_H
#define VIRTIOFSD_SECCOMP_H

void setup_seccomp(void);
void setup_seccomp_memfsd(void);

#endif /* VIRTIOFSD_SECCOMP_H */
