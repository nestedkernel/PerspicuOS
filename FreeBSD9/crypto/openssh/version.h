/* $OpenBSD: version.h,v 1.61 2011/02/04 00:44:43 djm Exp $ */
/* $FreeBSD: release/9.0.0/crypto/openssh/version.h 224638 2011-08-03 19:14:22Z brooks $ */

#ifndef SSH_VERSION

#define SSH_VERSION_BASE        "OpenSSH_5.8p2"
#define SSH_VERSION_ADDENDUM    "FreeBSD-20110503"
#define SSH_VERSION_HPN		"_hpn13v11"
#define SSH_VERSION		SSH_VERSION_BASE SSH_VERSION_HPN " " SSH_VERSION_ADDENDUM
#define SSH_RELEASE             (ssh_version_get())

const char *ssh_version_get(void);
void ssh_version_set_addendum(const char *);
#endif /* SSH_VERSION */
