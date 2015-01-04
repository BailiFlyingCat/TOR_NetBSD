/*
 * System call numbers.
 *
 * DO NOT EDIT-- this file is automatically generated.
 * created from: NetBSD syscalls.master,v 1.2 1994/06/29 06:30:37
 */

#define	SVR4_SYS_syscall	0
#define	SVR4_SYS_exit	1
#define	SVR4_SYS_fork	2
#define	SVR4_SYS_read	3
#define	SVR4_SYS_write	4
#define	SVR4_SYS_svr4_open	5
#define	SVR4_SYS_close	6
#define	SVR4_SYS_svr4_wait	7
#define	SVR4_SYS_svr4_creat	8
#define	SVR4_SYS_link	9
#define	SVR4_SYS_unlink	10
#define	SVR4_SYS_svr4_execv	11
#define	SVR4_SYS_chdir	12
#define	SVR4_SYS_time	13
#define	SVR4_SYS_svr4_mknod	14
#define	SVR4_SYS_chmod	15
#define	SVR4_SYS_chown	16
#define	SVR4_SYS_break	17
#define	SVR4_SYS_svr4_stat	18
#define	SVR4_SYS_lseek	19
#define	SVR4_SYS_getpid	20
#define	SVR4_SYS_setuid	23
#define	SVR4_SYS_getuid	24
#define	SVR4_SYS_svr4_fstat	28
#define	SVR4_SYS_access	33
#define	SVR4_SYS_sync	36
#define	SVR4_SYS_kill	37
#define	SVR4_SYS_dup	41
#define	SVR4_SYS_pipe	42
#define	SVR4_SYS_profil	44
#define	SVR4_SYS_getgid	47
#define	SVR4_SYS_msgsys	49
#define	SVR4_SYS_svr4_syssun	50
#define	SVR4_SYS_acct	51
#define	SVR4_SYS_shmsys	52
#define	SVR4_SYS_semsys	53
#define	SVR4_SYS_svr4_ioctl	54
#define	SVR4_SYS_fsync	58
#define	SVR4_SYS_execve	59
#define	SVR4_SYS_umask	60
#define	SVR4_SYS_chroot	61
				/* 70 is obsolete svr4_advfs */
				/* 71 is obsolete svr4_unadvfs */
				/* 72 is obsolete svr4_rmount */
				/* 73 is obsolete svr4_rumount */
				/* 74 is obsolete svr4_rfstart */
				/* 75 is obsolete svr4_sigret */
				/* 76 is obsolete svr4_rdebug */
				/* 77 is obsolete svr4_rfstop */
#define	SVR4_SYS_rmdir	79
#define	SVR4_SYS_mkdir	80
				/* 82 is obsolete svr4_libattach */
				/* 83 is obsolete svr4_libdetach */
#define	SVR4_SYS_svr4_lstat	88
#define	SVR4_SYS_symlink	89
#define	SVR4_SYS_readlink	90
#define	SVR4_SYS_setgroups	91
#define	SVR4_SYS_getgroups	92
#define	SVR4_SYS_fchmod	93
#define	SVR4_SYS_fchown	94
#define	SVR4_SYS_sigprocmask	95
#define	SVR4_SYS_sigaltstack	96
#define	SVR4_SYS_sigsuspend	97
#define	SVR4_SYS_sigaction	98
#define	SVR4_SYS_svr4_sigpending	99
#define	SVR4_SYS_pathconf	113
#define	SVR4_SYS_mincore	114
#define	SVR4_SYS_svr4_mmap	115
#define	SVR4_SYS_mprotect	116
#define	SVR4_SYS_munmap	117
#define	SVR4_SYS_fpathconf	118
#define	SVR4_SYS_vfork	119
#define	SVR4_SYS_fchdir	120
#define	SVR4_SYS_readv	121
#define	SVR4_SYS_writev	122
#define	SVR4_SYS_svr4_setrlimit	128
#define	SVR4_SYS_svr4_getrlimit	129
#define	SVR4_SYS_rename	134
#define	SVR4_SYS_svr4_uname	135
#define	SVR4_SYS_setegid	136
#define	SVR4_SYS_svr4_sysconfig	137
#define	SVR4_SYS_adjtime	138
#define	SVR4_SYS_seteuid	141
#define	SVR4_SYS_svr4_fchroot	153
#define	SVR4_SYS_svr4_vhangup	155
#define	SVR4_SYS_gettimeofday	156
#define	SVR4_SYS_getitimer	157
#define	SVR4_SYS_setitimer	158