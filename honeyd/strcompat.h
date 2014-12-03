#ifndef HAVE_STRLCPY
size_t	 strlcpy(char *, const char *, size_t);
#endif

#ifndef HAVE_STRLCAT
size_t	 strlcat(char *, const char *, size_t);
#endif

#ifndef HAVE_STRSEP
char	*strsep(char **, const char *);
#endif

#ifndef HAVE_DAEMON
int	daemon(int, int);
#endif
