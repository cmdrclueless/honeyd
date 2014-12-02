#
# Regular cron jobs for the honeyd package
#
0 4	* * *	root	[ -x /usr/bin/honeyd_maintenance ] && /usr/bin/honeyd_maintenance
