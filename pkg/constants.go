package decloaker

// Exit codes
const (
	OK              = 0
	ERROR           = 1
	FILES_HIDDEN    = 50
	KMOD_HIDDEN     = 51
	CONTENT_HIDDEN  = 52
	PID_BIND_MOUNT  = 53
	PROC_HIDDEN     = 54
	CONN_HIDDEN     = 55
	SUSPICIOUS_PROC = 56
)

var (
	// https://swisskyrepo.github.io/InternalAllTheThings/redteam/persistence/linux-persistence/
	DefaultHiddenFilesPaths = []string{
		"/etc/",
		"/lib/",
		"/usr/",
		"/sbin/",
		"/lib/",
		"/var/spool/",
		"/var/tmp/",
		"/home/*/.config/",
	}
	DefaultHiddenContentPaths = []string{
		"/etc/ld.so.preload",
		"/etc/ld.so.conf",
		"/etc/ld.so.conf.d/*",
		"/etc/passwd",
		"/etc/shadow",
		"/etc/sudoers",
		"/etc/motd",
		"/etc/environment",
		"/etc/profile",
		"/etc/profile.d/*",
		"/etc/rc.local",
		"/etc/rc.d/rc.local",
		"/etc/init.d/*",
		"/etc/rc*.d/*",
		"/etc/init/*",
		"/etc/update-motd.d/*",
		"/etc/modules",
		"/etc/modules-load.d/*",
		"/etc/udev/*/*",
		"/etc/cron*/*",
		"/etc/crontab",
		"/etc/xdg/autostart/*",
		"/etc/systemd/*/*/*",
		"/usr/lib/modules-load.d/*",
		"/var/spool/*/*/*",
		"/home/*/.bashrc",
		"/home/*/.config/autostart/*",
		"/home/*/.config/systemd/*/*",
		"/lib/systemd/*/*",
		"/usr/lib/systemd/*/*",
		"/root/*",
		"/proc/net/*",
	}
)
