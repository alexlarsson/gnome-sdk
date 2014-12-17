NULL =

bin_PROGRAMS = \
	gnome-sdk-helper \
	$(NULL)

bin_SCRIPTS = gnome-sdk-build gnome-sdk-run gnome-sdk-repo

gnome_sdk_helper_SOURCES = gnome-sdk-helper.c

install-exec-hook:
	chown root $(bindir)/gnome-sdk-helper
	chmod u+s $(bindir)/gnome-sdk-helper
