PREFIX ?= /usr
BINDIR ?= ${PREFIX}/bin

all: gnome-sdk-helper

gnome-sdk-helper: gnome-sdk-helper.c
	gcc -o gnome-sdk-helper gnome-sdk-helper.c -g -O -Wall

install: gnome-sdk-helper gnome-sdk-build gnome-sdk-run gnome-sdk-repo
	install -D gnome-sdk-build ${DESTDIR}${BINDIR}
	install -D gnome-sdk-run ${DESTDIR}${BINDIR}
	install -D gnome-sdk-repo ${DESTDIR}${BINDIR}
	install -D --mode=4755 --owner=root gnome-sdk-helper ${DESTDIR}${BINDIR}
