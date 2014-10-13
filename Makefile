PREFIX ?= /usr
BINDIR ?= ${PREFIX}/bin

all: gnome-sdk-helper

gnome-sdk-helper: gnome-sdk-helper.c
	gcc -o gnome-sdk-helper gnome-sdk-helper.c -O -Wall

install: gnome-sdk-helper gnome-sdk gnome-sdk-run gnome-sdk-repo
	install -D --mode=4755 --owner=root gnome-sdk-helper ${DESTDIR}${BINDIR}
	install -D gnome-sdk ${DESTDIR}${BINDIR}
	install -D gnome-sdk-run ${DESTDIR}${BINDIR}
	install -D gnome-sdk-repo ${DESTDIR}${BINDIR}
