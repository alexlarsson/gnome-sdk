PREFIX ?= /usr
BINDIR ?= ${PREFIX}/bin

all: gnome-sdk-helper

gnome-sdk-helper: gnome-sdk-helper.c
	gcc -o gnome-sdk-helper gnome-sdk-helper.c -O -Wall

install: gnome-sdk-helper gnome-sdk
	install -D --mode=4755 --owner=root gnome-sdk-helper ${DESTDIR}${BINDIR}
	install -D gnome-sdk ${DESTDIR}${BINDIR}
