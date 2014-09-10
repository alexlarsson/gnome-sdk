run-app: run-app.c
	gcc -o run-app run-app.c -O -Wall
	chown root.root run-app
	chmod u+s run-app
