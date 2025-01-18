
all: run

run: compile
	./encryption_program
compile:
	gcc main.c -o encryption_program -lcrypto -lssl
clean_all:
	rm encryption_program
	rm -f *.bin
clean:
	rm -f *.bin	