
all: run

run: compile
	./encryption_program
compile:
	gcc main.c -o encryption_program -lcrypto -lssl
clean:
	rm encryption_program
clean_all:
	rm -f "*.bin"	
	rm encryption_program