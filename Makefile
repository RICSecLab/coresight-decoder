CC = g++
CFLAGS = -std=c++14 -Wall -g -fsanitize=undefined -D_GLIBCXX_DEBUG

# capstone library name (without prefix 'lib' and suffix '.so')
LIBNAME = capstone


disassembler: disassembler.o
	${CC} $< ${CFLAGS} -l$(LIBNAME) -o $@

%.o: %.c
	${CC} -c $< -o $@

clean:
	rm -rf *.o disassembler
