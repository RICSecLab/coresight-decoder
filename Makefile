CC      = g++
CFLAGS  = -std=c++14 -Wall -g -fsanitize=undefined -D_GLIBCXX_DEBUG

OBJS    = decoder.o deformatter.o disassembler.o utils.o processor.o
PROGRAM = processor

# capstone library name (without prefix 'lib' and suffix '.so')
LIBNAME = capstone


$(PROGRAM): $(OBJS)
	$(CC) $(CFLAGS) $(OBJS) -l$(LIBNAME) -o $@

%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -rf *.o $(PROGRAM)
