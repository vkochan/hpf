TARGET=hpf

CC = gcc
CFLAGS = -O2
# WFLAGS := -Wall -Wstrict-prototypes  -Wmissing-prototypes
# WFLAGS += -Wmissing-declarations -Wold-style-definition -Wformat=2

OBJS=compiler.o xmalloc.o htable.o proto.o main.o link_protos.o net_protos.o \
     bpf.o parser.o lexer.o optimizer.o

all: $(TARGET)

$(TARGET): $(OBJS)
	$(CC) $(CFLAGS) $(WFLAGS) -o $(TARGET) $(OBJS) $(LDFLAGS)

.c.o:
	$(CC) $(CFLAGS) $(WFLAGS) -c $< -o $@

parser.c: parser.y
	bison -d $< -o $@

lexer.c: lexer.l
	flex -o $@ $<

clean:
	rm -f $(TARGET)
	rm -rf *.o
	rm -f parser.c parser.h lexer.c
