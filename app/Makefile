PROG = compdetect
OBJS = socket.o json.o shared.o main.o time.o

CFLAGS = -g -I../jansson-2.13/include
LDFLAGS = -L../jansson-2.13/lib -ljansson

%.o : %.c
	gcc $(CFLAGS) -c -o $@ $<

$(PROG) : $(OBJS)
	gcc $(CFLAGS) -o $@ $(OBJS) $(LDFLAGS)

clean :
	rm -rf $(PROG) $(OBJS) $(RESULT)    
