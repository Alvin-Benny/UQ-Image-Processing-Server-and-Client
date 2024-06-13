CFLAGS = -Wall -Wextra -pedantic -g -std=gnu99 -pthread \
	 -I/local/courses/csse2310/include
LINKED_LIB1 = -L/local/courses/csse2310/lib -lcsse2310a4
LINKED_LIB2 =  -L/local/courses/csse2310/lib -lcsse2310a4 -lcsse2310_freeimage \
	       -lfreeimage


all: uqimageclient uqimageproc
uqimageclient: uqimageclient.c
	gcc $(CFLAGS) -o uqimageclient uqimageclient.c $(LINKED_LIB1)
uqimageproc: uqimageproc.c
	gcc $(CFLAGS) -o uqimageproc uqimageproc.c $(LINKED_LIB2)

clean:
	rm uqimageclient uqimageproc
