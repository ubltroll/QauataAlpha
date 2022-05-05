CC=    gcc
LD=    gcc


#
# The variable `$PROJ_DIR' controls the variant(corresponding to a specific directory) will be built.
# To build a specific variant, set the $PROJ_DIR to a specific name of the directory.
#
# For example of building the `Ia_Classic' variant,
# one have to set $PROJ_DIR = Ia_Classic.
# The makefile will compile codes in the `Ia_Classic' directory only.
# No code changes have to be made.
#
# All possible variants are listed as followings.
#

ifndef PROJ_DIR
PROJ_DIR = Ia_Circumzenithal
endif


CFLAGS= -O3 -std=c11 -Wall -Wextra -fno-omit-frame-pointer -fPIC
INCPATH= -I/usr/local/include -I/opt/local/include -I/usr/include -I$(PROJ_DIR) -I/opt/homebrew/opt/openssl@1.1/include
LDFLAGS= -L/opt/homebrew/opt/openssl@1.1/lib
LIBPATH= -L/usr/local/lib -L/opt/local/lib -L/usr/lib
LIBS=    -lcrypto



SRCS = $(wildcard $(PROJ_DIR)/*.c)
SRCS_O = $(SRCS:.c=.o)
SRCS_O_ND = $(subst $(PROJ_DIR)/,,$(SRCS_O))

OBJ = $(SRCS_O_ND)

EXE = rainbow-test

RUNTIME = librainbow.so


CSRC= $(wildcard *.c)


ifdef DEBUG
        CFLAGS=  -D_DEBUG_ -g -O1 -mavx2 -std=c99 -Wall -Wextra -fsanitize=address -fno-omit-frame-pointer
        CXXFLAGS= -D_DEBUG_ -g -O1 -mavx2 -Wall -Wextra -fno-exceptions -fno-rtti -nostdinc++
endif

ifdef GPROF
	CFLAGS += -pg
	CXXFLAGS += -pg
	LDFLAGS += -pg
endif

.PHONY: all clean

all: $(OBJ) $(EXE) $(RUNTIME)


rainbow-test: $(OBJ) rainbow-test.o
	$(LD) $(LDFLAGS) $(LIBPATH) -o $@ $^ $(LIBS)

librainbow.so: $(OBJ) rainbow-crypto.o
	$(LD) $(LDFLAGS) $(LIBPATH) -shared -o $@ $^ $(LIBS)

%.o: %.c
	$(CC) $(CFLAGS) $(INCPATH) -c $<

%.o: $(PROJ_DIR)/%.c
	$(CC) $(CFLAGS) $(INCPATH) -c $<

clean:
	rm *.o rainbow-test;
