CC = gcc
CFLAGS = -Wall -Wextra -g
LIBS = -lpcap
INCLUDES = -I/usr/include/pcap

SRC = pcap_test.c
HDR = libnet-headers.h
OBJ = $(SRC:.c=.o)
TARGET = pcap-test

all: $(TARGET)

$(TARGET): $(OBJ)
	$(CC) $(CFLAGS) $(OBJ) -o $@ $(LIBS)

%.o: %.c $(HDR)
	$(CC) $(CFLAGS) $(INCLUDES) -c $< -o $@

clean:
	rm -f $(OBJ) $(TARGET)

.PHONY: all clean
