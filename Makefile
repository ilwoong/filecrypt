CC = g++
CPPFLAGS = -O2 -std=c++11
LDFLAGS = -lcrypto

.PHONY: all clean

all: filecrypt

filecrypt: *.cpp
	$(CC) $(CPPFLAGS) $^ -o $@ $(LDFLAGS)

clean:
	rm -rf filecrypt