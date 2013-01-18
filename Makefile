CFLAGS=-O3 -Iheaders/
LIBS=-lpcap
PREFIX=/usr/local


# Make All
all: src/qsniffer.o src/qsniffer
src/qsniffer.o: src/main.c
	$(CC) $(CFLAGS) -c $< -o $@
src/qsniffer: src/qsniffer.o
	$(CC) $(CFLAGS) $(LIBS) $^ -o $@


# Making Clean
clean:
	rm -rf src/*.o
	rm -rf src/qsniffer

# Install Files
install: src/qsniffer
	mkdir -p $(PREFIX)/bin
	rm -f $(PREFIX)/bin/qsniffer
	cp src/qsniffer $(PREFIX)/bin/qsniffer

# Uninstall Files
uninstall:
	rm -vf $(PREFIX)/bin/qsniffer
