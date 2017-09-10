CFLAGS=-Wall -Werror -fno-strict-aliasing -std=c99
PCAPFLAGS=$(shell pcap-config --libs --cflags)
PYTHONFLAGS=$(shell python-config --libs)
PYTHONINCLUDEFLAGS=$(shell python-config --includes)
SSLFLAGS=-lssl -lcrypto
VERSION=$(shell head -n1 VERSION)
DISTDIR=pt-utils-$(VERSION)
DISTFILES=README VERSION TODO Makefile CHANGES
TARDIR=/tmp/$(DISTDIR)
TARBALL=$(DISTDIR).tar.gz
BIN=ptlogd ptnote ptlogverify ptlogextract ptlogwipe \
ptfiledump ptcapture

all: CFLAGS += -O2
all: $(BIN) strip

debug: CFLAGS += -DDEBUG -g
debug: $(BIN)

.c.o:
	$(CC) $(CFLAGS) -c $< -o $@	

ptu.o: ptu.c
	$(CC) $(CFLAGS) -DPTU_VERSION=\"$(shell head -n1 VERSION)\" -c $< -o $@

libptu.a: utils.o buffer.o time.o hash.o ptu.o
	$(AR) r $@ $^

ptlogd: ptlogd.o libptu.a
	$(CC) $(CFLAGS) $^ -o $@

ptlogverify: ptlogverify.o libptu.a
	$(CC) $(CFLAGS) $^ -o $@

ptlogextract: ptlogextract.o libptu.a
	$(CC) $(CFLAGS) $^ -o $@

ptlogwipe: ptlogwipe.o libptu.a
	$(CC) $(CFLAGS) $^ -o $@

ptnote: ptnote.o libptu.a
	$(CC) $(CFLAGS) $^ -o $@

ptfiledump: ptfiledump.o libptu.a
	$(CC) $(CFLAGS) $^ -o $@

ptcapture: ptcapture.o libptu.a
	$(CC) $(CFLAGS) $^ -o $@ $(PCAPFLAGS)

pttermrec: pttermrec.o libptu.a
	$(CC) $(CFLAGS) $^ -o $@

pttermplay: pttermplay.o libptu.a
	$(CC) $(CFLAGS) $^ -o $@

python.o: python.c
	$(CC) $(CFLAGS) -c $< -o $@ $(PYTHONINCLUDEFLAGS)

ptproxy: ptproxy.o python.o libptu.a resolver.o http.o
	$(CC) $(CFLAGS) $^ -o $@ $(SSLFLAGS) $(PYTHONFLAGS)

strip: 
	strip $(BIN)

clean:
	$(RM) $(BIN) *.o *.a core

distclean: clean

tarball:
	@mkdir $(TARDIR)
	@cp *.c *.h $(DISTFILES) $(TARDIR)
	@cd $(TARDIR)/../ && tar zcf $(DISTDIR).tar.gz $(DISTDIR)
	@cp $(TARDIR)/../$(TARBALL) .
	@rm -rf $(TARDIR)
	@echo $(TARBALL) created
