AR = aal
RANLIB = touch

ifdef PROVIDER
MKPROVIDER = -D _PROVIDER_
endif

ifndef PRJROOT
CC = gcc -O3
LD = gcc -O3
EXDIR=data
INCEXTRA = $(MKPROVIDER)
else
CC = arm-linux-gcc -O3
LD = arm-linux-gcc -O3
INCEXTRA = -D _NEUROS_ $(MKPROVIDER) -I/opt/neuros-osd/neuros-bsp/kernels/linux-2.6.5/include/ -I/opt/neuros-osd/Neuros-Cooler/include/
INCLIBEXTRA = -L/opt/openssl/openssl-0.9.7e/ -lncooler -lcomnmsc
EXDIR=/opt/neuros-osd/neuros-bsp/rootfs/default/usr/data
endif



CFLAGS = -Wall $(INCEXTRA)
LDFLAGS =  -L. $(INCLIBEXTRA) -lcrypto -lm
BFLAGS = -Wall -lcrypto -lm -L.

RM = /bin/rm -f

OBJS = connection_manager.o security_manager.o data_manager.o tpm.o
LOGIC = data_server.o data_client.o bcast_server.o bcast_client.o interface_server.o
GEN = def.o generic.o socks.o server.o semaphores.o
PROG = paradiso
CMDLINE = commandline

# dependency definitions
DEPNUO = paradiso.h
DEPGEN = generic/generic.h generic/socks.h generic/server.h generic/semaphores.h

DEPCM = connection_manager/connection_manager.h

DEPLDC = logic/data_client.h
DEPLDS = logic/data_server.h
DEPLBC = logic/bcast_client.h
DEPLBS = logic/bcast_server.h
DEPLIS = logic/interface_server.h

DEPDM = data_manager/data_manager.h
DEPSM = security_manager/security_manager.h security_manager/tpm.h

all: $(GEN) $(LOGIC) $(PROG) $(CMDLINE)
logic: $(LOGIC)
generic: $(GEN)

# this rule links the program
$(PROG): $(OBJS) paradiso.o $(GEN) $(LOGIC)
	$(LD) paradiso.o $(OBJS) $(GEN) $(LOGIC) $(LDFLAGS) -o $(PROG)

paradiso.o: $(DEPGEN) $(DEPLDS) $(DEPLIS) $(DEPNUO) paradiso.c
	$(CC) $(CFLAGS) -c paradiso.c

# following is for the commandline
$(CMDLINE): $(OBJS) commandline.o $(GEN) $(LOGIC)
	$(LD) commandline.o connection_manager.o $(GEN) $(LDFLAGS) -o $(CMDLINE)

commandline.o: $(DEPGEN) $(DEPLDS) $(DEPLIS) commandline.c
	$(CC) $(CFLAGS) -c commandline.c

# connection manager
connection_manager.o: $(DEPGEN) $(DEPCM) connection_manager/connection_manager.c
	$(CC) $(CFLAGS) -c connection_manager/connection_manager.c

# logic
data_server.o: $(DEPGEN) $(DEPCM) $(DEPLDS) logic/data_server.c
	$(CC) $(CFLAGS) -c logic/data_server.c

data_client.o: $(DEPGEN) $(DEPCM) $(DEPLDC) logic/data_client.c
	$(CC) $(CFLAGS) -c logic/data_client.c

bcast_server.o: $(DEPGEN) $(DEPCM) $(DEPLBS) logic/bcast_server.c
	$(CC) $(CFLAGS) -c logic/bcast_server.c

bcast_client.o: $(DEPGEN) $(DEPCM) $(DEPLBC) logic/bcast_client.c
	$(CC) $(CFLAGS) -c logic/bcast_client.c

interface_server.o: $(DEPGEN) $(DEPCM) $(DEPLIS) $(DEPLDC) logic/interface_server.c
	$(CC) $(CFLAGS) -c logic/interface_server.c

# security manager
security_manager.o: $(DEPGEN) $(DEPSM) security_manager/security_manager.c
	$(CC) $(CFLAGS) -c security_manager/security_manager.c

tpm.o: $(DEPGEN) $(DEPCM) $(DEPLIS) $(DEPLDC) security_manager/tpm.c
	$(CC) $(CFLAGS) -c security_manager/tpm.c

# data manager
data_manager.o: $(DEPGEN) $(DEPDM) data_manager/data_manager.c
	$(CC) $(CFLAGS) -c data_manager/data_manager.c

# generic stuff
generic.o: $(DEPGEN) generic/generic.c
	$(CC) $(CFLAGS) -c generic/generic.c

socks.o: $(DEPGEN) generic/socks.c
	$(CC) $(CFLAGS) -c generic/socks.c

server.o: $(DEPGEN) $(DEPSM) $(DEPDM) generic/server.c
	$(CC) $(CFLAGS) -c generic/server.c

semaphores.o: $(DEPGEN) generic/semaphores.c
	$(CC) $(CFLAGS) -c generic/semaphores.c

def.o: generic/def.c
	$(CC) $(CFLAGS) -c generic/def.c


clean:
	$(RM) $(PROG) $(OBJS) $(GEN) $(LOGIC) paradiso.o commandline.o commandline

install:
	gcc $(BFLAGS) tools/generate_rsa_keypair.c -o gen_rsa_keypair
	gcc $(BFLAGS) tools/sign_rsa_key.c -o sign_rsa_key
	gcc $(BFLAGS) tools/zero_file.c -o zero_file
	cp setupfiles/* .
	mkdir $(EXDIR)
	./zero_file $(EXDIR)/drl.data
	rm zero_file
	mkdir $(EXDIR)/tpm
	openssl rand -out $(EXDIR)/tpm/tpm.secured.storage.mem 524288
	mkdir $(EXDIR)/keys
	./gen_rsa_keypair device
	rm gen_rsa_keypair
	./sign_rsa_key device manufacturer
	rm sign_rsa_key
	mv device.private.key $(EXDIR)/tpm/
	mv device.public.key $(EXDIR)/keys/
	mv manufacturer.public.key $(EXDIR)/keys/
	mv device.manufacturer.sig $(EXDIR)/keys/
	rm manufacturer.private.key
	mv licenseorg.public.key $(EXDIR)/keys/
	mv manufacturer.licenseorg.sig $(EXDIR)/keys/
	mkdir $(EXDIR)/clf
	mkdir $(EXDIR)/sessions
	mkdir $(EXDIR)/payments
	mkdir $(EXDIR)/respayments
	mkdir $(EXDIR)/content
	mkdir $(EXDIR)/temp
	chmod 777 -R $(EXDIR)
	chmod 700 $(EXDIR)/tpm/device.private.key
ifdef PRJROOT
	cp $(PROG) $(EXDIR)/..
endif

uninstall:
	rm -R $(EXDIR)
