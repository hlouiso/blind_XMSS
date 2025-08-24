OPENSSL_DIR = ../third_party/openssl/openssl-1.0.2l

CFLAGS  = -O2 -Wall -fopenmp -I$(OPENSSL_DIR)/include
LDFLAGS = -fopenmp $(OPENSSL_DIR)/libssl.a $(OPENSSL_DIR)/libcrypto.a -ldl

all: ../prover ../verifier ../sign ../commitment_gen

../prover: prover.o shared.o MPC_prove_functions.o building_views.o
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

shared.o: shared.c shared.h
	$(CC) $(CFLAGS) -c $< -o $@

prover.o: prover.c shared.h MPC_prove_functions.h building_views.h
	$(CC) $(CFLAGS) -c $< -o $@

MPC_prove_functions.o: MPC_prove_functions.c MPC_prove_functions.h shared.h
	$(CC) $(CFLAGS) -c $< -o $@

building_views.o: building_views.c building_views.h MPC_prove_functions.h shared.h
	$(CC) $(CFLAGS) -c $< -o $@

../verifier: verifier.o shared.o MPC_verify_functions.o
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

verifier.o: verifier.c shared.h MPC_verify_functions.h
	$(CC) $(CFLAGS) -c $< -o $@

MPC_verify_functions.o: MPC_verify_functions.c MPC_verify_functions.h shared.h
	$(CC) $(CFLAGS) -c $< -o $@

../sign: WOTS_Sign.o
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

WOTS_Sign.o: WOTS_Sign.c
	$(CC) $(CFLAGS) -c $< -o $@

../commitment_gen: commitment_gen.o
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

commitment_gen.o: commitment_gen.c
	$(CC) $(CFLAGS) -c $< -o $@

%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -f *.o src/*.o ../prover ../verifier ../sign ../out* ../proof.bin ../*.txt ../commitment_gen
