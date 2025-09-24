all: CLIENT_blinding_message SIGNER_MSS_keygen SIGNER_MSS_sign

CLIENT_blinding_message: CLIENT_blinding_message.c
	gcc -O2 -Wall CLIENT_blinding_message.c -o CLIENT_blinding_message -lcrypto

SIGNER_MSS_keygen: SIGNER_MSS_keygen.c SIGNER_pk_extract.c shared.c
	gcc -O2 -Wall SIGNER_MSS_keygen.c SIGNER_pk_extract.c shared.c -o SIGNER_MSS_keygen -lcrypto

SIGNER_MSS_sign: SIGNER_MSS_sign.c
	gcc -O2 -Wall SIGNER_MSS_sign.c -o SIGNER_MSS_sign -lcrypto

clean:
	rm -f CLIENT_blinding_message SIGNER_MSS_keygen
