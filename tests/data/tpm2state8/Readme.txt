The state files in this directory were created with the following commands.
Note that there is an RSA-3072 signing key persisted at 81000000 and an RSA-3072
storage key at 81000001.

profile=default-v1
version=v0.10    ; means that libtpms v0.10 was used to create the state

swtpm socket \
	--tpmstate backend-uri=file://data/tpm2state8/tpmstate-${version}-${profile}.bin \
	--tpm2 \
	--ctrl type=tcp,port=2322 \
	--server type=tcp,port=2321 \
	--flags not-need-init,startup-clear \
	--profile name=${profile}

tsscreateprimary -hi o -rsa 3072 -si
tssevictcontrol -hi o -ho 80000000 -hp 81000000

tsscreateprimary -hi o -rsa 3072 -des
tssevictcontrol -hi o -ho 80000001 -hp 81000001

tsssign \
	-if ./tests/data/tpm2state8/tosign.txt \
	-hk 81000000 \
	-halg sha256 \
	-os ./tests/data/tpm2state8/signature-v0.10-default-v1.bin \
	-scheme rsapss

tssencryptdecrypt \
	-hk 81000001 \
	-if ./tests/data/tpm2state8/toencrypt.txt \
	-of ./tests/data/tpm2state8/encrypted-v0.10-default.bin
