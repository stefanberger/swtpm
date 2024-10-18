#!/usr/bin/env bash

#echo $@

ek_cert=\
MIID9TCCAl2gAwIBAgICBL4wDQYJKoZIhvcNAQELBQAwGDEWMBQGA1UEAxMNc3d0cG0tbG9jYWxj\
YTAgFw0yMzA4MjIwMTM2MDdaGA85OTk5MTIzMTIzNTk1OVowEjEQMA4GA1UEAxMHdW5rbm93bjCC\
ASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAJSKqmO3O1KnFQFXENX+z8kcL0eIFW8xVhPW\
eCJrChwRil36KaxJHPf5aqzWkMuZnCHI2U5susPq7BAeCCPXaOb3pwbs3tgEC5eGAEApv6Y+5Yep\
ia8chBGI58q3CuKL/HcToNnzT1MwwTtq4dCzav9BcmR/tkh9fSUvjOwZyPIDktgvMXAkLFzqhAx3\
8TKSqdhjWgbUAr8fGsAUGm1bvepphEpycjCfftdC6/GnGEbHsDWjBS944k3sHWD7Aik/VV9wEHLT\
EIN8r3rKdj5nzqUrGRFqSupN5e25YRhKxS1SB9wFOiOYoevsPR7Bh3/5MdZd33zhnTbrA9f0RDxu\
qjUCAwEAAaOBzDCByTAQBgNVHSUECTAHBgVngQUIATBSBgNVHREBAf8ESDBGpEQwQjEWMBQGBWeB\
BQIBDAtpZDowMDAwMTAxNDEQMA4GBWeBBQICDAVzd3RwbTEWMBQGBWeBBQIDDAtpZDoyMDE5MTAy\
MzAMBgNVHRMBAf8EAjAAMCIGA1UdCQQbMBkwFwYFZ4EFAhAxDjAMDAMyLjACAQACAgCkMB8GA1Ud\
IwQYMBaAFMFMlKkwREqQv5MU2eVVkxUZIOP0MA4GA1UdDwEB/wQEAwIFIDANBgkqhkiG9w0BAQsF\
AAOCAYEAihjxS4PmR5xO7jAYsF5hqeMvEh5+wH+OWjkj9oH+a8N6oFlxUJeQgLLFgK+Jyq4zt0kz\
tdAaFX0XrWfPH/s1AQdwtUzqOHdSHWcBmfPV+MlMCtz1HjfC5GGKmCHPgwDRLiowwzsWyKFRPKlu\
UtmtP0ukRTbzGa/j3GpBSnIn7l2yTrnXZ6XXeZ/gvHghzyp02aGJ2Ei873X57zOuFmz1z++WwXRN\
ipRoAjga57NAz/f1RceJuF+zA8aAX7GY2dcvDCVpU1yoBsWt9gXtZ/4ZO400fbwnxz3zVLJEXgpR\
jd+XbUUxsGMWqWZ3qEApbrkWjS77TXkDmOqK8Nh92mZvLSMHBJa/mzWFJBPpu+MCSPbO9kAhfB5W\
F2ynlGuQfeBue4ju5PmcID3xs2FbCItWyj8bJhuA2QQDYmUrSnqQJ9zNLj7ibbq7hDWsaeko65/E\
HYBXBvksWO4cdoR7F9pcuyhsJDMU7jyGAo0RKuRkUrGnN2Aja4GKSXTilXTCeq/5


main() {
	local typ ek dir vmid tpm2=0

	while [ $# -ne 0 ]; do
		#echo $1
		case "$1" in
		--type)
			shift
			typ="$1"
			;;
		--ek)
			shift
			ek="$1"
			;;
		--dir)
			shift
			dir="$1"
			;;
		--vmid)
			shift
			vmid="$1"
			;;
		--tpm2)
			tpm2=1
			;;
		esac
		shift
	done

	case "$typ" in
	ek)
		# ek cert must be parseable for a TPM 2
		if [ "${tpm2}" -ne 0 ]; then
			base64 -d <<< "${ek_cert}" > ${dir}/ek.cert
		else
			echo -n "ek" > ${dir}/ek.cert
		fi
		;;
	platform)
		echo -n "platform" > ${dir}/platform.cert
		;;
	iak)
		echo -n "iak" > ${dir}/iak.cert
		;;
	idevid)
		echo -n "idevid" > ${dir}/idevid.cert
		;;
	esac
}

main "$@"
