#!/usr/bin/env bash

#echo $@

main() {
	local typ ek dir vmid

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
			;;
		esac
		shift
	done

	case "$typ" in
	ek)
		echo -n "ek" > ${dir}/ek.cert
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
