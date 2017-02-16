#!/bin/bash

# Configuration
TESTDIR="./"
RETURNCODE_SEPARATOR="_"
SRC_NFT="../../src/nft"

msg_error() {
	echo "E: $1 ..." >&2
	exit 1
}

msg_warn() {
	echo "W: $1" >&2
}

msg_info() {
	echo "I: $1"
}

if [ "$(id -u)" != "0" ] ; then
	msg_error "this requires root!"
fi

[ -z "$NFT" ] && NFT=$SRC_NFT
if [ ! -x "$NFT" ] ; then
	msg_error "no nft binary!"
else
	msg_info "using nft binary $NFT"
fi

if [ ! -d "$TESTDIR" ] ; then
	msg_error "missing testdir $TESTDIR"
fi

FIND="$(which find)"
if [ ! -x "$FIND" ] ; then
	msg_error "no find binary found"
fi

MODPROBE="$(which modprobe)"
if [ ! -x "$MODPROBE" ] ; then
	msg_error "no modprobe binary found"
fi

if [ -x "$1" ] ; then
	if grep ^.*${RETURNCODE_SEPARATOR}[0-9]\\+$ <<< $1 >/dev/null ; then
		SINGLE=$1
		VERBOSE=y
	fi
fi

if [ "$1" == "-v" ] ; then
	VERBOSE=y
fi

kernel_cleanup() {
	$NFT flush ruleset
	$MODPROBE -raq \
	nft_reject_ipv4 nft_reject_bridge nft_reject_ipv6 nft_reject \
	nft_redir_ipv4 nft_redir_ipv6 nft_redir \
	nft_dup_ipv4 nft_dup_ipv6 nft_dup nft_nat \
	nft_masq_ipv4 nft_masq_ipv6 nft_masq \
	nft_exthdr nft_payload nft_cmp nft_range \
	nft_quota nft_queue nft_numgen \
	nft_meta nft_meta_bridge nft_counter nft_log nft_limit \
	nft_hash nft_ct nft_compat nft_rt \
	nft_set_hash nft_set_rbtree nft_set_bitmap \
	nft_chain_nat_ipv4 nft_chain_nat_ipv6 \
	nf_tables_inet nf_tables_bridge nf_tables_arp \
	nf_tables_ipv4 nf_tables_ipv6 nf_tables
}

find_tests() {
	if [ ! -z "$SINGLE" ] ; then
		echo $SINGLE
		return
	fi
	${FIND} ${TESTDIR} -executable -regex \
		.*${RETURNCODE_SEPARATOR}[0-9]+ | sort
}

echo ""
ok=0
failed=0
for testfile in $(find_tests)
do
	kernel_cleanup

	rc_spec=$(awk -F${RETURNCODE_SEPARATOR} '{print $NF}' <<< $testfile)

	msg_info "[EXECUTING]	$testfile"
	test_output=$(NFT=$NFT ${testfile} 2>&1)
	rc_got=$?
	echo -en "\033[1A\033[K" # clean the [EXECUTING] foobar line

	if [ "$rc_got" == "$rc_spec" ] ; then
		msg_info "[OK]		$testfile"
		[ "$VERBOSE" == "y" ] && [ ! -z "$test_output" ] && echo "$test_output"
		((ok++))
	else
		((failed++))
		if [ "$VERBOSE" == "y" ] ; then
			msg_warn "[FAILED]	$testfile: expected $rc_spec but got $rc_got"
			[ ! -z "$test_output" ] && echo "$test_output"
		else
			msg_warn "[FAILED]	$testfile"
		fi
	fi
done

echo ""
msg_info "results: [OK] $ok [FAILED] $failed [TOTAL] $((ok+failed))"

kernel_cleanup
exit 0
