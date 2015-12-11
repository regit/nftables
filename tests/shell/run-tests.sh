#!/bin/bash

# Configuration
TESTDIR="./"
RETURNCODE_SEPARATOR="_"

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

[ -z "$NFT" ] && NFT="$(which nft)"
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

if [ "$1" == "-v" ] ; then
	VERBOSE=y
fi

echo ""
ok=0
failed=0
for testfile in $(${FIND} ${TESTDIR} -executable -regex .*${RETURNCODE_SEPARATOR}[0-9]+)
do
	$NFT flush ruleset

	rc_spec=$(awk -F${RETURNCODE_SEPARATOR} '{print $NF}' <<< $testfile)
	test_output=$(NFT=$NFT ${testfile} ${TESTS_OUTPUT} 2>&1)
	rc_got=$?
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

$NFT flush ruleset
