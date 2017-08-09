#!/bin/bash

cd $(dirname $0)
nft=../../src/nft
nft_opts="-nn -a --echo"
debug=false

debug_echo() {
	$debug || return

	echo "$@"
}

trap "$nft flush ruleset" EXIT

for testcase in testcases/*.t; do
	echo "running tests from file $(basename $testcase)"
	# files are like this:
	#
	# <input command>[;;<output regexp>]

	$nft flush ruleset

	while read line; do
		[[ -z "$line" || "$line" == "#"* ]] && continue

		# XXX: this only works if there is no semicolon in output
		input="${line%;;*}"
		output="${line##*;;}"

		[[ -z $output ]] && output="$input"

		debug_echo "calling '$nft $nft_opts $input'"
		cmd_out=$($nft $nft_opts $input)
		# strip trailing whitespace (happens when adding a named set)
		cmd_out="${cmd_out% }"
		debug_echo "got output '$cmd_out'"
		[[ $cmd_out == $output ]] || {
			echo "Warning: Output differs:"
			echo "# nft $nft_opts $input"
			echo "- $output"
			echo "+ $cmd_out"
		}
	done <$testcase
done
