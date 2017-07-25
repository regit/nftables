#!/bin/bash

cd $(dirname $0)

nft=../../src/nft
mydiff() {
	diff -w -I '^# ' "$@"
}

testdir=$(mktemp -d)
if [ ! -d $testdir ]; then
	echo "Failed to create test directory" >&2
	exit 0
fi
trap "rm -rf $testdir; $nft flush ruleset" EXIT

command_file=$(mktemp -p $testdir)
output_file=$(mktemp -p $testdir)

cmd_append() {
	echo "$*" >>$command_file
}
output_append() {
	[[ "$*" == '-' ]] && {
		cat $command_file >>$output_file
		return
	}
	echo "$*" >>$output_file
}
run_test() {
	monitor_output=$(mktemp -p $testdir)
	$nft monitor >$monitor_output &
	monitor_pid=$!

	sleep 0.5

	$nft -f $command_file || {
		echo "nft command failed!"
		kill $monitor_pid
		wait >/dev/null 2>&1
		exit 1
	}
	sleep 0.5
	kill $monitor_pid
	wait >/dev/null 2>&1
	if ! mydiff -q $monitor_output $output_file >/dev/null 2>&1; then
		echo "monitor output differs!"
		mydiff -u $output_file $monitor_output
		exit 1
	fi
	rm $command_file
	rm $output_file
	touch $command_file
	touch $output_file
}

for testcase in testcases/*.t; do
	echo "running tests from file $(basename $testcase)"
	# files are like this:
	#
	# I add table ip t
	# O add table ip t
	# I add chain ip t c
	# O add chain ip t c

	$nft flush ruleset

	input_complete=false
	while read dir line; do
		case $dir in
		I)
			$input_complete && run_test
			input_complete=false
			cmd_append "$line"
			;;
		O)
			input_complete=true
			output_append "$line"
			;;
		'#'|'')
			# ignore comments and empty lines
			;;
		esac
	done <$testcase
	$input_complete && run_test
done
