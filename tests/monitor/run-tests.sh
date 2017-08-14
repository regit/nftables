#!/bin/bash

cd $(dirname $0)
nft=../../src/nft
debug=false

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
monitor_output_append() {
	[[ "$*" == '-' ]] && {
		cat $command_file >>$output_file
		return
	}
	echo "$*" >>$output_file
}
echo_output_append() {
	# this is a bit tricky: for replace commands, nft prints a delete
	# command - so in case there is a replace command in $command_file,
	# just assume any other commands in the same file are sane
	grep -q '^replace' $command_file >/dev/null 2>&1 && {
		monitor_output_append "$*"
		return
	}
	[[ "$*" == '-' ]] && {
		grep '^\(add\|replace\|insert\)' $command_file >>$output_file
		return
	}
	[[ "$*" =~ ^add|replace|insert ]] && echo "$*" >>$output_file
}
monitor_run_test() {
	monitor_output=$(mktemp -p $testdir)
	$nft -nn monitor >$monitor_output &
	monitor_pid=$!

	sleep 0.5

	$debug && {
		echo "command file:"
		cat $command_file
	}
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

echo_run_test() {
	echo_output=$(mktemp -p $testdir)
	$debug && {
		echo "command file:"
		cat $command_file
	}
	$nft -nn -e -f $command_file >$echo_output || {
		echo "nft command failed!"
		exit 1
	}
	if ! mydiff -q $echo_output $output_file >/dev/null 2>&1; then
		echo "echo output differs!"
		mydiff -u $output_file $echo_output
		exit 1
	fi
	rm $command_file
	rm $output_file
	touch $command_file
	touch $output_file
}

for variant in monitor echo; do
	run_test=${variant}_run_test
	output_append=${variant}_output_append

	for testcase in testcases/*.t; do
		echo "$variant: running tests from file $(basename $testcase)"
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
				$input_complete && $run_test
				input_complete=false
				cmd_append "$line"
				;;
			O)
				input_complete=true
				$output_append "$line"
				;;
			'#'|'')
				# ignore comments and empty lines
				;;
			esac
		done <$testcase
		$input_complete && $run_test
	done
done
