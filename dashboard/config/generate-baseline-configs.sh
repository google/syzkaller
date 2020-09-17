#!/bin/bash
# Copyright 2020 syzkaller project authors. All rights reserved.
# Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

[ -z "${CC}" ] && echo 'Please set $CC to point to the compiler!' && exit
[ -z "${KERNEL_SOURCE}" ] && echo 'Please set $KERNEL_SOURCE to point to the kernel tree!' && exit

other_configs=""
for config in "upstream-kcsan.config upstream-kmsan.config upstream-leak.config upstream-usb.config"
do
    other_configs="$other_configs `realpath $config`"
done

# First prepare baseline for kasan config. Barebones was prepared by starting from kasan
# config and disabling everything that is not needed to bootup. Also all debugging options
# were kept as they are.
kasan_config=`realpath upstream-kasan.config`
barebones_config=`realpath upstream-kasan-barebones.config`

# This will contain all config options that has to be enabled in barebones config
enabled_configs=$kasan_config.enabled
# This will contain all config options that has to be disabled after enabling config options
# in enabled_configs
disabled_configs=$kasan_config.disabled
# This will contain all config options that are disable in baseline compared to kasan config
baseline_disabled_configs=$kasan_config.baseline.disabled

# Clear options from previous runs.
echo -n > $enabled_configs $disabled_configs $baseline_disabled_configs

# All kernel Kconfig files
kconfig_files=`find $KERNEL_SOURCE -name Kconfig`

# Iterates all Kconfig files for options that are dependent on config option given as parameter
check_dependents () {
    option=$1
    dependents=""

    for kconfig_file in $kconfig_files
    do
	starting_line=0
	while [ 1 ]
	do
	    # Find first dependent config option
	    config_option_line=`tac $kconfig_file | tail -n +$starting_line | sed -e "1,/depends.*$option/d" | grep ^config -m 1`
	    if [ $? -eq 0 ]
	    then
		# Update starting line to go through whole file
		starting_line=`tac $kconfig_file | grep "$config_option_line$" -n -m 1 | cut -d ':' -f 1`
		# Add found dependent to list
		dependents="$dependents `echo $config_option_line | cut -d ' ' -f 2`"
	    else
		break
	    fi
	done
    done
    echo $dependents
}

# Check if given config option is enabled in our kasan config.
is_enabled () {
    option=$1

    grep CONFIG_$option=y $kasan_config > /dev/null
    if [ $? -eq 0 ]
    then
	echo "true"
    else
	echo "false"
    fi
}

# Figure out what is disabled in barebones.config compared to kasan config.
disabled_options=`diff -Naur $kasan_config $barebones_config | grep "^+.*is.not.set" | cut -d ' ' -f 2 | sed 's/CONFIG_//'`

# Iterate all disabled options and check if there are dependents that
# are enabled in kasan config. Add config options which has any
# enabled dependent to config options that has to be enabled.
for option in $disabled_options
do
    echo "Checking $option..."
    dependents="$(check_dependents $option)"
    echo $dependents

    for dependent in $dependents
    do
	echo "  checking if dependent $dependent is enabled..."
	enabled=$(is_enabled $dependent)
	if [ $enabled == "true" ]
	then
	    echo "  $dependent is enabled -> enabling dependency"
	    echo CONFIG_$option=y >> $enabled_configs
	    break
	fi
    done
done

cd ${KERNEL_SOURCE}
cp $barebones_config .config

# Enable all options that has dependent enabled in target config
scripts/kconfig/merge_config.sh -m .config $enabled_configs
make ${MAKE_VARS} olddefconfig

# Find out config options that were enabled during merge_config.sh &&
# make olddefconfig.  There are more than we listed in enabled_configs
# and we want to disable those.
enabled_options=`diff -Naur $barebones_config .config | grep "^+.*=[y|m]" | cut -d '=' -f 1 | cut -d '+' -f 2`

# Re-disable options that were unintentionally enabled by make
# olddefconfig
for option in $enabled_options
do
    grep $option $enabled_configs > /dev/null
    if [ $? -ne 0 ]
    then
	echo "# $option is not set" >> $disabled_configs
    fi
done

scripts/kconfig/merge_config.sh -m .config $disabled_configs
make ${MAKE_VARS} olddefconfig

# Now we have baseline for kasan config
cp .config $kasan_config.baseline

# Check what were options that are disabled in kasan baseline
diff -Naur $kasan_config $kasan_config.baseline | grep "^+.*is.not.set" | cut -d '+' -f 2 > $baseline_disabled_configs

# Write rest of the baseline configs
for other_config in $other_configs
do
    cp $other_config .config
    scripts/kconfig/merge_config.sh -m .config $baseline_disabled_configs
    make ${MAKE_VARS} olddefconfig
    cp .config $other_config.baseline
done
