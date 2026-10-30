#!/usr/bin/env bash

set -euo pipefail

./build.sh

BACKGROUND_PIDS=()
BACKGROUND_LOGS=()
COLLISION_SERVER_PID=""

cleanup() {
    for log_file in "${BACKGROUND_LOGS[@]}"; do
        rm -f "$log_file"
    done

    if [[ -n "${COLLISION_SERVER_PID:-}" ]]; then
        kill "$COLLISION_SERVER_PID" 2>/dev/null || true
        wait "$COLLISION_SERVER_PID" 2>/dev/null || true
        COLLISION_SERVER_PID=""
    fi
}
trap cleanup EXIT

run_test_async() {
    local log_file
    log_file=$(mktemp)
    BACKGROUND_LOGS+=("$log_file")

    ./run-test.sh "$@" > "$log_file" 2>&1 &
    BACKGROUND_PIDS+=($!)
}

wait_for_async_tests() {
    local failed=0
    local i

    for i in "${!BACKGROUND_PIDS[@]}"; do
        local pid="${BACKGROUND_PIDS[$i]}"
        local log_file="${BACKGROUND_LOGS[$i]}"

        wait "$pid" || failed=1
        cat "$log_file"
        rm -f "$log_file"
    done

    BACKGROUND_PIDS=()
    BACKGROUND_LOGS=()

    if [[ $failed -ne 0 ]]; then
        exit 1
    fi
}

# It should run example files.
./run-test.sh "$@" "it_should_run_assembly_file_vm1" ./myvmm -v assembly_file_vm1
./run-test.sh "$@" "it_should_run_assembly_file_vm2" ./myvmm -v assembly_file_vm2
./run-test.sh "$@" "it_should_run_assembly_file_vm1_and_vm2" ./myvmm -v assembly_file_vm1 -v assembly_file_vm2

# It should be configurable.
./run-test.sh "$@" "it_should_print_debug_statements" ./myvmm -d -v tests/debug_assembly_file
./run-test.sh "$@" "it_should_print_debug_statements_for_multiple_vms" ./myvmm -d -v tests/debug_multiple_vms_vm1_assembly_file -v tests/debug_multiple_vms_vm2_assembly_file

# It should handle configuration errors.
./run-test.sh "$@" "it_should_exit_on_no_argument" ./myvmm
./run-test.sh "$@" "it_should_fail_on_too_long_argument" ./myvmm -v "$(printf '%*s' -4097 '' | tr ' ' 'A')"
./run-test.sh "$@" "it_should_fail_on_non_existent_assembly_file" ./myvmm -v tests/non_existent_assembly_file
./run-test.sh "$@" "it_should_fail_on_non_existent_succeeding_assembly_file" ./myvmm -v tests/noop_assembly_file -v tests/non_existent_assembly_file
./run-test.sh "$@" "it_should_fail_on_empty_vm_binary" ./myvmm -v tests/empty_vm_binary_assembly_file
./run-test.sh "$@" "it_should_fail_on_non_existent_vm_binary" ./myvmm -v tests/non_existent_vm_binary_assembly_file
./run-test.sh "$@" "it_should_fail_on_non_existent_succeeding_vm_binary" ./myvmm -v tests/noop_assembly_file -v tests/non_existent_vm_binary_assembly_file
./run-test.sh "$@" "it_should_fail_on_privileged_port" ./myvmm -p 80
./run-test.sh "$@" "it_should_fail_on_out_of_range_port" ./myvmm -p 70000
./run-test.sh "$@" "it_should_fail_on_non_numeric_port" ./myvmm -p abc
./run-test.sh "$@" "it_should_fail_on_migrate_to_privileged_port" ./myvmm -v tests/migration_privileged_port_assembly_file
./run-test.sh "$@" "it_should_fail_on_migrate_to_out_of_range_port" ./myvmm -v tests/migration_out_of_range_port_assembly_file
./run-test.sh "$@" "it_should_fail_on_invalid_timeout" ./myvmm -t 0
./run-test.sh "$@" "it_should_fail_on_negative_timeout" ./myvmm -t -1
./run-test.sh "$@" "it_should_fail_on_non_numeric_timeout" ./myvmm -t abc
./run-test.sh "$@" "it_should_fail_on_zero_instruction_slice" ./myvmm -n 0
./run-test.sh "$@" "it_should_fail_on_negative_instruction_slice" ./myvmm -n -1
./run-test.sh "$@" "it_should_fail_on_non_numeric_instruction_slice" ./myvmm -n abc


# It should support configuration quirks.
./run-test.sh "$@" "it_should_parse_spaced_vm_file" ./myvmm -v tests/spaced_assembly_file
./run-test.sh "$@" "it_should_skip_blank_lines_between_instructions" ./myvmm -v tests/blank_lines_assembly_file
./run-test.sh "$@" "it_should_follow_last_of_duplicate_config" ./myvmm -v tests/duplicate_config_assembly_file
./run-test.sh "$@" "it_should_ignore_zero_vm_exec_slice" ./myvmm -v tests/zero_vm_exec_slice_assembly_file
./run-test.sh "$@" "it_should_ignore_negative_vm_exec_slice" ./myvmm -v tests/negative_vm_exec_slice_assembly_file
./run-test.sh "$@" "it_should_ignore_non_numeric_vm_exec_slice" ./myvmm -v tests/non_numeric_vm_exec_slice_assembly_file
./run-test.sh "$@" "it_should_skip_when_no_vm_configured" ./myvmm -d
./run-test.sh "$@" "it_should_parse_absolute_paths" ./myvmm -d -v /home/johnbunag/Documents/remote-cmpe-283-virtual-technologies/project/tests/absolute_path_assembly_file
./run-test.sh "$@" "it_should_create_snapshot_with_mixed_paths" ./myvmm -v mixed_paths_assembly_file
./run-test.sh "$@" "it_should_restore_snapshot_with_mixed_paths" ./myvmm -v mixed_paths_assembly_file -s /home/johnbunag/Documents/remote-cmpe-283-virtual-technologies/project/tests/mixed_paths_snapshot
./run-test.sh "$@" "it_should_create_duplicate_snapshots" ./myvmm -v tests/duplicate_snapshot_assembly_file
./run-test.sh "$@" "it_should_follow_last_of_duplicate_snapshot" ./myvmm -v tests/duplicate_snapshot_assembly_file -s tests/duplicate_snapshot_first_snapshot -s tests/duplicate_snapshot_second_snapshot


# It should support instructions.
./run-test.sh "$@" "it_should_load_immediate" ./myvmm -v tests/load_immediate_assembly_file
./run-test.sh "$@" "it_should_add" ./myvmm -v tests/add_assembly_file
./run-test.sh "$@" "it_should_subtract" ./myvmm -v tests/subtract_assembly_file
./run-test.sh "$@" "it_should_add_immediate" ./myvmm -v tests/add_immediate_assembly_file
./run-test.sh "$@" "it_should_add_unsigned" ./myvmm -v tests/add_unsigned_assembly_file
./run-test.sh "$@" "it_should_subtract_unsigned" ./myvmm -v tests/subtract_unsigned_assembly_file
./run-test.sh "$@" "it_should_add_immediate_unsigned" ./myvmm -v tests/add_immediate_unsigned_assembly_file
./run-test.sh "$@" "it_should_multiply_without_overflow" ./myvmm -v tests/multiply_without_overflow_assembly_file
./run-test.sh "$@" "it_should_multiply" ./myvmm -v tests/multiply_assembly_file
./run-test.sh "$@" "it_should_divide" ./myvmm -v tests/divide_assembly_file
./run-test.sh "$@" "it_should_and" ./myvmm -v tests/and_assembly_file
./run-test.sh "$@" "it_should_or" ./myvmm -v tests/or_assembly_file
./run-test.sh "$@" "it_should_and_immediate" ./myvmm -v tests/and_immediate_assembly_file
./run-test.sh "$@" "it_should_or_immediate" ./myvmm -v tests/or_immediate_assembly_file
./run-test.sh "$@" "it_should_shift_left_logical" ./myvmm -v tests/shift_left_logical_assembly_file
./run-test.sh "$@" "it_should_shift_right_logical" ./myvmm -v tests/shift_right_logical_assembly_file
./run-test.sh "$@" "it_should_xor" ./myvmm -v tests/xor_assembly_file

# It should handle instruction errors.
./run-test.sh "$@" "it_should_ignore_out_of_bounds_register" ./myvmm -v tests/out_of_bounds_register_assembly_file
./run-test.sh "$@" "it_should_ignore_write_to_zero_register" ./myvmm -v tests/zero_register_assembly_file

# It should support instruction execution slicing.
./run-test.sh "$@" "it_should_run_multiple_vms_with_instruction_slice" ./myvmm -d -n 2 -v tests/instruction_slice_vm1_assembly_file -v tests/instruction_slice_vm2_assembly_file
./run-test.sh "$@" "it_should_support_individual_vm_instruction_slices" ./myvmm -d -v tests/individual_slice_lower_assembly_file -v tests/individual_slice_higher_assembly_file -v tests/individual_slice_unbounded_assembly_file
./run-test.sh "$@" "it_should_override_individual_vm_instruction_slices_with_global_slice" ./myvmm -d -n 4 -v tests/individual_slice_lower_assembly_file -v tests/individual_slice_higher_assembly_file -v tests/individual_slice_unbounded_assembly_file

# It should support snapshots.
./run-test.sh "$@" "it_should_create_single_snapshot" ./myvmm -d -v tests/single_snapshot_assembly_file
./run-test.sh "$@" "it_should_restore_single_snapshot" ./myvmm -d -v tests/single_snapshot_assembly_file -s tests/single_snapshot_snapshot
./run-test.sh "$@" "it_should_create_snapshot_with_mutations" ./myvmm -d -v tests/snapshot_mutations_assembly_file
./run-test.sh "$@" "it_should_restore_snapshot_with_mutations" ./myvmm -d -v tests/snapshot_mutations_assembly_file -s tests/snapshot_mutations_snapshot
./run-test.sh "$@" "it_should_create_multiple_snapshots" ./myvmm -v tests/multiple_snapshots_assembly_file
./run-test.sh "$@" "it_should_restore_multiple_snapshots_first_snapshot" ./myvmm -v tests/multiple_snapshots_assembly_file -s tests/multiple_snapshots_first_snapshot
./run-test.sh "$@" "it_should_restore_multiple_snapshots_second_snapshot" ./myvmm -v tests/multiple_snapshots_assembly_file -s tests/multiple_snapshots_second_snapshot
./run-test.sh "$@" "it_should_handle_skip_instructions_exceeding_length" ./myvmm -d -v tests/skip_instructions_exceeded_assembly_file -s tests/skip_instructions_exceeded_snapshot
./run-test.sh "$@" "it_should_restore_snapshot_with_blank_lines" ./myvmm -v tests/spaced_snapshot_assembly_file -s tests/spaced_snapshot_snapshot
./run-test.sh "$@" "it_should_create_snapshot_for_vm_snapshot" ./myvmm -v assembly_file_vm_snapshot
./run-test.sh "$@" "it_should_restore_snapshot_for_vm_snapshot" ./myvmm -v assembly_file_vm_snapshot -s snapshot_vm_snapshot
./run-test.sh "$@" "it_should_create_snapshot_with_absolute_path" ./myvmm -v /home/johnbunag/Documents/remote-cmpe-283-virtual-technologies/project/tests/absolute_path_snapshot_assembly_file
./run-test.sh "$@" "it_should_restore_snapshot_with_absolute_path" ./myvmm -v /home/johnbunag/Documents/remote-cmpe-283-virtual-technologies/project/tests/absolute_path_snapshot_assembly_file -s /home/johnbunag/Documents/remote-cmpe-283-virtual-technologies/project/tests/absolute_path_snapshot_snapshot
./run-test.sh "$@" "it_should_create_snapshots_for_multiple_vms" ./myvmm -v tests/multiple_vms_snapshot_vm1_assembly_file -v tests/multiple_vms_snapshot_vm2_assembly_file
./run-test.sh "$@" "it_should_restore_snapshots_for_multiple_vms" ./myvmm -v tests/multiple_vms_snapshot_vm1_assembly_file -s tests/multiple_vms_snapshot_vm1_snapshot -v tests/multiple_vms_snapshot_vm2_assembly_file -s tests/multiple_vms_snapshot_vm2_snapshot
./run-test.sh "$@" "it_should_warn_on_unknown_snapshot_instruction" ./myvmm -v tests/snapshot_unknown_instruction_assembly_file -s tests/snapshot_unknown_instruction_snapshot

# It should handle snapshot errors.
./run-test.sh "$@" "it_should_fail_on_non_existent_snapshot" ./myvmm -v tests/noop_assembly_file -s tests/non_existent_snapshot
./run-test.sh "$@" "it_should_fail_on_snapshot_flag_before_vm_flag" ./myvmm -s tests/non_existent_snapshot -v tests/noop_assembly_file -v tests/noop_assembly_file
./run-test.sh "$@" "it_should_fail_on_mismatched_snapshot_hash" ./myvmm -v tests/mismatched_hash_snapshot_assembly_file -s tests/mismatched_hash_snapshot_snapshot
./run-test.sh "$@" "it_should_drop_mismatched_snapshot_between_valid_vms" ./myvmm -v assembly_file_vm1 -v tests/mismatched_hash_snapshot_assembly_file -s tests/mismatched_hash_snapshot_snapshot -v assembly_file_vm2
./run-test.sh "$@" "it_should_fail_on_missing_skip_instructions" ./myvmm -v tests/missing_skip_instructions_snapshot_assembly_file -s tests/missing_skip_instructions_snapshot_snapshot
./run-test.sh "$@" "it_should_fail_on_skip_instructions_after_li" ./myvmm -v tests/skip_after_li_snapshot_assembly_file -s tests/skip_after_li_snapshot_snapshot
./run-test.sh "$@" "it_should_fail_on_missing_validate_instructions" ./myvmm -v tests/missing_validate_instructions_snapshot_assembly_file -s tests/missing_validate_instructions_snapshot_snapshot
./run-test.sh "$@" "it_should_fail_on_validate_not_first_instruction" ./myvmm -v tests/validate_not_first_snapshot_assembly_file -s tests/validate_not_first_snapshot_snapshot
./run-test.sh "$@" "it_should_fail_on_create_snapshot_in_non_existent_directory" ./myvmm -v tests/non_existent_directory_snapshot_assembly_file

# It should support live migration.
run_test_async "$@" "it_should_support_live_migration" ./myvmm -d -p 9090 -t 1 -v tests/live_migration_assembly_file
run_test_async "$@" "it_should_timeout_when_no_migration_received" ./myvmm -p 9091 -t 6
run_test_async "$@" "it_should_support_self_migration_with_multiple_vms" ./myvmm -p 9093 -t 1 -v tests/self_migration_vm1_assembly_file -v tests/self_migration_vm2_assembly_file
run_test_async "$@" "it_should_support_multiple_migrations_in_same_instruction_file" ./myvmm -p 9094 -t 1 -v tests/multiple_self_migrations_assembly_file
run_test_async "$@" "it_should_resume_local_execution_on_migration_failure" ./myvmm -v tests/migration_failure_fallback_assembly_file
run_test_async "$@" "it_should_resume_local_execution_on_unresolvable_migration_host" ./myvmm -v tests/migration_unresolvable_host_assembly_file
run_test_async "$@" "it_should_support_snapshot_before_and_after_migration" ./myvmm -p 9095 -t 1 -v tests/snapshot_migration_interleaved_assembly_file
run_test_async "$@" "it_should_create_snapshot_on_migrated_node" ./myvmm -p 9096 -t 1 -v tests/snapshot_on_migrated_node_assembly_file
run_test_async "$@" "it_should_restore_snapshot_created_on_migrated_node" ./myvmm -v tests/snapshot_on_migrated_node_assembly_file -s tests/snapshot_on_migrated_node_snapshot
run_test_async "$@" "it_should_support_migration_as_first_instruction" ./myvmm -p 9097 -t 1 -v tests/cold_offload_migration_assembly_file
run_test_async "$@" "it_should_support_migration_as_final_instruction" ./myvmm -d -p 9098 -t 1 -v tests/final_instruction_migration_assembly_file
run_test_async "$@" "it_should_migrate_already_restored_vm" ./myvmm -p 9099 -t 1 -v tests/snapshot_then_migrate_assembly_file -s tests/snapshot_then_migrate_initial_snapshot

# It should support cross-process live migration.
run_test_async "$@" "it_should_receive_cross_process_migration" ./myvmm -p 9900 -t 2
run_test_async "$@" "it_should_send_cross_process_migration" ./myvmm -v tests/cross_process_migration_assembly_file
run_test_async "$@" "it_should_round_trip_migrate_vm_a" ./myvmm -p 9901 -t 3 -v tests/round_trip_vm_a_assembly_file
run_test_async "$@" "it_should_round_trip_migrate_vm_b" ./myvmm -p 9902 -t 3 -v tests/round_trip_vm_b_assembly_file

MIGRATION_DOMAIN="${MIGRATION_DOMAIN:-cmpe-283.ianbunag.dev}"

# It should confirm live url requests go through the internet - the request will fail because the port is not exposed.
cat <<EOF > tests/localhost_then_closed_port_migration_instructions
li \$1,10
li \$2,20
add \$3,\$1,\$2
MIGRATE 127.0.0.1:9088
addi \$3,\$3,12
MIGRATE ${MIGRATION_DOMAIN}:9088
addi \$3,\$3,8
DUMP_REGISTER_STATE \$3
EOF
run_test_async "$@" "it_should_resume_local_execution_on_closed_port_after_localhost_migration" ./myvmm -d -p 9088 -t 1 -v tests/localhost_then_closed_port_migration_assembly_file

# It should support live url migration.
cat <<EOF > tests/live_url_migration_instructions
li \$1,10
li \$2,20
add \$3,\$1,\$2
MIGRATE ${MIGRATION_DOMAIN}:9089
addi \$3,\$3,12
DUMP_REGISTER_STATE \$3
EOF
run_test_async "$@" "it_should_support_live_url_migration" ./myvmm -d -p 9089 -t 1 -v tests/live_url_migration_assembly_file

# It should support complete feature set
run_test_async "$@" "it_should_support_complete_feature_set" ./myvmm -d -p 9078 -t 1 -n 2 -v tests/complete_feature_set_vm1_assembly_file -s tests/complete_feature_set_vm1_snapshot -v tests/complete_feature_set_vm2_assembly_file

# It should fail on server port collision.
./myvmm -p 9990 -t 5 >/dev/null 2>&1 &
COLLISION_SERVER_PID=$!
sleep 0.5
run_test_async "$@" "it_should_fail_on_server_port_collision" ./myvmm -p 9990

# Cleanup.
wait_for_async_tests
