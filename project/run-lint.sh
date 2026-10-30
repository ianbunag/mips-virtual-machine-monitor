./build.sh

echo "----- Performing SAST with flawfinder -----"
flawfinder myvmm.c

echo ""
echo "------ Performing DAST with Valgrind ------"
valgrind --leak-check=full ./myvmm -d -p 9089 -t 1 -n 2 -v assembly_file_vm1 -v assembly_file_vm2 -v assembly_file_vm_snapshot -v assembly_file_vm_snapshot -s snapshot_vm_snapshot -v tests/complete_feature_set_live_url_vm1_assembly_file
