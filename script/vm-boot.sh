qemu-system-x86_64 \
	-m 2G \
	-smp 2 \
	-kernel /home/tlyu/ebpf-fuzzing/kernel/bzImage \
	-append "console=ttyS0 root=/dev/sda earlyprintk=serial net.ifnames=0" \
	-drive file=/home/tlyu/ebpf-fuzzing/image/bullseye.img,format=raw \
	-net user,host=10.0.2.10,hostfwd=tcp:127.0.0.1:10021-:22 \
	-net nic,model=e1000 \
	-enable-kvm \
	-nographic \
	-pidfile vm.pid \
	2>&1
