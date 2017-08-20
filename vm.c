#include <linux/kvm.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <string.h>

/*
 * References:
 *  - https://ziviani.net/2018/kvm-hello-world-ppc64
 *  - https://lwn.net/Articles/658511/
 *  - https://lwn.net/Articles/658512/
 *  - https://www.kernel.org/doc/Documentation/virtual/kvm/api.txt
 */
const char *errors[] = {
    "success",
    "cannot open /dev/kvm",
    "cannot get KVM version",
    "failed to create virtual machine",
    "failed to allocate memory for the code that will run inside the VM",
    "memory allocate is lower than the program to execute",
    "could load the program into the guest memory",
    "failed to set the memory region to the VM",
    "failed to create virtual CPU",
    "cannot get the size of kvm_run struct",
    "kvm_run size returned is smalled than expected",
    "cannot map kvm_run struct memory to internal struct",

    "cannot get sregs",
    "failed to write sregs",
    "failed to set registers values",

    "KVM exit fail entry - HW failure reason:",
    "KVM exit internal error - suberror:",
    "exit reason:",
};

struct virtual_machine
{
    int kvmfd;
    int vmfd;
    int vcpufd;

    struct kvm_sregs sregs;

    size_t codemem_len;
    uint16_t *codemem;
    struct kvm_run *kvmrun;
};

int create_vm(struct virtual_machine *vm, FILE *fd)
{
    int ret;
    size_t mmap_size;
    size_t fsize;

    vm->codemem_len = getpagesize() * 8192;

    vm->kvmfd = open("/dev/kvm", O_RDWR | O_CLOEXEC);
    if (vm->kvmfd == -1) {
        return 1;
    }

    ret = ioctl(vm->kvmfd, KVM_GET_API_VERSION, NULL);
    if (ret == -1) {
        return 2;
    }
    printf("KVM version %d\n", ret);

    vm->vmfd = ioctl(vm->kvmfd, KVM_CREATE_VM, (unsigned long)0);
    if (ret == -1) {
        return 3;
    }

    vm->codemem = mmap(NULL,
                       vm->codemem_len,
                       PROT_READ | PROT_WRITE,
                       MAP_SHARED | MAP_ANONYMOUS,
                       -1, 0);

    if (vm->codemem == NULL) {
        return 4;
    }

    fseek(fd, 0, SEEK_END);
    if ((fsize = ftell(fd)) > vm->codemem_len) {
        return 5;
    }
    rewind(fd);

    if (fread(vm->codemem, 1, fsize, fd) != fsize) {
        return 6;
    }    

    struct kvm_userspace_memory_region region = {
        .slot = 0,
        .guest_phys_addr = 0,
        .memory_size = vm->codemem_len,
        .userspace_addr = (uint64_t)vm->codemem,
    };

    if (ioctl(vm->vmfd, KVM_SET_USER_MEMORY_REGION, &region) == -1) {
        return 7;
    }

    vm->vcpufd = ioctl(vm->vmfd, KVM_CREATE_VCPU, (unsigned long)0);
    if (vm->vcpufd == -1) {
        return 8;
    }

    mmap_size = ioctl(vm->kvmfd, KVM_GET_VCPU_MMAP_SIZE, NULL);
    if (mmap_size == -1) {
        return 9;
    }

    if (mmap_size < sizeof(*vm->kvmrun)) {
        return 10;
    }

    vm->kvmrun = mmap(NULL,
                       mmap_size,
                       PROT_READ | PROT_WRITE,
                       MAP_SHARED,
                       vm->vcpufd, 0);

    if (vm->kvmrun == NULL) {
        return 11;
    }

    return 0;
}

int setup_registers(struct virtual_machine *vm)
{
    if (ioctl(vm->vcpufd, KVM_GET_SREGS, &vm->sregs) == -1) {
        return 12;
    }
    vm->sregs.pvr = 0x004d0200; // power8

    if (ioctl(vm->vcpufd, KVM_SET_SREGS, &vm->sregs) == -1) {
        return 13;
    }

    struct kvm_regs regs = {
        .pc = 0x100,
        .msr = 0x8000000000000001ULL,
    };

    if (ioctl(vm->vcpufd, KVM_SET_REGS, &regs) == -1) {
        return 14;
    }

    return 0;
}

void print_regs(struct virtual_machine *vm)
{
    struct kvm_regs regs;
    int i;
    ioctl(vm->vcpufd, KVM_GET_REGS, &regs);
    for (i = 0; i < 32; i++) {
        if (i > 0 && i % 4 == 0) {
            printf("\n");
        }
        printf("R%2d: %ld\t", i, regs.gpr[i]);
    }
    printf("\n-------------------\n");
}

int run(struct virtual_machine *vm)
{
    while (1) {
        print_regs(vm);
        ioctl(vm->vcpufd, KVM_RUN, NULL);
        print_regs(vm);

        switch (vm->kvmrun->exit_reason) {
            case KVM_EXIT_HLT:
                printf("halt\n");
                break;

            case KVM_EXIT_IO:
                break;

            case KVM_EXIT_FAIL_ENTRY:
                return 15;

            case KVM_EXIT_INTERNAL_ERROR:
                return 16;

            default:
                return 17;
        }
    }
    return 0;
}

int main()
{
    int ret;

    FILE *bin = fopen("code.bin", "r");

    struct virtual_machine guest;
    ret = create_vm(&guest, bin);
    if (ret == 0) {
        printf("VM created successfuly\n");
    }
    else {
        fprintf(stderr, "%s\n", errors[ret]);
        return ret;
    }

    ret = setup_registers(&guest);
    if (ret == 0) {
        printf("Registers set successfuly\n");
    }
    else {
        fprintf(stderr, "%s\n", errors[ret]);
        return ret;
    }

    ret = run(&guest);
    if (ret == 15) {
        fprintf(stderr, "%s %lx\n",
                errors[ret],
                guest.kvmrun->fail_entry.hardware_entry_failure_reason);
    }
    else if (ret == 16) {
        fprintf(stderr, "%s 0x%x\n",
                errors[ret],
                guest.kvmrun->internal.suberror);
    }
    else if (ret == 17) {
        fprintf(stderr, "%s 0x%x\n",
                errors[ret],
                guest.kvmrun->exit_reason);
    }
    else {
        fprintf(stderr, "%s\n", errors[ret]);
    }

    return ret;
}
