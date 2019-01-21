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

    // set 512MB of memory to this virtual machine
    vm->codemem_len = 512 * 1024 * 1024;

    vm->kvmfd = open("/dev/kvm", O_RDWR | O_CLOEXEC);
    if (vm->kvmfd == -1) {
        printf("cannot open /dev/kvm\n");
        return 1;
    }

    ret = ioctl(vm->kvmfd, KVM_GET_API_VERSION, NULL);
    if (ret == -1) {
        printf("cannot get KVM version\n");
        return 1;
    }
    printf("KVM version %d\n", ret);

    vm->vmfd = ioctl(vm->kvmfd, KVM_CREATE_VM, (unsigned long)0);
    if (ret == -1) {
        printf("failed to create virtual machine\n");
        return 1;
    }

    vm->codemem = mmap(NULL,
                       vm->codemem_len,
                       PROT_READ | PROT_WRITE,
                       MAP_SHARED | MAP_ANONYMOUS,
                       -1, 0);

    if (vm->codemem == NULL) {
        printf("failed to allocate memory for the VM\n");
        return 1;
    }

    fseek(fd, 0, SEEK_END);
    if ((fsize = ftell(fd)) > vm->codemem_len) {
        printf("binary needs more memory\n");
        return 1;
    }
    rewind(fd);

    if (fread(vm->codemem, 1, fsize, fd) != fsize) {
        printf("cannot copy the binary into mmaped memory\n");
        return 1;
    }

    struct kvm_userspace_memory_region region = {
        .slot = 0,
        .guest_phys_addr = 0,
        .memory_size = vm->codemem_len,
        .userspace_addr = (uint64_t)vm->codemem,
    };

    if (ioctl(vm->vmfd, KVM_SET_USER_MEMORY_REGION, &region) == -1) {
        printf("kvm failed to set the user memory region\n");
        return 1;
    }

    vm->vcpufd = ioctl(vm->vmfd, KVM_CREATE_VCPU, (unsigned long)0);
    if (vm->vcpufd == -1) {
        printf("kvm failed to create the VCPU\n");
        return 1;
    }

    mmap_size = ioctl(vm->kvmfd, KVM_GET_VCPU_MMAP_SIZE, NULL);
    if (mmap_size == -1) {
        printf("kvm failed to return the memory mapped for kvm_run struct\n");
        return 1;
    }

    if (mmap_size < sizeof(*vm->kvmrun)) {
        printf("kvm memory doesn't support kvm_run struct\n");
        return 1;
    }

    vm->kvmrun = mmap(NULL,
                       mmap_size,
                       PROT_READ | PROT_WRITE,
                       MAP_SHARED,
                       vm->vcpufd, 0);

    if (vm->kvmrun == NULL) {
        printf("problem to map kvm_run between this emulator and KVM");
        return 1;
    }

    return 0;
}

int setup_registers(struct virtual_machine *vm)
{
    struct kvm_enable_cap cap = {
        .cap = KVM_CAP_PPC_PAPR,
        .flags = 0,
    };

    struct kvm_guest_debug debug = {
       .control = KVM_GUESTDBG_ENABLE | KVM_GUESTDBG_USE_SW_BP,
    };

    if (ioctl(vm->vcpufd, KVM_ENABLE_CAP, &cap) == -1) {
        printf("kvm failed to enabled PAPR capability\n");
        return 1;
    }

    if (ioctl(vm->vcpufd, KVM_SET_GUEST_DEBUG, &debug) == -1) {
        printf("kvm didn't set guest in debug mode\n");
    }

    if (ioctl(vm->vcpufd, KVM_GET_SREGS, &vm->sregs) == -1) {
        printf("kvm failed to return current special registers\n");
        return 1;
    }
    vm->sregs.pvr = 0x004b0201; // power8

    if (ioctl(vm->vcpufd, KVM_SET_SREGS, &vm->sregs) == -1) {
        printf("kvm failed to set special registers\n");
        return 1;
    }

    struct kvm_regs regs = {
        .pc = 0x100,
        .msr = 0x8000000000000008ULL, //64-bit, HV, Big Endian
    };

    if (ioctl(vm->vcpufd, KVM_SET_REGS, &regs) == -1) {
        printf("kvm failed to set registers values\n");
        return 1;
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
        //print_regs(vm);
        ioctl(vm->vcpufd, KVM_RUN, NULL);
        //print_regs(vm);

        switch (vm->kvmrun->exit_reason) {
            case KVM_EXIT_HLT:
                printf("halt\n");
                return 0;

            // handling putchat only
            case KVM_EXIT_PAPR_HCALL:
                putchar(vm->kvmrun->papr_hcall.args[2] >> 56);
                break;

            case KVM_EXIT_IO:
                printf("not handling IO yet\n");
                return 1;

            case KVM_EXIT_FAIL_ENTRY:
                printf("HW Error: %lx\n",
                    vm->kvmrun->fail_entry.hardware_entry_failure_reason);
                return 1;

            case KVM_EXIT_INTERNAL_ERROR:
                printf("internal error: 0x%x\n",
                    vm->kvmrun->internal.suberror);
                return 1;

            case KVM_EXIT_MMIO:
                printf("not handling MMIO yet\n");
                return 1;

            default:
                printf("==> %08x\n", vm->kvmrun->exit_reason);
                return 1;
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

    ret = setup_registers(&guest);
    if (ret == 0) {
        printf("Registers set successfuly\n");
    }

    ret = run(&guest);
    return ret;
}
