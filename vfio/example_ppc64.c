#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <linux/vfio.h>
#include <asm/eeh.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>


int main(void)
{
    int container, group, device, i;
    struct vfio_group_status group_status =
        { .argsz = sizeof(group_status) };
    struct vfio_iommu_spapr_tce_info spapr_iommu_info =
        { .argsz = sizeof(spapr_iommu_info) };
    struct vfio_iommu_type1_dma_map dma_map =
        { .argsz = sizeof(dma_map) };
    struct vfio_device_info device_info = { .argsz = sizeof(device_info) };
    struct vfio_eeh_pe_op pe_op = { .argsz = sizeof(pe_op), .flags = 0 };

    container = open("/dev/vfio/vfio", O_RDWR);

    if (ioctl(container, VFIO_GET_API_VERSION) != VFIO_API_VERSION) {
        return 1;
    }

    if (!ioctl(container, VFIO_CHECK_EXTENSION, VFIO_SPAPR_TCE_IOMMU)) {
        return 2;
    }

    group = open("/dev/vfio/6", O_RDWR);

    ioctl(group, VFIO_GROUP_GET_STATUS, &group_status);

    if (!(group_status.flags & VFIO_GROUP_FLAGS_VIABLE)) {
        return 3;
    }

    ioctl(group, VFIO_GROUP_SET_CONTAINER, &container);

    ioctl(container, VFIO_SET_IOMMU, VFIO_SPAPR_TCE_IOMMU);

    /*
    if (ioctl(container, VFIO_IOMMU_ENABLE)) {
        return 4;
    }
    */

    ioctl(container, VFIO_IOMMU_SPAPR_TCE_GET_INFO, &spapr_iommu_info);

    dma_map.vaddr = mmap(0, 1024 * 1024, PROT_READ | PROT_WRITE,
            MAP_PRIVATE | MAP_ANONYMOUS, 0, 0);
    dma_map.size = 1024 * 1024;
    dma_map.iova = 0;
    dma_map.flags = VFIO_DMA_MAP_FLAG_READ | VFIO_DMA_MAP_FLAG_WRITE;

    ioctl(container, VFIO_IOMMU_MAP_DMA, &dma_map);

    device = ioctl(group, VFIO_GROUP_GET_DEVICE_FD, "0004:02:00.0");

    for (i = 0; i < device_info.num_regions; i++) {
        struct vfio_region_info reg = { .argsz = sizeof(reg) };

        reg.index = i;

        ioctl(device, VFIO_DEVICE_GET_REGION_INFO, &reg);
    }

    for (i = 0; i < device_info.num_irqs; i++) {
        struct vfio_irq_info irq = { .argsz = sizeof(irq) };

        irq.index = i;

        ioctl(device, VFIO_DEVICE_GET_IRQ_INFO, &irq);
    }

    ioctl(device, VFIO_DEVICE_RESET);

    ioctl(container, VFIO_CHECK_EXTENSION, VFIO_EEH);

    pe_op.op = VFIO_EEH_PE_ENABLE;
    ioctl(container, VFIO_EEH_PE_OP, &pe_op);

    pe_op.op = VFIO_EEH_PE_GET_STATE;
    ioctl(container, VFIO_EEH_PE_OP, &pe_op);

    pe_op.op = VFIO_EEH_PE_INJECT_ERR;
    pe_op.err.type = EEH_ERR_TYPE_32;
    pe_op.err.func = EEH_ERR_FUNC_LD_CFG_ADDR;
    pe_op.err.addr = 0ULL;
    pe_op.err.mask = 0ULL;
    ioctl(container, VFIO_EEH_PE_OP, &pe_op);

    ioctl(container, VFIO_EEH_PE_OP, &pe_op);

    pe_op.op = VFIO_EEH_PE_UNFREEZE_IO;
    ioctl(container, VFIO_EEH_PE_OP, &pe_op);

    pe_op.op = VFIO_EEH_PE_RESET_HOT;
    ioctl(container, VFIO_EEH_PE_OP, &pe_op);

    pe_op.op = VFIO_EEH_PE_RESET_DEACTIVATE;
    ioctl(container, VFIO_EEH_PE_OP, &pe_op);

    pe_op.op = VFIO_EEH_PE_CONFIGURE;
    ioctl(container, VFIO_EEH_PE_OP, &pe_op);

    return 0;
}
