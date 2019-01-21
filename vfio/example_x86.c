#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <linux/vfio.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>


int main(void)
{
    int container, group, device, i;
    struct vfio_group_status group_status =
        { .argsz = sizeof(group_status) };
    struct vfio_iommu_type1_info iommu_info =
        { .argsz = sizeof(iommu_info) };
    struct vfio_iommu_type1_dma_map dma_map =
        { .argsz = sizeof(dma_map) };
    struct vfio_device_info device_info = { .argsz = sizeof(device_info) };

    container = open("/dev/vfio/vfio", O_RDWR);

    if (ioctl(container, VFIO_GET_API_VERSION) != VFIO_API_VERSION) {
        return 1;
    }

    if (!ioctl(container, VFIO_CHECK_EXTENSION, VFIO_TYPE1_IOMMU)) {
        return 2;
    }

    group = open("/dev/vfio/2", O_RDWR);

    ioctl(group, VFIO_GROUP_GET_STATUS, &group_status);

    if (!(group_status.flags & VFIO_GROUP_FLAGS_VIABLE)) {
        return 3;
    }

    ioctl(group, VFIO_GROUP_SET_CONTAINER, &container);

    ioctl(container, VFIO_SET_IOMMU, VFIO_TYPE1_IOMMU);

    ioctl(container, VFIO_IOMMU_GET_INFO, &iommu_info);

    dma_map.size = 1024 * 1024;
    dma_map.iova = 0;
    dma_map.flags = VFIO_DMA_MAP_FLAG_READ | VFIO_DMA_MAP_FLAG_WRITE;

    ioctl(container, VFIO_IOMMU_MAP_DMA, &dma_map);

    device = ioctl(group, VFIO_GROUP_GET_DEVICE_FD, "0000:00:14.0");

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

    return 0;
}
