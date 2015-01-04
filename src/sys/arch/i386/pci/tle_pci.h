/*
 * Copyright (c) 1995, 1996 Christopher G. Demetriou.  All rights reserved.
 * Copyright (c) 1994 Charles Hannum.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. All advertising materials mentioning features or use of this software
 *    must display the following acknowledgement:
 *  This product includes software developed by Charles Hannum.
 * 4. The name of the author may not be used to endorse or promote products
 *    derived from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 * IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 * 
 *  $Id: tle_pci.h,v 0.1 2014/05/29 00:13:00 StupidTortoise Exp $ */
 */

#ifndef _TLE_PCI_H_
#define _TLE_PCI_H_

/*
 * Standardized PCI configuration information
 *
 * XXX This is not complete.
 */

/*
 * Device identification register; contains a vendor ID and a device ID.
 */

typedef u_int16_t pci_vendor_id_t;
typedef u_int16_t pci_product_id_t;

#define PCI_VENDOR_SHIFT            0
#define PCI_VENDOR_MASK             0xffff
#define PCI_VENDOR(id) \
        (((id) >> PCI_VENDOR_SHIFT) & PCI_VENDOR_MASK)

#define PCI_PRODUCT_SHIFT           16
#define PCI_PRODUCT_MASK            0xffff
#define PCI_PRODUCT(id) \
        (((id) >> PCI_PRODUCT_SHIFT) & PCI_PRODUCT_MASK)

/*
 * PCI Class and Revision Register; defines type and revision of device.
 */

typedef u_int8_t pci_class_t;
typedef u_int8_t pci_subclass_t;
typedef u_int8_t pci_interface_t;
typedef u_int8_t pci_revision_t;

#define PCI_CLASS_SHIFT             24
#define PCI_CLASS_MASK              0xff
#define PCI_CLASS(cr) \
        (((cr) >> PCI_CLASS_SHIFT) & PCI_CLASS_MASK)

#define PCI_SUBCLASS_SHIFT          16
#define PCI_SUBCLASS_MASK           0xff
#define PCI_SUBCLASS(cr) \
        (((cr) >> PCI_SUBCLASS_SHIFT) & PCI_SUBCLASS_MASK)

#define PCI_INTERFACE_SHIFT         8
#define PCI_INTERFACE_MASK          0xff
#define PCI_INTERFACE(cr) \
        (((cr) >> PCI_INTERFACE_SHIFT) & PCI_INTERFACE_MASK)

#define PCI_REVISION_SHIFT          0
#define PCI_REVISION_MASK           0xff
#define PCI_REVISION(cr) \
        (((cr) >> PCI_REVISION_SHIFT) & PCI_REVISION_MASK)

/* base classes */
#define PCI_CLASS_PREHISTORIC           0x00
#define PCI_CLASS_MASS_STORAGE          0x01
#define PCI_CLASS_NETWORK           0x02
#define PCI_CLASS_DISPLAY           0x03
#define PCI_CLASS_MULTIMEDIA            0x04
#define PCI_CLASS_MEMORY            0x05
#define PCI_CLASS_BRIDGE            0x06
#define PCI_CLASS_UNDEFINED         0xff

/* 0x00 prehistoric subclasses */
#define PCI_SUBCLASS_PREHISTORIC_MISC       0x00
#define PCI_SUBCLASS_PREHISTORIC_VGA        0x01

/* 0x01 mass storage subclasses */
#define PCI_SUBCLASS_MASS_STORAGE_SCSI      0x00
#define PCI_SUBCLASS_MASS_STORAGE_IDE       0x01
#define PCI_SUBCLASS_MASS_STORAGE_FLOPPY    0x02
#define PCI_SUBCLASS_MASS_STORAGE_IPI       0x03
#define PCI_SUBCLASS_MASS_STORAGE_MISC      0x80

/* 0x02 network subclasses */
#define PCI_SUBCLASS_NETWORK_ETHERNET       0x00
#define PCI_SUBCLASS_NETWORK_TOKENRING      0x01
#define PCI_SUBCLASS_NETWORK_FDDI       0x02
#define PCI_SUBCLASS_NETWORK_MISC       0x80

/* 0x03 display subclasses */
#define PCI_SUBCLASS_DISPLAY_VGA        0x00
#define PCI_SUBCLASS_DISPLAY_XGA        0x01
#define PCI_SUBCLASS_DISPLAY_MISC       0x80

/* 0x04 multimedia subclasses */
#define PCI_SUBCLASS_MULTIMEDIA_VIDEO       0x00
#define PCI_SUBCLASS_MULTIMEDIA_AUDIO       0x01
#define PCI_SUBCLASS_MULTIMEDIA_MISC        0x80

/* 0x05 memory subclasses */
#define PCI_SUBCLASS_MEMORY_RAM         0x00
#define PCI_SUBCLASS_MEMORY_FLASH       0x01
#define PCI_SUBCLASS_MEMORY_MISC        0x80

/* 0x06 bridge subclasses */
#define PCI_SUBCLASS_BRIDGE_HOST        0x00
#define PCI_SUBCLASS_BRIDGE_ISA         0x01
#define PCI_SUBCLASS_BRIDGE_EISA        0x02
#define PCI_SUBCLASS_BRIDGE_MC          0x03
#define PCI_SUBCLASS_BRIDGE_PCI         0x04
#define PCI_SUBCLASS_BRIDGE_PCMCIA      0x05
#define PCI_SUBCLASS_BRIDGE_MISC        0x80

/*
 * PCI BIST/Header Type/Latency Timer/Cache Line Size Register.
 */
#define PCI_BHLC_REG            0x0c

#define PCI_BIST_SHIFT              24
#define PCI_BIST_MASK               0xff
#define PCI_BIST(bhlcr) \
        (((bhlcr) >> PCI_BIST_SHIFT) & PCI_BIST_MASK)

#define PCI_HDRTYPE_SHIFT           24
#define PCI_HDRTYPE_MASK            0xff
#define PCI_HDRTYPE(bhlcr) \
        (((bhlcr) >> PCI_HDRTYPE_SHIFT) & PCI_HDRTYPE_MASK)

#define PCI_HDRTYPE_MULTIFN(bhlcr) \
        ((PCI_HDRTYPE(bhlcr) & 0x80) != 0)

#define PCI_LATTIMER_SHIFT          24
#define PCI_LATTIMER_MASK           0xff
#define PCI_LATTIMER(bhlcr) \
        (((bhlcr) >> PCI_LATTIMER_SHIFT) & PCI_LATTIMER_MASK)

#define PCI_CACHELINE_SHIFT         24
#define PCI_CACHELINE_MASK          0xff
#define PCI_CACHELINE(bhlcr) \
        (((bhlcr) >> PCI_CACHELINE_SHIFT) & PCI_CACHELINE_MASK)

/*
 * Mapping registers
 */
#define PCI_MAPREG_START        0x10
#define PCI_MAPREG_END          0x28

#define PCI_MAPREG_TYPE(mr)                     \
        ((mr) & PCI_MAPREG_TYPE_MASK)
#define PCI_MAPREG_TYPE_MASK            0x00000001

#define PCI_MAPREG_TYPE_MEM         0x00000000
#define PCI_MAPREG_TYPE_IO          0x00000001

#define PCI_MAPREG_MEM_TYPE(mr)                     \
        ((mr) & PCI_MAPREG_MEM_TYPE_MASK)
#define PCI_MAPREG_MEM_TYPE_MASK        0x00000006

#define PCI_MAPREG_MEM_TYPE_32BIT       0x00000000
#define PCI_MAPREG_MEM_TYPE_32BIT_1M        0x00000002
#define PCI_MAPREG_MEM_TYPE_64BIT       0x00000004

#define PCI_MAPREG_MEM_CACHEABLE(mr)                    \
        (((mr) & PCI_MAPREG_MEM_CACHEABLE_MASK) != 0)
#define PCI_MAPREG_MEM_CACHEABLE_MASK       0x00000008

#define PCI_MAPREG_MEM_ADDR(mr)                     \
        ((mr) & PCI_MAPREG_MEM_ADDR_MASK)
#define PCI_MAPREG_MEM_ADDR_MASK        0xfffffff0

#define PCI_MAPREG_IO_ADDR(mr)                      \
        ((mr) & PCI_MAPREG_IO_ADDR_MASK)
#define PCI_MAPREG_IO_ADDR_MASK         0xfffffffe

/*
 * Interrupt Configuration Register; contains interrupt pin and line.
 */
#define PCI_INTERRUPT_REG       0x3c

#define PCI_INTERRUPT_PIN_SHIFT         8
#define PCI_INTERRUPT_PIN_MASK          0xff
#define PCI_INTERRUPT_PIN(icr) \
        (((icr) >> PCI_INTERRUPT_PIN_SHIFT) & PCI_INTERRUPT_PIN_MASK)

#define PCI_INTERRUPT_LINE_SHIFT        0
#define PCI_INTERRUPT_LINE_MASK         0xff
#define PCI_INTERRUPT_LINE(icr) \
        (((icr) >> PCI_INTERRUPT_LINE_SHIFT) & PCI_INTERRUPT_LINE_MASK)

#define PCI_INTERRUPT_PIN_NONE          0x00
#define PCI_INTERRUPT_PIN_A         0x01
#define PCI_INTERRUPT_PIN_B         0x02
#define PCI_INTERRUPT_PIN_C         0x03
#define PCI_INTERRUPT_PIN_D         0x04

/*
 * List of known PCI vendors
 */
#define PCI_VENDOR_AMD  0x1022      /* AMD */

/* AMD products */
#define PCI_PRODUCT_AMD_PCNET_PCI   0x2000      /* PCnet-PCI Ethernet */

/* =========================== add from other head file ============================== */

#define PCNET_PCI_RDP   0x10
#define PCNET_PCI_RAP   0x12
#define ETHER_ADDR_LEN  6

/*
 * PCI constants.
 * XXX These should be in a common file!
 */
#define PCI_CBIO    0x10        /* Configuration Base IO Address */
#define PCI_COMMAND_STATUS_REG    0x04
#define PCI_COMMAND_MASTER_ENABLE 0x00000004
#define ICU_LEN     16      /* 32-47 are ISA interrupts */
#define RTF_CLONING 0x100       /* generate new routes on use */

/*
 * Length of interface external name, including terminating '\0'.
 * Note: this is the same size as a generic device's external name.
 */
#define IFNAMSIZ    16

/*
 * Register offsets
 */
#define PPB_REG_BUSINFO     0x18        /* Bus information */

/*
 * I/O addresses (in bus space)
 */
typedef u_long bus_io_addr_t;
typedef u_long bus_io_size_t;

/*
 * Access methods for bus resources, I/O space, and memory space.
 */
typedef void *bus_chipset_tag_t;
typedef u_long bus_io_handle_t;

/*
 * Types provided to machine-independent PCI code
 */
typedef void *pci_chipset_tag_t;
typedef int pci_intr_handle_t;

#define bus_io_map(t, port, size, iohp)  ((void) t, *iohp = port, 0)
#define bus_io_read_1(t, h, o)           ((void) t, inb((h) + (o)))
#define bus_io_read_2(t, h, o)           ((void) t, inw((h) + (o)))
#define bus_io_write_2(t, h, o, v)       ((void) t, outw((h) + (o), (v)))

/*
 * Macros to extract the contents of the "Bus Info" register.
 */
#define PPB_BUSINFO_SECONDARY(bir)   ((bir >>  8) & 0xff)

#define DELAY(x)    delay(x)
#define PGSHIFT     12      /* LOG2(NBPG) */
#define i386_btop(x)        ((unsigned)(x) >> PGSHIFT)
#define PG_FRAME    0xfffff000  /* page frame mask */
typedef int pt_entry_t;
extern pt_entry_t   PTmap[];
/*
 * virtual address to page table entry and
 * to physical address. Likewise for alternate address space.
 * Note: these work recursively, thus vtopte of a pte will give
 * the corresponding pde that in turn maps it.
 */
#define vtopte(va)  (PTmap + i386_btop(va))
#define vtophys(va) ((*vtopte(va) & PG_FRAME) | ((unsigned)(va) & ~PG_FRAME))

#endif /* _DEV_PCI_PCIREG_H_ */

