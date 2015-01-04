/*
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
 *  $Id: tle_pci.c,v 0.1 2014/05/29 00:13:00 StupidTortoise Exp $
 */

/*
 * PCI autoconfiguration support
 */

#include "bpfilter.h"

#include <sys/types.h>
#include <sys/param.h>
#include <sys/systm.h>
#include <sys/mbuf.h>
#include <sys/syslog.h>
#include <sys/socket.h>
#include <sys/device.h>
#include <sys/malloc.h>
#include <sys/ioctl.h>
#include <sys/errno.h>
#include <machine/pio.h>

#if defined(i386) && !defined(NEWCONFIG)
#include <i386/isa/isa_device.h>
#endif

#include <net/if.h>
#include <net/if_dl.h>
#include <net/if_types.h>
#include <net/netisr.h>

#ifdef INET
#include <netinet/in.h>
#include <netinet/in_systm.h>
#include <netinet/in_var.h>
#include <netinet/ip.h>
#include <netinet/if_ether.h>
#endif

#ifdef NS
#include <netns/ns.h>
#include <netns/ns_if.h>
#endif

#if defined(CCITT) && defined(LLC)
#include <sys/socketvar.h>
#include <netccitt/x25.h>
#include <netccitt/pk.h>
#include <netccitt/pk_var.h>
#include <netccitt/pk_extern.h>
#endif

#if NBPFILTER > 0
#include <net/bpf.h>
#include <net/bpfdesc.h>
#endif

#include <i386/pci/pcivar.h>
#include <i386/pci/tle_pci.h>
#include <i386/pci/am7990reg.h>
#include <i386/pci/am7990var.h>

/*
 * Ethernet software status per interface.
 *
 * Each interface is referenced by a network interface structure,
 * arpcom.ac_if, which the routing code uses to locate the interface.
 * This structure contains the output queue for the interface, its address, ...
 */
struct tle_softc {
    struct  am7990_softc sc_am7990; /* glue to MI code */
    struct intrhand sc_ih;          /* interrupt info */
    bus_chipset_tag_t sc_bc;        /* chipset cookie */
    bus_io_handle_t   sc_ioh;       /* bus i/o handle */
    int sc_rap, sc_rdp;             /* offsets to LANCE registers */
};

hide void tle_pci_wrcsr __P((struct am7990_softc *, u_int16_t, u_int16_t));
hide u_int16_t tle_pci_rdcsr __P((struct am7990_softc *, u_int16_t));
int tle_pci_probe __P((struct device *, struct cfdata *, void *));
void tle_pci_attach __P((struct device *, struct device *, void *));

/* tle driver define */
struct cfdriver tlecd = {
    NULL, "tle", tle_pci_probe, tle_pci_attach, DV_IFNET, sizeof(struct tle_softc)
};

/* ======================= from am7990.c ========================= */
#ifdef LEDEBUG
void am7990_recv_print __P((struct am7990_softc *, int));
void am7990_xmit_print __P((struct am7990_softc *, int));
#endif

integrate void am7990_rint __P((struct am7990_softc *));
integrate void am7990_tint __P((struct am7990_softc *));
integrate int am7990_put __P((struct am7990_softc *, int, struct mbuf *));
integrate struct mbuf *am7990_get __P((struct am7990_softc *, int, int));
integrate void am7990_read __P((struct am7990_softc *, int, int));
hide void am7990_shutdown __P((void *));

static struct am7990_softc *static_am_softc;

#ifndef ETHER_CMP
#define ETHER_CMP(a, b) bcmp((a), (b), ETHER_ADDR_LEN)
#endif

/*
 * am7990 configuration driver.  Attachments are provided by
 * machine-dependent driver front-ends.
 */
/* struct cfdriver le_cd = {
    NULL, "le", DV_IFNET
};*/

void
am7990_config(sc)
    struct am7990_softc *sc;
{
    int mem;
    register struct ifnet *ifp = &(sc->sc_arpcom.ac_if);

    /* Make sure the chip is stopped. */
    am7990_stop(sc);

    /* Initialize ifnet structure. */
    ifp->if_name = tlecd.cd_name;
	ifp->if_output = ether_output;
    ifp->if_start = am7990_start;
    ifp->if_ioctl = am7990_ioctl;
    ifp->if_watchdog = am7990_watchdog;
    ifp->if_flags = IFF_BROADCAST | IFF_SIMPLEX | IFF_NOTRAILERS | IFF_MULTICAST;
#ifdef LANCE_REVC_BUG
    ifp->if_flags &= ~IFF_MULTICAST;
#endif

    /* Attach the interface. */
    if_attach(ifp);
    ether_ifattach(ifp);

#if NBPFILTER > 0
    bpfattach(&ifp->if_bpf, ifp, DLT_EN10MB, sizeof(struct ether_header));
#endif

    switch (sc->sc_memsize) {
    case 8192:
        sc->sc_nrbuf = 4;
        sc->sc_ntbuf = 1;
        break;
    case 16384:
        sc->sc_nrbuf = 8;
        sc->sc_ntbuf = 2;
        break;
    case 32768:
        sc->sc_nrbuf = 16;
        sc->sc_ntbuf = 4;
        break;
    case 65536:
        sc->sc_nrbuf = 32;
        sc->sc_ntbuf = 8;
        break;
    default:
        panic("am7990_config: weird memory size");
    }

    printf(": address %s\n", ether_sprintf(sc->sc_arpcom.ac_enaddr));
    printf("%s: %d receive buffers, %d transmit buffers\n", sc->sc_dev.dv_xname, sc->sc_nrbuf, sc->sc_ntbuf);

    mem = 0;
    sc->sc_initaddr = mem;
    mem += sizeof(struct leinit);
    sc->sc_rmdaddr = mem;
    mem += sizeof(struct lermd) * sc->sc_nrbuf;
    sc->sc_tmdaddr = mem;
    mem += sizeof(struct letmd) * sc->sc_ntbuf;
    sc->sc_rbufaddr = mem;
    mem += LEBLEN * sc->sc_nrbuf;
    sc->sc_tbufaddr = mem;
    mem += LEBLEN * sc->sc_ntbuf;
#ifdef notyet
    if (mem > ...)
        panic(...);
#endif
}

void
am7990_reset(sc)
    struct am7990_softc *sc;
{
    int s;

    s = splimp();
    am7990_init(sc);
    splx(s);
}

/*
 * Set up the initialization block and the descriptor rings.
 */
void
am7990_meminit(sc)
    register struct am7990_softc *sc;
{
    u_long a;
    int bix;
    struct leinit init;
    struct lermd rmd;
    struct letmd tmd;
    register struct ifnet *ifp = &(sc->sc_arpcom.ac_if);

#if NBPFILTER > 0
    if (ifp->if_flags & IFF_PROMISC)
        init.init_mode = LE_MODE_NORMAL | LE_MODE_PROM;
    else
#endif
        init.init_mode = LE_MODE_NORMAL;
    init.init_padr[0] = (sc->sc_arpcom.ac_enaddr[1] << 8) | sc->sc_arpcom.ac_enaddr[0];
    init.init_padr[1] = (sc->sc_arpcom.ac_enaddr[3] << 8) | sc->sc_arpcom.ac_enaddr[2];
    init.init_padr[2] = (sc->sc_arpcom.ac_enaddr[5] << 8) | sc->sc_arpcom.ac_enaddr[4];
    am7990_setladrf(&sc->sc_arpcom, init.init_ladrf);

    sc->sc_last_rd = 0;
    sc->sc_first_td = sc->sc_last_td = sc->sc_no_td = 0;

    a = sc->sc_addr + LE_RMDADDR(sc, 0);
    init.init_rdra = a;
    init.init_rlen = (a >> 16) | ((ffs(sc->sc_nrbuf) - 1) << 13);

    a = sc->sc_addr + LE_TMDADDR(sc, 0);
    init.init_tdra = a;
    init.init_tlen = (a >> 16) | ((ffs(sc->sc_ntbuf) - 1) << 13);

    (*sc->sc_copytodesc)(sc, &init, LE_INITADDR(sc), sizeof(init));

    /*
     * Set up receive ring descriptors.
     */
    for (bix = 0; bix < sc->sc_nrbuf; bix++) {
        a = sc->sc_addr + LE_RBUFADDR(sc, bix);
        rmd.rmd0 = a;
        rmd.rmd1_hadr = a >> 16;
        rmd.rmd1_bits = LE_R1_OWN;
        rmd.rmd2 = -LEBLEN | LE_XMD2_ONES;
        rmd.rmd3 = 0;
        (*sc->sc_copytodesc)(sc, &rmd, LE_RMDADDR(sc, bix), sizeof(rmd));
    }

    /*
     * Set up transmit ring descriptors.
     */
    for (bix = 0; bix < sc->sc_ntbuf; bix++) {
        a = sc->sc_addr + LE_TBUFADDR(sc, bix);
        tmd.tmd0 = a;
        tmd.tmd1_hadr = a >> 16;
        tmd.tmd1_bits = 0;
        tmd.tmd2 = 0 | LE_XMD2_ONES;
        tmd.tmd3 = 0;
        (*sc->sc_copytodesc)(sc, &tmd, LE_TMDADDR(sc, bix), sizeof(tmd));
    }
}

void
am7990_stop(sc)
    struct am7990_softc *sc;
{
    (*sc->sc_wrcsr)(sc, LE_CSR0, LE_C0_STOP);
}

/*
 * Initialization of interface; set up initialization block
 * and transmit/receive descriptor rings.
 */
void
am7990_init(sc)
    register struct am7990_softc *sc;
{
    register int timo;
    u_long a;
    register struct ifnet *ifp = &(sc->sc_arpcom.ac_if);

    (*sc->sc_wrcsr)(sc, LE_CSR0, LE_C0_STOP);
    DELAY(100);

    /* Set the correct byte swapping mode, etc. */
    (*sc->sc_wrcsr)(sc, LE_CSR3, sc->sc_conf3);

    /* Set up LANCE init block. */
    am7990_meminit(sc);

    /* Give LANCE the physical address of its init block. */
    a = sc->sc_addr + LE_INITADDR(sc);
    (*sc->sc_wrcsr)(sc, LE_CSR1, a);
    (*sc->sc_wrcsr)(sc, LE_CSR2, a >> 16);

    /* Try to initialize the LANCE. */
    DELAY(100);
    (*sc->sc_wrcsr)(sc, LE_CSR0, LE_C0_INIT);

    /* Wait for initialization to finish. */
    for (timo = 100000; timo; timo--)
        if ((*sc->sc_rdcsr)(sc, LE_CSR0) & LE_C0_IDON)
            break;

    if ((*sc->sc_rdcsr)(sc, LE_CSR0) & LE_C0_IDON) {
        /* Start the LANCE. */
        (*sc->sc_wrcsr)(sc, LE_CSR0, LE_C0_INEA | LE_C0_STRT | LE_C0_IDON);
        ifp->if_flags |= IFF_RUNNING;
        ifp->if_flags &= ~IFF_OACTIVE;
        ifp->if_timer = 0;
        am7990_start(ifp);
    } else
        printf("%s: card failed to initialize\n", sc->sc_dev.dv_xname);
    if (sc->sc_hwinit)
        (*sc->sc_hwinit)(sc);
}

/*
 * Routine to copy from mbuf chain to transmit buffer in
 * network buffer memory.
 */
integrate int
am7990_put(sc, boff, m)
    struct am7990_softc *sc;
    int boff;
    register struct mbuf *m;
{
    register struct mbuf *n;
    register int len, tlen = 0;

    for (; m; m = n) {
        len = m->m_len;
        if (len == 0) {
            MFREE(m, n);
            continue;
        }
        (*sc->sc_copytobuf)(sc, mtod(m, caddr_t), boff, len);
        boff += len;
        tlen += len;
        MFREE(m, n);
    }
    if (tlen < LEMINSIZE) {
        (*sc->sc_zerobuf)(sc, boff, LEMINSIZE - tlen);
        tlen = LEMINSIZE;
    }
    return (tlen);
}

/*
 * Pull data off an interface.
 * Len is length of data, with local net header stripped.
 * We copy the data into mbufs.  When full cluster sized units are present
 * we copy into clusters.
 */
integrate struct mbuf *
am7990_get(sc, boff, totlen)
    struct am7990_softc *sc;
    int boff, totlen;
{
    register struct mbuf *m;
    struct mbuf *top, **mp;
    int len, pad;
    register struct ifnet *ifp = &(sc->sc_arpcom.ac_if);

    MGETHDR(m, M_DONTWAIT, MT_DATA);
    if (m == 0)
        return (0);
    m->m_pkthdr.rcvif = ifp;
    m->m_pkthdr.len = totlen;
    pad = ALIGN(sizeof(struct ether_header)) - sizeof(struct ether_header);
    m->m_data += pad;
    len = MHLEN - pad;
    top = 0;
    mp = &top;

    while (totlen > 0) {
        if (top) {
            MGET(m, M_DONTWAIT, MT_DATA);
            if (m == 0) {
                m_freem(top);
                return 0;
            }
            len = MLEN;
        }
        if (top && totlen >= MINCLSIZE) {
            MCLGET(m, M_DONTWAIT);
            if (m->m_flags & M_EXT)
                len = MCLBYTES;
        }
        m->m_len = len = min(totlen, len);
        (*sc->sc_copyfrombuf)(sc, mtod(m, caddr_t), boff, len);
        boff += len;
        totlen -= len;
        *mp = m;
        mp = &m->m_next;
    }

    return (top);
}

/*
 * Pass a packet to the higher levels.
 */
integrate void
am7990_read(sc, boff, len)
    register struct am7990_softc *sc;
    int boff, len;
{
    struct mbuf *m;
    struct ether_header *eh;
    struct ifnet *ifp = &(sc->sc_arpcom.ac_if);

    if (len <= sizeof(struct ether_header) || len > ETHERMTU + sizeof(struct ether_header)) {
#ifdef LEDEBUG
        printf("%s: invalid packet size %d; dropping\n", sc->sc_dev.dv_xname, len);
#endif
        ifp->if_ierrors++;
        return;
    }

    /* Pull packet off interface. */
    m = am7990_get(sc, boff, len);
    if (m == 0) {
        ifp->if_ierrors++;
        return;
    }

    ifp->if_ipackets++;

    /* We assume that the header fit entirely in one mbuf. */
    eh = mtod(m, struct ether_header *);

#if NBPFILTER > 0
    /*
     * Check if there's a BPF listener on this interface.
     * If so, hand off the raw packet to BPF.
     */
    if (ifp->if_bpf) {
        bpf_mtap(ifp->if_bpf, m);

#ifndef LANCE_REVC_BUG
        /*
         * Note that the interface cannot be in promiscuous mode if
         * there are no BPF listeners.  And if we are in promiscuous
         * mode, we have to check if this packet is really ours.
         */
        if ((ifp->if_flags & IFF_PROMISC) != 0 &&
            (eh->ether_dhost[0] & 1) == 0 && /* !mcast and !bcast */
            ETHER_CMP(eh->ether_dhost, sc->sc_arpcom.ac_enaddr)) {
            m_freem(m);
            return;
        }
#endif
    }
#endif

#ifdef LANCE_REVC_BUG
    /*
     * The old LANCE (Rev. C) chips have a bug which causes
     * garbage to be inserted in front of the received packet.
     * The work-around is to ignore packets with an invalid
     * destination address (garbage will usually not match).
     * Of course, this precludes multicast support...
     */
    if (ETHER_CMP(eh->ether_dhost, sc->sc_arpcom.ac_enaddr) &&
        ETHER_CMP(eh->ether_dhost, etherbroadcastaddr)) {
        m_freem(m);
        return;
    }
#endif

    /* Pass the packet up, with the ether header sort-of removed. */
    m_adj(m, sizeof(struct ether_header));
    ether_input(ifp, eh, m);
}

integrate void
am7990_rint(sc)
    struct am7990_softc *sc;
{
    register int bix;
    int rp;
    struct lermd rmd;
    register struct ifnet *ifp = &(sc->sc_arpcom.ac_if);

    bix = sc->sc_last_rd;

    /* Process all buffers with valid data. */
    for (;;) {
        rp = LE_RMDADDR(sc, bix);
        (*sc->sc_copyfromdesc)(sc, &rmd, rp, sizeof(rmd));

        if (rmd.rmd1_bits & LE_R1_OWN)
            break;

        if (rmd.rmd1_bits & LE_R1_ERR) {
            if (rmd.rmd1_bits & LE_R1_ENP) {
#ifdef LEDEBUG
                if ((rmd.rmd1_bits & LE_R1_OFLO) == 0) {
                    if (rmd.rmd1_bits & LE_R1_FRAM)
                        printf("%s: framing error\n",
                            sc->sc_dev.dv_xname);
                    if (rmd.rmd1_bits & LE_R1_CRC)
                        printf("%s: crc mismatch\n",
                            sc->sc_dev.dv_xname);
                }
#endif
            } else {
                if (rmd.rmd1_bits & LE_R1_OFLO)
                    printf("%s: overflow\n",
                        sc->sc_dev.dv_xname);
            }
            if (rmd.rmd1_bits & LE_R1_BUFF)
                printf("%s: receive buffer error\n",
                    sc->sc_dev.dv_xname);
            ifp->if_ierrors++;
        } else if ((rmd.rmd1_bits & (LE_R1_STP | LE_R1_ENP)) !=
            (LE_R1_STP | LE_R1_ENP)) {
            printf("%s: dropping chained buffer\n",
                sc->sc_dev.dv_xname);
            ifp->if_ierrors++;
        } else {
#ifdef LEDEBUG
            if (sc->sc_debug)
                am7990_recv_print(sc, sc->sc_last_rd);
#endif
            am7990_read(sc, LE_RBUFADDR(sc, bix),
                (int)rmd.rmd3 - 4);
        }

        rmd.rmd1_bits = LE_R1_OWN;
        rmd.rmd2 = -LEBLEN | LE_XMD2_ONES;
        rmd.rmd3 = 0;
        (*sc->sc_copytodesc)(sc, &rmd, rp, sizeof(rmd));

#ifdef LEDEBUG
        if (sc->sc_debug)
            printf("sc->sc_last_rd = %x, rmd: "
                   "ladr %04x, hadr %02x, flags %02x, "
                   "bcnt %04x, mcnt %04x\n",
                sc->sc_last_rd,
                rmd.rmd0, rmd.rmd1_hadr, rmd.rmd1_bits,
                rmd.rmd2, rmd.rmd3);
#endif

        if (++bix == sc->sc_nrbuf)
            bix = 0;
    }

    sc->sc_last_rd = bix;
}

integrate void
am7990_tint(sc)
    register struct am7990_softc *sc;
{
    register int bix;
    struct letmd tmd;
    register struct ifnet *ifp = &(sc->sc_arpcom.ac_if);

    bix = sc->sc_first_td;

    for (;;) {
        if (sc->sc_no_td <= 0)
            break;

#ifdef LEDEBUG
        if (sc->sc_debug)
            printf("trans tmd: "
                   "ladr %04x, hadr %02x, flags %02x, "
                   "bcnt %04x, mcnt %04x\n",
                tmd.tmd0, tmd.tmd1_hadr, tmd.tmd1_bits,
                tmd.tmd2, tmd.tmd3);
#endif

        (*sc->sc_copyfromdesc)(sc, &tmd, LE_TMDADDR(sc, bix),
            sizeof(tmd));

        if (tmd.tmd1_bits & LE_T1_OWN)
            break;

        ifp->if_flags &= ~IFF_OACTIVE;

        if (tmd.tmd1_bits & LE_T1_ERR) {
            if (tmd.tmd3 & LE_T3_BUFF)
                printf("%s: transmit buffer error\n",
                    sc->sc_dev.dv_xname);
            else if (tmd.tmd3 & LE_T3_UFLO)
                printf("%s: underflow\n", sc->sc_dev.dv_xname);
            if (tmd.tmd3 & (LE_T3_BUFF | LE_T3_UFLO)) {
                am7990_reset(sc);
                return;
            }
            if (tmd.tmd3 & LE_T3_LCAR)
                printf("%s: lost carrier\n",
                    sc->sc_dev.dv_xname);
            if (tmd.tmd3 & LE_T3_LCOL)
                ifp->if_collisions++;
            if (tmd.tmd3 & LE_T3_RTRY) {
                printf("%s: excessive collisions, tdr %d\n",
                    sc->sc_dev.dv_xname,
                    tmd.tmd3 & LE_T3_TDR_MASK);
                ifp->if_collisions += 16;
            }
            ifp->if_oerrors++;
        } else {
            if (tmd.tmd1_bits & LE_T1_ONE)
                ifp->if_collisions++;
            else if (tmd.tmd1_bits & LE_T1_MORE)
                /* Real number is unknown. */
                ifp->if_collisions += 2;
            ifp->if_opackets++;
        }

        if (++bix == sc->sc_ntbuf)
            bix = 0;

        --sc->sc_no_td;
    }

    sc->sc_first_td = bix;

    am7990_start(ifp);

    if (sc->sc_no_td == 0)
        ifp->if_timer = 0;
}

/*
 * Controller interrupt.
 */
int
am7990_intr()
{
    register struct am7990_softc *sc = static_am_softc;
    register struct ifnet *ifp = &(sc->sc_arpcom.ac_if);
    register u_int16_t isr;

    isr = (*sc->sc_rdcsr)(sc, LE_CSR0);
#ifdef LEDEBUG
    if (sc->sc_debug)
        printf("%s: am7990_intr entering with isr=%04x\n",
            sc->sc_dev.dv_xname, isr);
#endif
    if ((isr & LE_C0_INTR) == 0)
        return (0);

    (*sc->sc_wrcsr)(sc, LE_CSR0,
        isr & (LE_C0_INEA | LE_C0_BABL | LE_C0_MISS | LE_C0_MERR | LE_C0_RINT | LE_C0_TINT | LE_C0_IDON));
    if (isr & LE_C0_ERR) {
        if (isr & LE_C0_BABL) {
#ifdef LEDEBUG
            printf("%s: babble\n", sc->sc_dev.dv_xname);
#endif
            ifp->if_oerrors++;
        }
#if 0
        if (isr & LE_C0_CERR) {
            printf("%s: collision error\n", sc->sc_dev.dv_xname);
            ifp->if_collisions++;
        }
#endif
        if (isr & LE_C0_MISS) {
#ifdef LEDEBUG
            printf("%s: missed packet\n", sc->sc_dev.dv_xname);
#endif
            ifp->if_ierrors++;
        }
        if (isr & LE_C0_MERR) {
            printf("%s: memory error\n", sc->sc_dev.dv_xname);
            am7990_reset(sc);
            return (1);
        }
    }

    if ((isr & LE_C0_RXON) == 0) {
        printf("%s: receiver disabled\n", sc->sc_dev.dv_xname);
        ifp->if_ierrors++;
        am7990_reset(sc);
        return (1);
    }
    if ((isr & LE_C0_TXON) == 0) {
        printf("%s: transmitter disabled\n", sc->sc_dev.dv_xname);
        ifp->if_oerrors++;
        am7990_reset(sc);
        return (1);
    }

    if (isr & LE_C0_RINT)
        am7990_rint(sc);
    if (isr & LE_C0_TINT)
        am7990_tint(sc);

    return (1);
}

int
am7990_watchdog(unit)
    int unit;
{
    struct am7990_softc *sc = static_am_softc;
    struct ifnet *ifp = &(sc->sc_arpcom.ac_if);

    log(LOG_ERR, "%s: device timeout\n", sc->sc_dev.dv_xname);
    ++ifp->if_oerrors;

    am7990_reset(sc);
}

/*
 * Setup output on interface.
 * Get another datagram to send off of the interface queue, and map it to the
 * interface before starting the output.
 * Called only at splimp or interrupt level.
 */
int
am7990_start(ifp)
    register struct ifnet *ifp;
{
    register struct am7990_softc *sc = static_am_softc;
    register int bix;
    register struct mbuf *m;
    struct letmd tmd;
    int rp;
    int len;

    if ((ifp->if_flags & (IFF_RUNNING | IFF_OACTIVE)) != IFF_RUNNING)
        return;

    bix = sc->sc_last_td;
    for (;;) {
        rp = LE_TMDADDR(sc, bix);
        (*sc->sc_copyfromdesc)(sc, &tmd, rp, sizeof(tmd));

        if (tmd.tmd1_bits & LE_T1_OWN) {
            ifp->if_flags |= IFF_OACTIVE;
            printf("missing buffer, no_td = %d, last_td = %d\n", sc->sc_no_td, sc->sc_last_td);
        }

        IF_DEQUEUE(&ifp->if_snd, m);
        if (m == 0)
            break;

#if NBPFILTER > 0
        /*
         * If BPF is listening on this interface, let it see the packet
         * before we commit it to the wire.
         */
        if (ifp->if_bpf)
            bpf_mtap(ifp->if_bpf, m);
#endif

        /*
         * Copy the mbuf chain into the transmit buffer.
         */
        len = am7990_put(sc, LE_TBUFADDR(sc, bix), m);

#ifdef LEDEBUG
        if (len > ETHERMTU + sizeof(struct ether_header))
            printf("packet length %d\n", len);
#endif

        ifp->if_timer = 5;

        /*
         * Init transmit registers, and set transmit start flag.
         */
        tmd.tmd1_bits = LE_T1_OWN | LE_T1_STP | LE_T1_ENP;
        tmd.tmd2 = -len | LE_XMD2_ONES;
        tmd.tmd3 = 0;

        (*sc->sc_copytodesc)(sc, &tmd, rp, sizeof(tmd));

#ifdef LEDEBUG
        if (sc->sc_debug)
            am7990_xmit_print(sc, sc->sc_last_td);
#endif

        (*sc->sc_wrcsr)(sc, LE_CSR0, LE_C0_INEA | LE_C0_TDMD);

        if (++bix == sc->sc_ntbuf)
            bix = 0;

        if (++sc->sc_no_td == sc->sc_ntbuf) {
            ifp->if_flags |= IFF_OACTIVE;
            break;
        }

    }

    sc->sc_last_td = bix;
}

/*
 * Process an ioctl request.
 */
int
am7990_ioctl(ifp, cmd, data)
    register struct ifnet *ifp;
    int cmd;
    caddr_t data;
{
    register struct am7990_softc *sc = static_am_softc;
    struct ifaddr *ifa = (struct ifaddr *)data;
    struct ifreq *ifr = (struct ifreq *)data;
    int s, error = 0;
    
    s = splimp();
    switch (cmd) {
    case SIOCSIFADDR:
        ifp->if_flags |= IFF_UP;
        switch (ifa->ifa_addr->sa_family) {
#ifdef INET
        case AF_INET:
            am7990_init(sc);
            arp_ifinit(&sc->sc_arpcom, ifa);
            break;
#endif
#ifdef NS
        case AF_NS:
            {
            register struct ns_addr *ina = &IA_SNS(ifa)->sns_addr;

            if (ns_nullhost(*ina))
                ina->x_host = *(union ns_host *)(sc->sc_arpcom.ac_enaddr);
            else
                bcopy(ina->x_host.c_host, sc->sc_arpcom.ac_enaddr, sizeof(sc->sc_arpcom.ac_enaddr));
            /* Set new address. */
            am7990_init(sc);
            break;
            }
#endif
        default:
            am7990_init(sc);
            break;
        }
        break;

#if defined(CCITT) && defined(LLC)
    case SIOCSIFCONF_X25:
        ifp->if_flags |= IFF_UP;
        ifa->ifa_rtrequest = cons_rtrequest; /* XXX */
        error = x25_llcglue(PRC_IFUP, ifa->ifa_addr);
        if (error == 0)
            am7990_init(sc);
        break;
#endif /* CCITT && LLC */

    case SIOCSIFFLAGS:
        if ((ifp->if_flags & IFF_UP) == 0 &&
            (ifp->if_flags & IFF_RUNNING) != 0) {
            /*
             * If interface is marked down and it is running, then
             * stop it.
             */
            am7990_stop(sc);
            ifp->if_flags &= ~IFF_RUNNING;
        } else if ((ifp->if_flags & IFF_UP) != 0 &&
                   (ifp->if_flags & IFF_RUNNING) == 0) {
            /*
             * If interface is marked up and it is stopped, then
             * start it.
             */
            am7990_init(sc);
        } else {
            /*
             * Reset the interface to pick up changes in any other
             * flags that affect hardware registers.
             */
            /*am7990_stop(sc);*/
            am7990_init(sc);
        }
#ifdef LEDEBUG
        if (ifp->if_flags & IFF_DEBUG)
            sc->sc_debug = 1;
        else
            sc->sc_debug = 0;
#endif
        break;

    case SIOCADDMULTI:
    case SIOCDELMULTI:
        error = (cmd == SIOCADDMULTI) ?
            ether_addmulti(ifr, &sc->sc_arpcom) :
            ether_delmulti(ifr, &sc->sc_arpcom);

        if (error == ENETRESET) {
            /*
             * Multicast list has changed; set the hardware filter
             * accordingly.
             */
            am7990_reset(sc);
            error = 0;
        }
        break;

    default:
        error = EINVAL;
        break;
    }

    splx(s);
    return (error);
}

hide void
am7990_shutdown(arg)
    void *arg;
{
    am7990_stop((struct am7990_softc *)arg);
}

#ifdef LEDEBUG
void
am7990_recv_print(sc, no)
    struct am7990_softc *sc;
    int no;
{
    struct lermd rmd;
    u_int16_t len;
    struct ether_header eh;

    (*sc->sc_copyfromdesc)(sc, &rmd, LE_RMDADDR(sc, no), sizeof(rmd));
    len = rmd.rmd3;
    printf("%s: receive buffer %d, len = %d\n", sc->sc_dev.dv_xname, no, len);
    printf("%s: status %04x\n", sc->sc_dev.dv_xname, (*sc->sc_rdcsr)(sc, LE_CSR0));
    printf("%s: ladr %04x, hadr %02x, flags %02x, bcnt %04x, mcnt %04x\n",
        sc->sc_dev.dv_xname,
        rmd.rmd0, rmd.rmd1_hadr, rmd.rmd1_bits, rmd.rmd2, rmd.rmd3);
    if (len >= sizeof(eh)) {
        (*sc->sc_copyfrombuf)(sc, &eh, LE_RBUFADDR(sc, no), sizeof(eh));
        printf("%s: dst %s", sc->sc_dev.dv_xname, ether_sprintf(eh.ether_dhost));
        printf(" src %s type %04x\n", ether_sprintf(eh.ether_shost), ntohs(eh.ether_type));
    }
}

void
am7990_xmit_print(sc, no)
    struct am7990_softc *sc;
    int no;
{
    struct letmd tmd;
    u_int16_t len;
    struct ether_header eh;

    (*sc->sc_copyfromdesc)(sc, &tmd, LE_TMDADDR(sc, no), sizeof(tmd));
    len = -tmd.tmd2;
    printf("%s: transmit buffer %d, len = %d\n", sc->sc_dev.dv_xname, no, len);
    printf("%s: status %04x\n", sc->sc_dev.dv_xname, (*sc->sc_rdcsr)(sc, LE_CSR0));
    printf("%s: ladr %04x, hadr %02x, flags %02x, bcnt %04x, mcnt %04x\n", 
        sc->sc_dev.dv_xname,
        tmd.tmd0, tmd.tmd1_hadr, tmd.tmd1_bits, tmd.tmd2, tmd.tmd3);
    if (len >= sizeof(eh)) {
        (*sc->sc_copyfrombuf)(sc, &eh, LE_TBUFADDR(sc, no), sizeof(eh));
        printf("%s: dst %s", sc->sc_dev.dv_xname, ether_sprintf(eh.ether_dhost));
        printf(" src %s type %04x\n", ether_sprintf(eh.ether_shost), ntohs(eh.ether_type));
    }
}
#endif /* LEDEBUG */

/*
 * Set up the logical address filter.
 */
void
am7990_setladrf(ac, af)
    struct arpcom *ac;
    u_int16_t *af;
{
    struct ifnet *ifp = &ac->ac_if;
    struct ether_multi *enm;
    register u_char *cp, c;
    register u_int32_t crc;
    register int i, len;
    struct ether_multistep step;

    /*
     * Set up multicast address filter by passing all multicast addresses
     * through a crc generator, and then using the high order 6 bits as an
     * index into the 64 bit logical address filter.  The high order bit
     * selects the word, while the rest of the bits select the bit within
     * the word.
     */
    if (ifp->if_flags & IFF_PROMISC)
        goto allmulti;

    af[0] = af[1] = af[2] = af[3] = 0x0000;
    ETHER_FIRST_MULTI(step, ac, enm);
    while (enm != NULL) {
        if (ETHER_CMP(enm->enm_addrlo, enm->enm_addrhi)) {
            /*
             * We must listen to a range of multicast addresses.
             * For now, just accept all multicasts, rather than
             * trying to set only those filter bits needed to match
             * the range.  (At this time, the only use of address
             * ranges is for IP multicast routing, for which the
             * range is big enough to require all bits set.)
             */
            goto allmulti;
        }

        cp = enm->enm_addrlo;
        crc = 0xffffffff;
        for (len = sizeof(enm->enm_addrlo); --len >= 0;) {
            c = *cp++;
            for (i = 8; --i >= 0;) {
                if ((crc & 0x01) ^ (c & 0x01)) {
                    crc >>= 1;
                    crc ^= 0xedb88320;
                } else
                    crc >>= 1;
                c >>= 1;
            }
        }
        /* Just want the 6 most significant bits. */
        crc >>= 26;

        /* Set the corresponding bit in the filter. */
        af[crc >> 4] |= 1 << (crc & 0xf);

        ETHER_NEXT_MULTI(step, enm);
    }
    ifp->if_flags &= ~IFF_ALLMULTI;
    return;

allmulti:
    ifp->if_flags |= IFF_ALLMULTI;
    af[0] = af[1] = af[2] = af[3] = 0xffff;
}


/*
 * Routines for accessing the transmit and receive buffers.
 * The various CPU and adapter configurations supported by this
 * driver require three different access methods for buffers
 * and descriptors:
 *  (1) contig (contiguous data; no padding),
 *  (2) gap2 (two bytes of data followed by two bytes of padding),
 *  (3) gap16 (16 bytes of data followed by 16 bytes of padding).
 */

/*
 * contig: contiguous data with no padding.
 *
 * Buffers may have any alignment.
 */

void
am7990_copytobuf_contig(sc, from, boff, len)
    struct am7990_softc *sc;
    void *from;
    int boff, len;
{
    volatile caddr_t buf = sc->sc_mem;

    /*
     * Just call bcopy() to do the work.
     */
    bcopy(from, buf + boff, len);
}

void
am7990_copyfrombuf_contig(sc, to, boff, len)
    struct am7990_softc *sc;
    void *to;
    int boff, len;
{
    volatile caddr_t buf = sc->sc_mem;

    /*
     * Just call bcopy() to do the work.
     */
    bcopy(buf + boff, to, len);
}

void
am7990_zerobuf_contig(sc, boff, len)
    struct am7990_softc *sc;
    int boff, len;
{
    volatile caddr_t buf = sc->sc_mem;

    /*
     * Just let bzero() do the work
     */
    bzero(buf + boff, len);
}

/* ==================== other function ============================== */
int
pci_io_find(pcitag, reg, iobasep, iosizep)
    pcitag_t pcitag;
    int reg;
    bus_io_addr_t *iobasep;
    bus_io_size_t *iosizep;
{
    pcireg_t addrdata, sizedata;
    int s;

    if (reg < PCI_MAPREG_START || reg >= PCI_MAPREG_END || (reg & 3))
        panic("pci_io_find: bad request");

    /* XXX?
     * Section 6.2.5.1, `Address Maps', tells us that:
     *
     * 1) The builtin software should have already mapped the device in a
     * reasonable way.
     *
     * 2) A device which wants 2^n bytes of memory will hardwire the bottom
     * n bits of the address to 0.  As recommended, we write all 1s and see
     * what we get back.
     */
    addrdata = pci_conf_read(pcitag, reg);

    s = splhigh();
    pci_conf_write(pcitag, reg, 0xffffffff);
    sizedata = pci_conf_read(pcitag, reg);
    pci_conf_write(pcitag, reg, addrdata);
    splx(s);

    if (PCI_MAPREG_TYPE(addrdata) != PCI_MAPREG_TYPE_IO)
        panic("pci_io_find: not an I/O region");

    if (iobasep != NULL)
        *iobasep = PCI_MAPREG_IO_ADDR(addrdata);
    if (iosizep != NULL)
        *iosizep = ~PCI_MAPREG_IO_ADDR(sizedata) + 1;

    return (0);
}

hide void
tle_pci_wrcsr(sc, port, val)
    struct am7990_softc *sc;
    u_int16_t port, val;
{
    struct tle_softc *lesc = (struct tle_softc *)sc;
    bus_chipset_tag_t bc = lesc->sc_bc;
    bus_io_handle_t ioh = lesc->sc_ioh;

    bus_io_write_2(bc, ioh, lesc->sc_rap, port);
    bus_io_write_2(bc, ioh, lesc->sc_rdp, val);
}

hide u_int16_t
tle_pci_rdcsr(sc, port)
    struct am7990_softc *sc;
    u_int16_t port;
{
    struct tle_softc *lesc = (struct tle_softc *)sc;
    bus_chipset_tag_t bc = lesc->sc_bc;
    bus_io_handle_t ioh = lesc->sc_ioh;
    u_int16_t val;

    bus_io_write_2(bc, ioh, lesc->sc_rap, port);
    val = bus_io_read_2(bc, ioh, lesc->sc_rdp);
    return (val);
}

int
pci_intr_map(intrtag, pin, line, ihp)
    pcitag_t intrtag;
    int pin, line;
    pci_intr_handle_t *ihp;
{

    if (pin == 0) {
        /* No IRQ used. */
        goto bad;
    }

    if (pin > 4) {
        printf("pci_intr_map: bad interrupt pin %d\n", pin);
        goto bad;
    }

    /*
     * Section 6.2.4, `Miscellaneous Functions', says that 255 means
     * `unknown' or `no connection' on a PC.  We assume that a device with
     * `no connection' either doesn't have an interrupt (in which case the
     * pin number should be 0, and would have been noticed above), or
     * wasn't configured by the BIOS (in which case we punt, since there's
     * no real way we can know how the interrupt lines are mapped in the
     * hardware).
     *
     * XXX
     * Since IRQ 0 is only used by the clock, and we can't actually be sure
     * that the BIOS did its job, we also recognize that as meaning that
     * the BIOS has not configured the device.
     */
    if (line == 0 || line == 255) {
        printf("pci_intr_map: no mapping for pin %c\n", '@' + pin);
        goto bad;
    } else {
        if (line >= ICU_LEN) {
            printf("pci_intr_map: bad interrupt line %d\n", line);
            goto bad;
        }
        if (line == 2) {
            printf("pci_intr_map: changed line 2 to line 9\n");
            line = 9;
        }
    }

    *ihp = line;
    return 0;

bad:
    *ihp = -1;
    return 1;
}

const char *
pci_intr_string(ih)
    pci_intr_handle_t ih;
{
    static char irqstr[8];      /* 4 + 2 + NULL + sanity */

    if (ih == 0 || ih >= ICU_LEN || ih == 2)
        panic("pci_intr_string: bogus handle 0x%x\n", ih);

    sprintf(irqstr, "irq %d", ih);
    return (irqstr);    
}

/* ===================================================================================== */

int
tle_pci_probe(parent, cf, aux)
    struct device *parent;
    struct cfdata *cf;
    void *aux;
{
    struct pci_attach_args *pa = aux;

    if (PCI_VENDOR(pa->pa_id) != PCI_VENDOR_AMD)
        return (0);

    switch (PCI_PRODUCT(pa->pa_id)) {
    case PCI_PRODUCT_AMD_PCNET_PCI:
        return (1);
    }

    return (0);
}

void
tle_pci_attach(parent, self, aux)
    struct device *parent, *self;
    void *aux;
{
    struct tle_softc *lesc = (void *)self;
    struct am7990_softc *sc = &lesc->sc_am7990;
    struct pci_attach_args *pa = aux;
    pci_intr_handle_t ih;
    bus_io_addr_t iobase;
    bus_io_size_t iosize;
    bus_io_handle_t ioh;
    bus_chipset_tag_t bc = NULL;
    pci_chipset_tag_t pc = 0;
    pcireg_t csr, busdata, intr;
    int i, bus, pin;
    const char *model, *intrstr;

    switch (PCI_PRODUCT(pa->pa_id)) {
    case PCI_PRODUCT_AMD_PCNET_PCI:
        model = "PCnet-PCI Ethernet";
        lesc->sc_rap = PCNET_PCI_RAP;
        lesc->sc_rdp = PCNET_PCI_RDP;
        break;

    default:
        model = "unknown model!";
    }
    printf(": %s\n", model);

    if (pci_io_find(pa->pa_tag, PCI_CBIO, &iobase, &iosize)) {
        printf("%s: can't find I/O base\n", sc->sc_dev.dv_xname);
        return;
    }
    if (bus_io_map(bc, iobase, iosize, &ioh)) {
        printf("%s: can't map I/O space\n", sc->sc_dev.dv_xname);
        return;
    }

    /*
     * Extract the physical MAC address from the ROM.
     */
    for (i = 0; i < sizeof(sc->sc_arpcom.ac_enaddr); i++)
        sc->sc_arpcom.ac_enaddr[i] = bus_io_read_1(bc, ioh, i);

    sc->sc_mem = malloc(16384, M_DEVBUF, M_NOWAIT);
    if (sc->sc_mem == 0) {
        printf("%s: couldn't allocate memory for card\n", sc->sc_dev.dv_xname);
        return;
    }

    lesc->sc_bc = bc;
    lesc->sc_ioh = ioh;
    
    sc->sc_conf3 = 0;
    sc->sc_addr = vtophys(sc->sc_mem);  /* XXX XXX XXX */
    sc->sc_memsize = 16384;

    sc->sc_copytodesc = am7990_copytobuf_contig;
    sc->sc_copyfromdesc = am7990_copyfrombuf_contig;
    sc->sc_copytobuf = am7990_copytobuf_contig;
    sc->sc_copyfrombuf = am7990_copyfrombuf_contig;
    sc->sc_zerobuf = am7990_zerobuf_contig;
    sc->sc_rdcsr = tle_pci_rdcsr;
    sc->sc_wrcsr = tle_pci_wrcsr;
    sc->sc_hwinit = NULL;

    static_am_softc = sc;
    am7990_config(sc);

    /* Enable the card. */
    csr = pci_conf_read(pa->pa_tag, PCI_COMMAND_STATUS_REG);
    pci_conf_write(pa->pa_tag, PCI_COMMAND_STATUS_REG, csr | PCI_COMMAND_MASTER_ENABLE);

    /* Map and establish the interrupt. */
    busdata = pci_conf_read(pa->pa_tag, PPB_REG_BUSINFO);
    bus = PPB_BUSINFO_SECONDARY(busdata);
    if (bus == 0) {
        pa->pa_intrswiz = 0;
        pa->pa_intrtag = pa->pa_tag;
    } else {
        pa->pa_intrswiz = pa->pa_device;
        pa->pa_intrtag = pa->pa_tag;
    }
    
    intr = pci_conf_read(pa->pa_tag, PCI_INTERRUPT_REG);
    pin = PCI_INTERRUPT_PIN(intr);
    if (pin == PCI_INTERRUPT_PIN_NONE) {
        /* no interrupt */
        pa->pa_intrpin = 0;
    } else {
        /*
         * swizzle it based on the number of
         * busses we're behind and our device
         * number.
         */
        pa->pa_intrpin = ((pin + pa->pa_intrswiz - 1) % 4) + 1;
    }
    pa->pa_intrline = PCI_INTERRUPT_LINE(intr);

    if (pci_intr_map(pa->pa_intrtag, pa->pa_intrpin, pa->pa_intrline, &ih)) {
        printf("%s: couldn't map interrupt\n", sc->sc_dev.dv_xname);
        return;
    }
    intrstr = pci_intr_string(ih);
    lesc->sc_ih.ih_fun = am7990_intr;
    lesc->sc_ih.ih_arg = lesc;
    lesc->sc_ih.ih_level = IPL_NET;
    intr_establish(ih, &(lesc->sc_ih));
    printf("%s: interrupting at %s\n", sc->sc_dev.dv_xname, intrstr);
}

