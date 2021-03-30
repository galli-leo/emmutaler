#ifndef __CHIPID_H
#define __CHIPID_H

#include <stdint.h>

#define IO_BASE (0x200000000)
#define AOP_BASE_ADDR (IO_BASE + 0x3d200000)
#define AOP_MINIPMGR_BASE_ADDR (AOP_BASE_ADDR + 0xBC000)
#define AOP_AES_BASE_ADDR (AOP_BASE_ADDR + 0xD0000)

#define PMGR_FUSE(off) (*(volatile uint32_t *)(AOP_MINIPMGR_BASE_ADDR + (off)))

#define rCFG_FUSE(n) PMGR_FUSE(4*(n))

#define	rCFG_FUSE0			rCFG_FUSE(0)
#define	rCFG_FUSE1			rCFG_FUSE(1)
#define	rCFG_FUSE2			rCFG_FUSE(2)
#define	rCFG_FUSE3			rCFG_FUSE(3)
#define	rCFG_FUSE4			rCFG_FUSE(4)
#define	rCFG_FUSE5			rCFG_FUSE(5)
#define	rCFG_FUSE9			rCFG_FUSE(9)
#define	rCFG_FUSE10			rCFG_FUSE(10)

#define ECID_BASE (0x300)
#define	rECIDLO				PMGR_FUSE(ECID_BASE)
#define	rECIDHI				PMGR_FUSE(ECID_BASE+4)

// #define rSEP_SECURITY			(*(volatile uint32_t *)(AOP_MINIPMGR_BASE_ADDR + MINIPMGR_FUSE_SEP_SECURITY_OFFSET))

#define rCFG_FUSE_RAW(n) PMGR_FUSE(4*(n) + 0x400)
#define rCFG_FUSE0_RAW			rCFG_FUSE_RAW(0)
#define rCFG_FUSE1_RAW          rCFG_FUSE_RAW(1)
#define rCFG_FUSE2_RAW          rCFG_FUSE_RAW(2)
#define rCFG_FUSE3_RAW          rCFG_FUSE_RAW(3)

#define SEC_BIT_OFF 0xA050C030
#define SEC_BIT_ON  0xA55AC33C

#define sec_set_bit(fuse, on) if (on) { fuse = SEC_BIT_ON; } else { fuse = SEC_BIT_OFF; }
#define sec_get_bit(fuse) (fuse == SEC_BIT_ON)

#define AES_FUSE(off) (*(volatile uint32_t *)(AOP_AES_BASE_ADDR + (off)))

#define rLO_BOARD AES_FUSE(0x20)
#define rHI_BOARD rCFG_FUSE4

#define MASK(size) ((uint64_t)(1 << (size)) - 1)

#define BITFIELD(name, fuse, lo, hi) \
    static inline uint32_t get_ ## name() { return (fuse >> lo) & (MASK(hi - lo)); } \
    static inline void set_##name(uint32_t value) { fuse = (fuse & (~(MASK(hi - lo) << lo))) | ((value & (MASK(hi - lo))) << lo); }

#define SEC_BITFIELD(name, fuse) \
    static inline uint32_t get_##name() { return sec_get_bit(fuse); } \
    static inline void set_##name(uint32_t value) { sec_set_bit(fuse, value); }

#define COMB_BITFIELD(name, bf_lo, bf_hi, mid) \
    static inline uint64_t get_ ## name() { return ((uint64_t) get_##bf_lo() & MASK(mid)) | ((uint64_t) get_##bf_hi() << mid); } \
    static inline void set_##name(uint64_t value) { set_##bf_lo(value & MASK(mid)); set_##bf_hi((uint64_t)(value >> mid)); }

BITFIELD(security_epoch, rCFG_FUSE4, 5, 12)

// board_id
BITFIELD(lo_board_id, rLO_BOARD, 0, 5)
BITFIELD(hi_board_id, rHI_BOARD, 0, 3)
COMB_BITFIELD(board_id, lo_board_id, hi_board_id, 5)

// security_domain
SEC_BITFIELD(lo_sec_domain, rCFG_FUSE2)
SEC_BITFIELD(hi_sec_domain, rCFG_FUSE3)
COMB_BITFIELD(sec_domain, lo_sec_domain, hi_sec_domain, 2)

// ecid
BITFIELD(lo_ecid, rECIDLO, 0, 31)
BITFIELD(hi_ecid, rECIDHI, 0, 31)
COMB_BITFIELD(ecid, lo_ecid, hi_ecid, 32)

// raw_production_mode
SEC_BITFIELD(raw_prod_mode, rCFG_FUSE0_RAW)
// current_production_mode
SEC_BITFIELD(curr_prod_mode, rCFG_FUSE0)

// secure_mode
SEC_BITFIELD(secure_mode, rCFG_FUSE1_RAW)

// unknown fuses, that have to be set, otherwise image fails to load!
SEC_BITFIELD(uk_fuse, rCFG_FUSE2_RAW)
SEC_BITFIELD(uk_fuse2, rCFG_FUSE3_RAW)

#endif /* __CHIPID_H */
