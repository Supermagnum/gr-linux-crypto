# DMR Tier 1 Adaptation Analysis: QRadioLink

## Executive Summary

**Finding**: QRadioLink provides a complete DMR TX/RX implementation for Tier 2/3, but requires significant modifications for Tier 1 compatibility.

**Recommendation**: Adaptation is **feasible** but requires substantial changes to remove TDMA/slot logic and simplify to FDMA operation.

## Current QRadioLink Architecture

### Key Components

1. **Modulation/Demodulation** (`gr_mod_dmr.cpp/h`, `gr_demod_dmr.cpp/h`)
   - 4FSK modulation: constellation [-1.5, -0.5, 0.5, 1.5]
   - Symbol rate: 4800 symbols/sec (24 kHz / 5 samples per symbol)
   - Frequency modulator/demodulator
   - **REUSABLE**: These blocks can be used as-is for Tier 1

2. **Frame Structure** (`dmrframe.cpp/h`)
   - Frame length: 33 bytes (264 bits)
   - Includes CACH (Common Announcement Channel): 3 bytes
   - Includes slot number information
   - **REQUIRES MODIFICATION**: Remove CACH, simplify frame structure

3. **Timing System** (`dmrtiming.cpp/h`)
   - TDMA slot timing (2 slots per channel)
   - Slot synchronization
   - Time-based transmission scheduling
   - **REQUIRES REMOVAL**: Tier 1 has no slots, continuous transmission

4. **Control Logic** (`dmrcontrol.cpp/h`)
   - Slot selection (slot 0 or slot 1)
   - CACH decoding/encoding
   - Repeater vs DMO mode
   - **REQUIRES MODIFICATION**: Remove slot logic, simplify to single channel

5. **DMO Support** (`gr_dmr_dmo_sink.cpp/h`)
   - Direct Mode Operation (mobile-to-mobile)
   - Still uses TDMA slots
   - **REQUIRES MODIFICATION**: Remove slot handling, use as base for Tier 1

## Tier 1 vs Tier 2/3 Differences

| Feature | Tier 2/3 (QRadioLink) | Tier 1 (Target) |
|---------|----------------------|-----------------|
| **Access Method** | TDMA (2 slots) | FDMA (single channel) |
| **CACH** | Yes (3 bytes) | No |
| **Slot Number** | Yes (0 or 1) | No |
| **Frame Structure** | CACH (24 bits) + Payload (108 bits) + Sync (48 bits) | Sync (48 bits) + Payload (108 bits) |
| **Timing** | Slot-based synchronization | Continuous transmission |
| **Channel Bandwidth** | 12.5 kHz (TDMA) | 6.25 kHz (FDMA) |
| **Frequency** | Licensed bands | 446 MHz (PMR446) |

## Required Modifications

### 1. Frame Structure Simplification

**Current (Tier 2/3)**:
```
[CACH: 24 bits] [Payload: 108 bits] [Sync: 48 bits] = 180 bits total
```

**Target (Tier 1)**:
```
[Sync: 48 bits] [Payload: 108 bits] = 156 bits total
```

**Changes Needed**:
- Remove `_cach_data` from `DMRFrame` class
- Remove CACH encoding/decoding logic
- Remove slot number from frame header
- Simplify frame construction to: Sync + Payload only

### 2. Timing System Removal

**Files to Modify**:
- `dmrtiming.cpp/h`: Remove slot timing logic
- `dmrcontrol.cpp`: Remove slot selection
- `gr_dmr_source.cpp`: Remove slot-based transmission timing

**Changes**:
- Remove `set_slot_times()`, `get_slot_times()` calls
- Remove slot number tracking
- Remove time-based transmission scheduling
- Use simple continuous transmission

### 3. Control Logic Simplification

**Current Logic Flow**:
```
Frame → CACH Decode → Slot Selection → Process Frame
```

**Tier 1 Logic Flow**:
```
Frame → Process Frame (no CACH, no slot)
```

**Changes**:
- Remove `processTimeslot()` function
- Remove `processCACH()` function
- Remove slot number from `DMRFrame`
- Simplify `DMR_MODE` enum (Tier 1 is always simplex)

### 4. Demodulator Adaptation

**Current (`gr_demod_dmr.cpp`)**:
- Detects CACH to determine slot
- Uses slot-based synchronization

**Tier 1 Adaptation**:
- Remove CACH detection
- Use sync pattern only for frame alignment
- Continuous demodulation (no slot switching)

### 5. Modulator Adaptation

**Current (`gr_mod_dmr.cpp`)**:
- Already outputs 4FSK symbols
- Can be used as-is

**Tier 1 Adaptation**:
- No changes needed to modulation blocks
- Remove CACH insertion in frame construction

### 6. Constants Update

**File**: `src/DMR/constants.h`

**Changes**:
- Remove `CACH_LENGTH_BYTES`, `CACH_LENGTH_BITS`, `CACH_LENGTH_SYMBOLS`
- Update `FRAME_LENGTH_BITS` from 264 to 156 (remove CACH)
- Update `FRAME_LENGTH_BYTES` from 33 to 19.5 (round to 20 bytes)
- Remove slot-related constants

## Implementation Plan

### Phase 1: Frame Structure Simplification (High Priority)

1. Modify `DMRFrame` class:
   - Remove `_cach_data` member
   - Remove `getCACH()`, `setCACH()` methods
   - Remove `_slot_no` member
   - Update frame construction to exclude CACH

2. Update `constants.h`:
   - Define Tier 1 frame constants
   - Remove CACH constants

**Estimated Effort**: 2-3 days

### Phase 2: Remove TDMA Logic (High Priority)

1. Modify `dmrtiming.cpp/h`:
   - Remove slot timing functions
   - Simplify to continuous transmission

2. Modify `dmrcontrol.cpp`:
   - Remove slot selection logic
   - Remove CACH processing
   - Simplify to single-channel operation

3. Modify `gr_dmr_source.cpp`:
   - Remove slot-based transmission timing
   - Simplify to continuous frame output

**Estimated Effort**: 3-4 days

### Phase 3: Demodulator Adaptation (Medium Priority)

1. Modify `gr_demod_dmr.cpp`:
   - Remove CACH detection
   - Simplify sync detection
   - Remove slot switching logic

2. Modify `gr_dmr_dmo_sink.cpp`:
   - Remove slot-based frame processing
   - Simplify to continuous frame reception

**Estimated Effort**: 2-3 days

### Phase 4: Integration and Testing (Medium Priority)

1. Create Tier 1 mode flag
2. Add conditional compilation for Tier 1 vs Tier 2/3
3. Test with Tier 1 frame structure
4. Verify 4FSK modulation/demodulation works correctly

**Estimated Effort**: 3-5 days

### Phase 5: Encryption Integration (Low Priority)

1. Integrate `gr-linux-crypto` for encryption
2. Add encryption/decryption blocks to flowgraph
3. Support AES-128/256, ARC4, DES as per DMR spec

**Estimated Effort**: 5-7 days

## Code Reuse Analysis

### Fully Reusable Components (0% modification)

- **4FSK Modulator** (`gr_mod_dmr.cpp`): Constellation, symbol mapping, frequency modulation
- **4FSK Demodulator** (`gr_demod_dmr.cpp`): Quadrature demod, symbol sync, slicing
- **CRC Functions** (`crc32.cpp/h`, `crc9.cpp/h`): CRC calculation
- **FEC/Trellis** (`DMRTrellis.cpp/h`): Error correction
- **AMBE Vocoder Integration**: Voice codec handling

### Partially Reusable Components (30-50% modification)

- **Frame Processing** (`dmrframe.cpp/h`): Remove CACH, keep payload handling
- **Control Logic** (`dmrcontrol.cpp/h`): Remove slot logic, keep frame processing
- **DMO Sink** (`gr_dmr_dmo_sink.cpp/h`): Remove slot sync, keep frame detection

### Not Reusable Components (100% removal)

- **Timing System** (`dmrtiming.cpp/h`): Slot timing completely removed
- **CACH Handling**: All CACH-related code
- **Slot Selection**: Slot number tracking and selection

## Estimated Total Effort

- **Minimum**: 10-15 days (basic Tier 1 functionality)
- **Realistic**: 15-20 days (with testing and integration)
- **With Encryption**: 20-30 days (full feature set)

## Risks and Challenges

1. **Frame Structure Compatibility**: Ensure Tier 1 frames are compatible with existing DMR vocoder (AMBE)
2. **Sync Pattern**: Verify sync patterns work without CACH
3. **Regulatory Compliance**: Tier 1 is license-free, ensure power limits are enforced
4. **Testing**: Need Tier 1 hardware or test vectors for validation
5. **Documentation**: DMR Tier 1 specifications may be less accessible than Tier 2/3

## Alternative Approach: New Implementation

Instead of adapting QRadioLink, create a new simplified Tier 1 implementation:

**Advantages**:
- Cleaner codebase (no legacy TDMA code)
- Smaller footprint
- Easier to maintain
- Faster initial development

**Disadvantages**:
- Lose proven QRadioLink code
- Need to reimplement tested components
- More initial development time

**Recommendation**: If starting fresh, use QRadioLink's 4FSK blocks as reference, but implement Tier 1 from scratch for a cleaner solution.

## Conclusion

Adapting QRadioLink for Tier 1 is **feasible** but requires significant modifications. The core modulation/demodulation blocks are reusable, but the TDMA/slot infrastructure must be removed. 

**Best Approach**: 
1. Fork QRadioLink
2. Create a Tier 1 branch
3. Systematically remove TDMA components
4. Simplify frame structure
5. Test with Tier 1 specifications

The estimated effort is **15-20 days** for a working Tier 1 implementation, with encryption integration adding another 5-7 days.


