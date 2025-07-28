# ECMath Dynamic Memory Allocation Fix Plan

## Problem
ECMath methods called during CA (processMSE) contain dynamic memory allocations causing SW=0x0001

## Methods that need fixing (called from processMSE):
1. `generateRandomScalar` - generates random private key
2. `generatePublicKey` - calls `scalarMultiply` 
3. `performECDH` - calls `scalarMultiply`
4. `scalarMultiply` - contains multiple `new byte[]` allocations

## Quick Fix Strategy
Add class member buffers in ECMath:
```java
// Add these as class members
private byte[] tempX1Full;
private byte[] tempY1Full;
private byte[] tempX2Full;
private byte[] tempY2Full;
private byte[] tempXFull;
private byte[] tempYFull;
private byte[] tempAValue;
private byte[] tempBValue;

// Initialize in constructor
tempX1Full = JCSystem.makeTransientByteArray(RSA_BLOCK_SIZE, JCSystem.CLEAR_ON_DESELECT);
tempY1Full = JCSystem.makeTransientByteArray(RSA_BLOCK_SIZE, JCSystem.CLEAR_ON_DESELECT);
// ... etc
```

Then replace all `new byte[RSA_BLOCK_SIZE]` in these methods with the pre-allocated buffers.

## Affected methods:
- Line 237-238: in `scalarMultiply`
- Line 303-306: in `pointAdd`
- Line 658-659, 672, 680: in `pointDouble`

This is a significant change that requires careful testing.