using System;
using System.Numerics;
using System.Security.Cryptography;

namespace XTS.NET;

public static class XTS
{
    public static void EncryptXts(this SymmetricAlgorithm alg, byte[] buffer, ReadOnlySpan<byte> key, BigInteger sectorNum, int sectorSize)
    {
        SetupRawCipher(alg);

        // Set K1 and create encryptor
        ICryptoTransform encryptor = alg.CreateEncryptor(key[..(key.Length / 2)].ToArray(), null);

        int nSectors = (buffer.Length - 1) / sectorSize + 1;

        int currentSectorSize = sectorSize;
        // This for apply on each sectors
        for (int i = 0; i < nSectors; i += 1)
        {
            // Last sector is likely shorter
            if (i == nSectors - 1)
            {
                currentSectorSize = (buffer.Length - 1) % sectorSize + 1;
            }

            // Encrypt the tweak
            byte[] tweak = EncryptTweak(alg, key, sectorNum);

            // Process the sector
            ProcessXtsSector(encryptor, buffer, i * sectorSize, currentSectorSize, tweak, false);

            // We advance the counter for the next sector
            sectorNum += 1;
        }
    }

    public static void DecryptXts(this SymmetricAlgorithm alg, byte[] buffer, ReadOnlySpan<byte> key, BigInteger sectorNum, int sectorSize)
    {
        SetupRawCipher(alg);

        // Set K1 and create decryptor
        ICryptoTransform encryptor = alg.CreateDecryptor(key[..(key.Length / 2)].ToArray(), null);

        int nSectors = (buffer.Length - 1) / sectorSize + 1;

        int currentSectorSize = sectorSize;
        // This for apply on each sectors
        for (int i = 0; i < nSectors; i += 1)
        {
            // Last sector is likely shorter
            if (i == nSectors - 1)
            {
                currentSectorSize = (buffer.Length - 1) % sectorSize + 1;
            }

            // Encrypt the tweak
            byte[] tweak = EncryptTweak(alg, key, sectorNum);

            // Process the sector
            ProcessXtsSector(encryptor, buffer, i * sectorSize, currentSectorSize, tweak, true);

            // We advance the counter for the next sector
            sectorNum += 1;
        }
    }

    public static void EncryptXtsSector(this SymmetricAlgorithm alg, byte[] buffer, ReadOnlySpan<byte> key, BigInteger sectorNum)
    {
        SetupRawCipher(alg);

        // Set K1 and create encryptor
        ICryptoTransform encryptor = alg.CreateEncryptor(key[..(key.Length / 2)].ToArray(), null);

        // Encrypt the tweak
        byte[] tweak = EncryptTweak(alg, key, sectorNum);

        // Encrypt Sector
        ProcessXtsSector(encryptor, buffer, 0, buffer.Length, tweak, false);
    }

    public static void DecryptXtsSector(this SymmetricAlgorithm alg, byte[] buffer, ReadOnlySpan<byte> key, BigInteger sectorNum)
    {
        SetupRawCipher(alg);

        // Set K1 and create decryptor
        ICryptoTransform decryptor = alg.CreateDecryptor(key[..(key.Length / 2)].ToArray(), null);

        // Encrypt the tweak
        byte[] tweak = EncryptTweak(alg, key, sectorNum);

        // Decrypt Sector
        ProcessXtsSector(decryptor, buffer, 0, buffer.Length, tweak, true);
    }

    private static void ProcessXtsSector(ICryptoTransform alg, byte[] buffer, int bufferOffset, int bufferLength, Span<byte> tweak, bool decrypt)
    {
        int blockSize = alg.InputBlockSize;
        int nFullBlocks = bufferLength / blockSize;

        if (bufferLength < blockSize)
        {
            throw new ArgumentException("You cannot encrypt less then a block in a sector using XTS");
        }

        for (int j = 0; j < nFullBlocks - 1; j += 1)
        {
            int blockStart = bufferOffset + j * blockSize;
            TransformBlock(alg, buffer, blockStart, tweak);

            // Multiply tweak by two for next block
            GaloisMultiplyByTwo(tweak);
        }

        // If we decrypt and we need to do ciphertext stealing, we need to skip a GF multiplication here and roll back after
        int remainingBytes = bufferLength - nFullBlocks * blockSize;
        bool needsCiphertextStealing = remainingBytes > 0;

        if (decrypt && needsCiphertextStealing)
        {
            // We backup the tweak, re-multiply it and restore it after
            byte[] oldTweak = tweak.ToArray();
            GaloisMultiplyByTwo(tweak);

            int blockStart = bufferOffset + (nFullBlocks - 1) * blockSize;
            TransformBlock(alg, buffer, blockStart, tweak);

            tweak = oldTweak;
        }
        else
        {
            int blockStart = bufferOffset + (nFullBlocks - 1) * blockSize;
            TransformBlock(alg, buffer, blockStart, tweak);

            if (needsCiphertextStealing)
            {
                // We will need another decryption after this
                GaloisMultiplyByTwo(tweak);
            }
        }

        if (needsCiphertextStealing)
        {
            // We need to do ciphertext stealing since the sector size does not align with the blocksize
            int previousBlockStart = bufferOffset + (nFullBlocks - 1) * blockSize;
            int currentBlockStart = previousBlockStart + blockSize;

            Span<byte> bufferSpan = buffer.AsSpan();
            Span<byte> previousBlockSpan = bufferSpan[previousBlockStart..currentBlockStart];
            Span<byte> currentBlockSpan = bufferSpan[currentBlockStart..(bufferOffset + bufferLength)];

            // Buffer last bytes
            byte[] remainingBytesArray = currentBlockSpan.ToArray();

            // We copy part of the previous ciphertext at the end
            previousBlockSpan[..remainingBytes].CopyTo(currentBlockSpan);

            // We compute the last block on the previous block
            // We only need to copy the start of the last block, as the end of the previous block is already there
            remainingBytesArray.AsSpan().CopyTo(previousBlockSpan);

            TransformBlock(alg, buffer, previousBlockStart, tweak);
        }
    }

    private static byte[] EncryptTweak(SymmetricAlgorithm alg, ReadOnlySpan<byte> key, BigInteger sectorNum)
    {
        int blockSize = alg.BlockSize / 8;

        // Set K2 to create tweak encryptor
        ICryptoTransform tweaker = alg.CreateEncryptor(key[(key.Length / 2)..].ToArray(), null);

        // Convert sector number to little endian block
        byte[] tweak = sectorNum.ToByteArray(isUnsigned: true, isBigEndian: false);
        Array.Resize(ref tweak, blockSize);

        // Encrypt tweak
        tweaker.TransformBlock(tweak, 0, blockSize, tweak, 0);

        return tweak;
    }

    private static void SetupRawCipher(SymmetricAlgorithm alg)
    {
        // Setup for raw cipher, without mode or padding
        alg.Mode = CipherMode.ECB;
        alg.Padding = PaddingMode.None;
    }

    private static void TransformBlock(ICryptoTransform alg, byte[] buffer, int bufferOffset, ReadOnlySpan<byte> tweak)
    {
        // Get block size from the transform
        int blockSize = alg.InputBlockSize;

        // Cast as span for easier manipulation
        Span<byte> outputSpan = buffer.AsSpan()[bufferOffset..(bufferOffset + blockSize)];

        // XEX part
        XorBlocksInPlace(tweak, outputSpan);
        alg.TransformBlock(buffer, bufferOffset, blockSize, buffer, bufferOffset);
        XorBlocksInPlace(tweak, outputSpan);
    }

    private static void XorBlocksInPlace(ReadOnlySpan<byte> input, Span<byte> output)
    {
        for (int i = 0; i < output.Length; i++)
        {
            output[i] ^= input[i];
        }
    }

    private static void GaloisMultiplyByTwo(Span<byte> tweak)
    {
        bool carry = false;
        for (int i = 0; i < tweak.Length; i++)
        {
            // Save carry from previous byte
            byte oldCarry = (byte)(carry ? 1 : 0);

            // Check if there is a carry for this shift
            carry = (tweak[i] & 0x80) > 0;

            // Shift left
            tweak[i] <<= 1;

            // Carry over bit from last carry
            tweak[i] |= oldCarry;
        }

        if (carry)
        {
            // Derived from polynomial x^128 + x^7 + x^2 + x + 1
            tweak[0] ^= 135;
        }
    }
}
