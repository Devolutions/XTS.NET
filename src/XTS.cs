using System;
using System.Numerics;
using System.Security.Cryptography;

namespace XTS.NET
{
    public static class XTS
    {
        // Derived from polynomial x^128 + x^7 + x^2 + x + 1
        private const byte GF_MOD = 135;

        /// <summary>
        /// Encrypt multiple sectors of data using XTS mode
        /// </summary>
        /// <param name="alg">A SymmetricAlgorithm representing the underlying block cipher. In a regular scenario, you can use Aes.Create() to get this.</param>
        /// <param name="input">The data to encrypt</param>
        /// <param name="key">The key to use. Note that XTS mode uses a key twice the underlying size of the block cipher.</param>
        /// <param name="sectorNum">The sector number, also known as the tweak. This is the equivalent of the IV/Nonce for other modes.</param>
        /// <param name="sectorSize">The size of a sector. This function allows encrypting multiple sector. Use the Sector variants if you don't care about this.</param>
        /// <returns>The encrypted data</returns>
        public static byte[] EncryptXts(this SymmetricAlgorithm alg, ReadOnlySpan<byte> input, ReadOnlySpan<byte> key, BigInteger sectorNum, int sectorSize)
        {
            byte[] buffer = input.ToArray();
            alg.EncryptXtsInPlace(buffer, key, sectorNum, sectorSize);
            return buffer;
        }

        /// <summary>
        /// Decrypt multiple sectors of data using XTS mode
        /// </summary>
        /// <param name="alg">A SymmetricAlgorithm representing the underlying block cipher. In a regular scenario, you can use Aes.Create() to get this.</param>
        /// <param name="input">The data to decrypt</param>
        /// <param name="key">The key to use. Note that XTS mode uses a key twice the underlying size of the block cipher.</param>
        /// <param name="sectorNum">The sector number, also known as the tweak. This is the equivalent of the IV/Nonce for other modes.</param>
        /// <param name="sectorSize">The size of a sector. This function allows decrypting multiple sector. Use the Sector variants if you don't care about this.</param>
        /// <returns>The decrypted data</returns>
        public static byte[] DecryptXts(this SymmetricAlgorithm alg, ReadOnlySpan<byte> input, ReadOnlySpan<byte> key, BigInteger sectorNum, int sectorSize)
        {
            byte[] buffer = input.ToArray();
            alg.DecryptXtsInPlace(buffer, key, sectorNum, sectorSize);
            return buffer;
        }

        /// <summary>
        /// Encrypt data using XTS mode
        /// </summary>
        /// <param name="alg">A SymmetricAlgorithm representing the underlying block cipher. In a regular scenario, you can use Aes.Create() to get this.</param>
        /// <param name="input">The data to encrypt</param>
        /// <param name="key">The key to use. Note that XTS mode uses a key twice the underlying size of the block cipher.</param>
        /// <param name="sectorNum">The sector number, also known as the tweak. This is the equivalent of the IV/Nonce for other modes.</param>
        /// <returns>The encrypted data</returns>
        public static byte[] EncryptXtsSector(this SymmetricAlgorithm alg, ReadOnlySpan<byte> input, ReadOnlySpan<byte> key, BigInteger sectorNum)
        {
            byte[] buffer = input.ToArray();
            alg.EncryptXtsSectorInPlace(buffer, key, sectorNum);
            return buffer;
        }

        /// <summary>
        /// Decrypt data using XTS mode
        /// </summary>
        /// <param name="alg">A SymmetricAlgorithm representing the underlying block cipher. In a regular scenario, you can use Aes.Create() to get this.</param>
        /// <param name="input">The data to decrypt</param>
        /// <param name="key">The key to use. Note that XTS mode uses a key twice the underlying size of the block cipher.</param>
        /// <param name="sectorNum">The sector number, also known as the tweak. This is the equivalent of the IV/Nonce for other modes.</param>
        /// <returns>The decrypted data</returns>
        public static byte[] DecryptXtsSector(this SymmetricAlgorithm alg, ReadOnlySpan<byte> input, ReadOnlySpan<byte> key, BigInteger sectorNum)
        {
            byte[] buffer = input.ToArray();
            alg.DecryptXtsSectorInPlace(buffer, key, sectorNum);
            return buffer;
        }

        /// <summary>
        /// Encrypt multiple sectors of data using XTS mode in place
        /// </summary>
        /// <param name="alg">A SymmetricAlgorithm representing the underlying block cipher. In a regular scenario, you can use Aes.Create() to get this.</param>
        /// <param name="buffer">The data to encrypt, and also the output buffer</param>
        /// <param name="key">The key to use. Note that XTS mode uses a key twice the underlying size of the block cipher.</param>
        /// <param name="sectorNum">The sector number, also known as the tweak. This is the equivalent of the IV/Nonce for other modes.</param>
        /// <param name="sectorSize">The size of a sector. This function allows encrypting multiple sector. Use the Sector variants if you don't care about this.</param>
        /// <returns>The encrypted data</returns>
        public static void EncryptXtsInPlace(this SymmetricAlgorithm alg, byte[] buffer, ReadOnlySpan<byte> key, BigInteger sectorNum, int sectorSize)
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

        /// <summary>
        /// Decrypt multiple sectors of data using XTS mode in place
        /// </summary>
        /// <param name="alg">A SymmetricAlgorithm representing the underlying block cipher. In a regular scenario, you can use Aes.Create() to get this.</param>
        /// <param name="buffer">The data to decrypt, and also the output buffer</param>
        /// <param name="key">The key to use. Note that XTS mode uses a key twice the underlying size of the block cipher.</param>
        /// <param name="sectorNum">The sector number, also known as the tweak. This is the equivalent of the IV/Nonce for other modes.</param>
        /// <param name="sectorSize">The size of a sector. This function allows encrypting multiple sector. Use the Sector variants if you don't care about this.</param>
        /// <returns>The decrypted data</returns>
        public static void DecryptXtsInPlace(this SymmetricAlgorithm alg, byte[] buffer, ReadOnlySpan<byte> key, BigInteger sectorNum, int sectorSize)
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

        /// <summary>
        /// Encrypt data using XTS mode in place
        /// </summary>
        /// <param name="alg">A SymmetricAlgorithm representing the underlying block cipher. In a regular scenario, you can use Aes.Create() to get this.</param>
        /// <param name="input">The data to encrypt and also the output buffer</param>
        /// <param name="key">The key to use. Note that XTS mode uses a key twice the underlying size of the block cipher.</param>
        /// <param name="sectorNum">The sector number, also known as the tweak. This is the equivalent of the IV/Nonce for other modes.</param>
        /// <returns>The encrypted data</returns>
        public static void EncryptXtsSectorInPlace(this SymmetricAlgorithm alg, byte[] buffer, ReadOnlySpan<byte> key, BigInteger sectorNum)
        {
            SetupRawCipher(alg);

            // Set K1 and create encryptor
            ICryptoTransform encryptor = alg.CreateEncryptor(key[..(key.Length / 2)].ToArray(), null);

            // Encrypt the tweak
            byte[] tweak = EncryptTweak(alg, key, sectorNum);

            // Encrypt Sector
            ProcessXtsSector(encryptor, buffer, 0, buffer.Length, tweak, false);
        }

        /// <summary>
        /// Decrypt data using XTS mode in place
        /// </summary>
        /// <param name="alg">A SymmetricAlgorithm representing the underlying block cipher. In a regular scenario, you can use Aes.Create() to get this.</param>
        /// <param name="input">The data to decrypt and also the output buffer</param>
        /// <param name="key">The key to use. Note that XTS mode uses a key twice the underlying size of the block cipher.</param>
        /// <param name="sectorNum">The sector number, also known as the tweak. This is the equivalent of the IV/Nonce for other modes.</param>
        /// <returns>The decrypted data</returns>
        public static void DecryptXtsSectorInPlace(this SymmetricAlgorithm alg, byte[] buffer, ReadOnlySpan<byte> key, BigInteger sectorNum)
        {
            SetupRawCipher(alg);

            // Set K1 and create decryptor
            ICryptoTransform decryptor = alg.CreateDecryptor(key[..(key.Length / 2)].ToArray(), null);

            // Encrypt the tweak
            byte[] tweak = EncryptTweak(alg, key, sectorNum);

            // Decrypt Sector
            ProcessXtsSector(decryptor, buffer, 0, buffer.Length, tweak, true);
        }

        /// <summary>
        /// The core XTS function. This encrypts/decrypts a sector in place
        /// </summary>
        /// <param name="alg">The block cipher encrypt/decrypt interface</param>
        /// <param name="buffer">The input and output buffer</param>
        /// <param name="bufferOffset">The offset where to start processing</param>
        /// <param name="bufferLength">The length of the data to process</param>
        /// <param name="tweak">The initial tweak value, which is an encryption of the sector number</param>
        /// <param name="decrypt">A bool telling weither or not this is a decryption. There is a single place where the function may differ based on that.</param>
        /// <exception cref="ArgumentException">Throws if the sector has less data then a full block, since this case is unsupported by XTS by design.</exception>
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
                // We fast forward the multiplication here
                bool carry = GaloisMultiplyByTwo(tweak);

                int blockStart = bufferOffset + (nFullBlocks - 1) * blockSize;
                TransformBlock(alg, buffer, blockStart, tweak);

                // We backtrack the multiplication
                GaloisUnmultiplyByTwo(tweak, carry);
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

                // Define the spans
                Span<byte> bufferSpan = buffer.AsSpan();
                Span<byte> previousBlockSpan = bufferSpan[previousBlockStart..currentBlockStart];
                Span<byte> currentBlockSpan = bufferSpan[currentBlockStart..(bufferOffset + bufferLength)];

                // We copy part of the previous ciphertext at the end and replace it with the plaintext of the last block
                SwapSpan(previousBlockSpan[..remainingBytes], currentBlockSpan);

                // We encrypt/decrypt the second to last block
                TransformBlock(alg, buffer, previousBlockStart, tweak);
            }
        }

        /// <summary>
        /// Encrypt the sector number into a tweak using K2
        /// </summary>
        /// <param name="alg">The block cipher to use</param>
        /// <param name="key">The key to use</param>
        /// <param name="sectorNum">The sector number</param>
        /// <returns>The tweak</returns>
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

        /// <summary>
        /// Setup the block cipher to be ECB without padding, since we are implementing both manually
        /// </summary>
        /// <param name="alg"></param>
        private static void SetupRawCipher(SymmetricAlgorithm alg)
        {
            // Setup for raw cipher, without mode or padding
            alg.Mode = CipherMode.ECB;
            alg.Padding = PaddingMode.None;
        }

        /// <summary>
        /// Execute the block cipher
        /// </summary>
        /// <param name="alg">The block cipher implementation</param>
        /// <param name="buffer">The working buffer</param>
        /// <param name="bufferOffset">The offset from which the data is being worked on in the buffer</param>
        /// <param name="tweak">The tweak</param>
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

        /// <summary>
        /// XOR a span into another
        /// </summary>
        /// <param name="input">The input block, which is XORed into the output</param>
        /// <param name="output">The receiving buffer</param>
        private static void XorBlocksInPlace(ReadOnlySpan<byte> input, Span<byte> output)
        {
            for (int i = 0; i < output.Length; i++)
            {
                output[i] ^= input[i];
            }
        }

        /// <summary>
        /// Swap data from one span to another.
        /// </summary>
        /// <param name="x">The first span</param>
        /// <param name="y">The second span</param>
        private static void SwapSpan(Span<byte> x, Span<byte> y)
        {
            for (int i = 0; i < x.Length; i++)
            {
                byte tmp = x[i];
                x[i] = y[i];
                y[i] = tmp;
            }
        }

        /// <summary>
        /// Galois Field multiplication by 2
        /// </summary>
        /// <param name="tweak"></param>
        /// <returns></returns>
        private static bool GaloisMultiplyByTwo(Span<byte> tweak)
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
                tweak[0] ^= GF_MOD;
            }

            return carry;
        }

        /// <summary>
        /// Reverse the galois field multiplication. This is used once during decryption to avoid an allocation
        /// </summary>
        /// <param name="tweak">The tweak to reverse</param>
        /// <param name="carry">The carry flag of the last multiplication</param>
        /// <returns></returns>
        private static void GaloisUnmultiplyByTwo(Span<byte> tweak, bool carry)
        {
            if (carry)
            {
                tweak[0] ^= GF_MOD;
            }

            int newCarry = 0;
            for (int i = tweak.Length - 1; i >= 0; i--)
            {
                int oldCarry = newCarry;

                // Check if there is a carry for this shift
                newCarry = tweak[i] & 1;

                // Shift left
                tweak[i] >>= 1;

                // Carry over bit from last carry
                tweak[i] |= (byte)(oldCarry << 7);
            }

            if (carry)
            {
                tweak[tweak.Length - 1] |= 0x80;
            }
        }
    }
}
