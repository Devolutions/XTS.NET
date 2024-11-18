using System.Text;

namespace XTS.NET.Tests;

public class Tests
{
    [SetUp]
    public void Setup()
    {
    }

    [Test]
    public void EncryptDecryptTest()
    {
        // Text generated with ChatGPT
        byte[] expectedPlaintext = Encoding.UTF8.GetBytes("In the serene dawn of a hidden valley, golden sunlight began filtering through the mist, painting the landscape in hues of orange and pink. Each leaf sparkled with a delicate sheen of dew, reminiscent of a thousand scattered jewels upon the gentle sway of early autumn trees. A distant river whispered a soft, calming lullaby, threading its way through a bed of smooth stones. Birds, waking from their slumber, chirped a subtle yet beautiful symphony that harmonized with the flowing water, creating a tranquil yet powerful soundscape. Amidst this quiet paradise, a lone figure walked, footprints left on the soft earth, exploring with reverent curiosity.\r\n\r\nAs the figure ventured deeper into the valley, an old stone bridge appeared over the river, its stones worn by countless seasons, yet resilient, standing as a testament to the artisans of old. Crossing the bridge, they were greeted by a vibrant grove, filled with the earthy scent of damp soil and the faint fragrance of blooming wildflowers. In this magical solitude, time seemed to slow, each step a moment to breathe, to feel, and to simply exist in harmony with the world around.\r\n\r\nThis should provide around 520 bytes for a few blocks but not perfectly divisible by 520, as requested. Let me know if you'd like more text or a different style.");
        byte[] key = [
            0xE1, 0x33, 0xCB, 0xCB, 0x9B, 0xA4, 0x9E, 0xCC,
            0x27, 0x40, 0xD6, 0xF9, 0x71, 0x22, 0xA9, 0x5A,
            0x0F, 0x70, 0x77, 0xAA, 0x20, 0x2E, 0xA9, 0xAE,
            0xB6, 0x4B, 0x3B, 0xDA, 0x87, 0xED, 0xE8, 0xC7
        ];

        Aes cipher = Aes.Create();

        byte[] ciphertext = (byte[])expectedPlaintext.Clone();
        cipher.EncryptXts(ciphertext, key, 0, 520);

        // Ensures some form of data transformation happened
        Assert.That(ciphertext, Is.Not.EqualTo(expectedPlaintext));

        cipher.DecryptXts(ciphertext, key, 0, 520);

        Assert.That(ciphertext, Is.EqualTo(expectedPlaintext));
    }

    [Test]
    public void EncryptDecrypt256Test()
    {
        // Text generated with ChatGPT
        byte[] expectedPlaintext = Encoding.UTF8.GetBytes("In the serene dawn of a hidden valley, golden sunlight began filtering through the mist, painting the landscape in hues of orange and pink. Each leaf sparkled with a delicate sheen of dew, reminiscent of a thousand scattered jewels upon the gentle sway of early autumn trees. A distant river whispered a soft, calming lullaby, threading its way through a bed of smooth stones. Birds, waking from their slumber, chirped a subtle yet beautiful symphony that harmonized with the flowing water, creating a tranquil yet powerful soundscape. Amidst this quiet paradise, a lone figure walked, footprints left on the soft earth, exploring with reverent curiosity.\r\n\r\nAs the figure ventured deeper into the valley, an old stone bridge appeared over the river, its stones worn by countless seasons, yet resilient, standing as a testament to the artisans of old. Crossing the bridge, they were greeted by a vibrant grove, filled with the earthy scent of damp soil and the faint fragrance of blooming wildflowers. In this magical solitude, time seemed to slow, each step a moment to breathe, to feel, and to simply exist in harmony with the world around.\r\n\r\nThis should provide around 520 bytes for a few blocks but not perfectly divisible by 520, as requested. Let me know if you'd like more text or a different style.");
        byte[] key = [
            0xE1, 0x33, 0xCB, 0xCB, 0x9B, 0xA4, 0x9E, 0xCC,
            0x27, 0x40, 0xD6, 0xF9, 0x71, 0x22, 0xA9, 0x5A,
            0x0F, 0x70, 0x77, 0xAA, 0x20, 0x2E, 0xA9, 0xAE,
            0xB6, 0x4B, 0x3B, 0xDA, 0x87, 0xED, 0xE8, 0xC7,
            0xE9, 0xC2, 0x5D, 0xC4, 0x14, 0xF2, 0xB4, 0xAD,
            0xC0, 0xF5, 0x80, 0x41, 0xA0, 0xCA, 0x16, 0x6F,
            0xB4, 0x11, 0x66, 0x21, 0x61, 0x8F, 0x24, 0xF5,
            0xED, 0xD3, 0x95, 0xD1, 0xB1, 0xA6, 0x19, 0x39
            
        ];

        Aes cipher = Aes.Create();

        byte[] ciphertext = (byte[])expectedPlaintext.Clone();
        cipher.EncryptXts(ciphertext, key, 0, 520);

        // Ensures some form of data transformation happened
        Assert.That(ciphertext, Is.Not.EqualTo(expectedPlaintext));

        cipher.DecryptXts(ciphertext, key, 0, 520);

        Assert.That(ciphertext, Is.EqualTo(expectedPlaintext));
    }

    [Test]
    public void NoStealingTestCase()
    {
        // Text generated with ChatGPT
        byte[] expectedPlaintext = Encoding.UTF8.GetBytes("ABCDEFGHIJKLMNOPQRSTUVWXYZ123456");
        byte[] key = [
            0xE1, 0x33, 0xCB, 0xCB, 0x9B, 0xA4, 0x9E, 0xCC,
            0x27, 0x40, 0xD6, 0xF9, 0x71, 0x22, 0xA9, 0x5A,
            0x0F, 0x70, 0x77, 0xAA, 0x20, 0x2E, 0xA9, 0xAE,
            0xB6, 0x4B, 0x3B, 0xDA, 0x87, 0xED, 0xE8, 0xC7
        ];

        Aes cipher = Aes.Create();

        byte[] ciphertext = (byte[])expectedPlaintext.Clone();

        cipher.EncryptXts(ciphertext, key, 0, 520);

        // Ensures some form of data transformation happened
        Assert.That(ciphertext, Is.Not.EqualTo(expectedPlaintext));

        cipher.DecryptXts(ciphertext, key, 0, 520);

        Assert.That(ciphertext, Is.EqualTo(expectedPlaintext));
    }

    [Test]
    public void ExactSectorTestCase()
    {
        // Text generated with ChatGPT
        byte[] expectedPlaintext = Encoding.UTF8.GetBytes("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789");
        byte[] key = [
            0xE1, 0x33, 0xCB, 0xCB, 0x9B, 0xA4, 0x9E, 0xCC,
            0x27, 0x40, 0xD6, 0xF9, 0x71, 0x22, 0xA9, 0x5A,
            0x0F, 0x70, 0x77, 0xAA, 0x20, 0x2E, 0xA9, 0xAE,
            0xB6, 0x4B, 0x3B, 0xDA, 0x87, 0xED, 0xE8, 0xC7
        ];

        Aes cipher = Aes.Create();

        byte[] ciphertext = (byte[])expectedPlaintext.Clone();

        cipher.EncryptXts(ciphertext, key, 0, 100);

        // Ensures some form of data transformation happened
        Assert.That(ciphertext, Is.Not.EqualTo(expectedPlaintext));

        cipher.DecryptXts(ciphertext, key, 0, 100);

        Assert.That(ciphertext, Is.EqualTo(expectedPlaintext));
    }
}