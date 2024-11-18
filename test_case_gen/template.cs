namespace XTS.NET.Tests;

public class IeeeVectorsTests
{ {% for test in test_cases %}
    [Test]
    public void Vector{{ test.vectorNum }}Test()
    {
        byte[] key = [
            {{ test.key }}
        ];

        ulong sector = {{ test.sector }};

        byte[] expectedPlaintext = [
            {{ test.expectedPlaintext }}
        ];

        byte[] expectedCiphertext = [
            {{ test.expectedCiphertext }}
        ];

        SymmetricAlgorithm aes = Aes.Create();

        byte[] ciphertext = (byte[])expectedPlaintext.Clone();
        
        aes.EncryptXtsSector(ciphertext, key, sector);
        Assert.That(ciphertext, Is.EqualTo(expectedCiphertext));

        aes.DecryptXtsSector(ciphertext, key, sector);
        Assert.That(ciphertext, Is.EqualTo(expectedPlaintext));
    }
{% endfor %}
}