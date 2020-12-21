package ansi.x9_24_2004.encryption;

import ansi.x9_24_2004.utils.CustomBitSet;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInstance;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

import javax.crypto.SecretKey;
import javax.xml.bind.DatatypeConverter;
import java.util.stream.Stream;

@SuppressWarnings({"java:S1192", "java:S1112"})
public class TripleDesTest {

    private TripleDes tripleDes;

    @BeforeEach
    void init() {
        this.tripleDes = new TripleDes();
    }

    @Nested
    @TestInstance(TestInstance.Lifecycle.PER_CLASS)
    class WhenEncryptMethodIsCalled {

        @ParameterizedTest(name = "Should return encrypted data: \"{3}\".")
        @MethodSource("getKeyDataPaddingAndExpectedEncryptedData")
        void shouldEncryptData(final String key,
                               final String data,
                               final boolean padding,
                               final String expectedEncryptedData) {
            // Given
            // When
            final byte[] actualEncryptedData =
                    tripleDes.encrypt(new CustomBitSet(key), DatatypeConverter.parseHexBinary(data), padding);

            // Then
            Assertions.assertEquals(expectedEncryptedData, DatatypeConverter.printHexBinary(actualEncryptedData));
        }

        Stream<Arguments> getKeyDataPaddingAndExpectedEncryptedData() {
            return Stream.of(
                    // 8 bytes key
                    Arguments.of(
                            "0258F3E7770A5F61", // Key
                            "0000000000000000", // Data
                            false, // Padding
                            "3F1E698119F57324" // Encrypted data
                    ),
                    Arguments.of(
                            "0258F3E7770A5F61", // Key
                            "0000000000000000", // Data
                            true, // Padding
                            "3F1E698119F57324322C70A55FADB9EE" // Encrypted data
                    ),
                    Arguments.of(
                            "0258F3E7770A5F61", // Key
                            "", // Data
                            true, // Padding
                            "9F24202C537707FD" // Encrypted data
                    ),
                    // 16 bytes key
                    Arguments.of(
                            "0258F3E7770A5F610258F3E7770A5F61", // Key
                            "0000000000000000", // Data
                            false, // Padding
                            "3F1E698119F57324" // Encrypted data
                    ),
                    Arguments.of(
                            "0258F3E7770A5F610258F3E7770A5F61", // Key
                            "0000000000000000", // Data
                            true, // Padding
                            "3F1E698119F57324322C70A55FADB9EE" // Encrypted data
                    ),
                    Arguments.of(
                            "0258F3E7770A5F610258F3E7770A5F61", // Key
                            "", // Data
                            true, // Padding
                            "9F24202C537707FD" // Encrypted data
                    ),
                    // 24 bytes key
                    Arguments.of(
                            "0258F3E7770A5F610258F3E7770A5F610258F3E7770A5F61", // Key
                            "0000000000000000", // Data
                            false, // Padding
                            "3F1E698119F57324" // Encrypted data
                    ),
                    Arguments.of(
                            "0258F3E7770A5F610258F3E7770A5F610258F3E7770A5F61", // Key
                            "0000000000000000", // Data
                            true, // Padding
                            "3F1E698119F57324322C70A55FADB9EE" // Encrypted data
                    ),
                    Arguments.of(
                            "0258F3E7770A5F610258F3E7770A5F610258F3E7770A5F61", // Key
                            "", // Data
                            true, // Padding
                            "9F24202C537707FD" // Encrypted data
                    )
            );
        }

    }

    @Nested
    @TestInstance(TestInstance.Lifecycle.PER_CLASS)
    class WhenDecryptMethodIsCalled {

        @ParameterizedTest(name = "Should return decrypted data: \"{3}\".")
        @MethodSource("getKeyDataPaddingAndExpectedEncryptedData")
        void shouldDecryptData(final String key,
                               final String data,
                               final boolean padding,
                               final String expectedEncryptedData) {
            // Given
            // When
            final byte[] actualEncryptedData =
                    tripleDes.decrypt(new CustomBitSet(key), DatatypeConverter.parseHexBinary(data), padding);

            // Then
            Assertions.assertEquals(expectedEncryptedData, DatatypeConverter.printHexBinary(actualEncryptedData));
        }

        Stream<Arguments> getKeyDataPaddingAndExpectedEncryptedData() {
            return Stream.of(
                    Arguments.of(
                            "0258F3E7770A5F61", // Key
                            "3F1E698119F57324", // Encrypted data
                            false, // Padding
                            "0000000000000000" // Plain data
                    ),
                    Arguments.of(
                            "0258F3E7770A5F61", // Key
                            "3F1E698119F57324322C70A55FADB9EE", // Encrypted data
                            false, // Padding
                            "00000000000000000808080808080808" // Plain data
                    ),
                    Arguments.of(
                            "0258F3E7770A5F61", // Key
                            "9F24202C537707FD", // Encrypted data
                            false, // Padding
                            "0808080808080808" // Plain data
                    )
            );
        }

    }

    @Nested
    class WhenPaddingOptionMethodsAreCalled {

        @Test
        void shouldReturnPadding() {
            // Given
            // When
            // Then
            Assertions.assertEquals("DESede/CBC/PKCS5Padding", tripleDes.padding());
        }

        @Test
        void shouldReturnNoPadding() {
            // Given
            // When
            // Then
            Assertions.assertEquals("DESede/CBC/NoPadding", tripleDes.noPadding());
        }

    }

    @Nested
    class WhenGetEncryptionKeyMethodIsCalled {

        @Test
        void shouldCreateEncryptionKey() {
            // Given
            final CustomBitSet key = new CustomBitSet("0258F3E7770A5F61");

            // When
            final SecretKey secretKey = tripleDes.getEncryptionKey(key);

            // Then
            Assertions.assertEquals("DESede", secretKey.getAlgorithm());
            Assertions.assertEquals("RAW", secretKey.getFormat());
            Assertions.assertEquals(
                    "0258F2E6760B5E610258F2E6760B5E610258F2E6760B5E61",
                    DatatypeConverter.printHexBinary(secretKey.getEncoded())
            );
        }

    }

}
