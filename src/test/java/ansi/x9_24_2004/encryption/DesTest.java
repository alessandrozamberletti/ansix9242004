package ansi.x9_24_2004.encryption;

import ansi.x9_24_2004.utils.BitArray;
import org.junit.jupiter.api.Assertions;
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
public class DesTest {

    private final Des des = new Des();

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
                    des.encrypt(new BitArray(key), DatatypeConverter.parseHexBinary(data), padding);

            // Then
            Assertions.assertEquals(expectedEncryptedData, DatatypeConverter.printHexBinary(actualEncryptedData));
        }

        Stream<Arguments> getKeyDataPaddingAndExpectedEncryptedData() {
            return Stream.of(
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
                    )
            );
        }

        @Test
        void shouldThrowOnWrongKey() {
            // Given
            final BitArray wrongKey = new BitArray("FF");
            final byte[] data = "".getBytes();

            // When
            final IllegalStateException illegalStateException =
                    Assertions.assertThrows(
                            IllegalStateException.class,
                            () -> des.encrypt(wrongKey, data)
                    );

            // Then
            Assertions.assertEquals(
                    "Wrong DES key: 'FF'",
                    illegalStateException.getMessage()
            );
        }

    }

    @Nested
    @TestInstance(TestInstance.Lifecycle.PER_CLASS)
    class WhenEncryptMethodIsCalledWithIV {

        @ParameterizedTest(name = "Should return encrypted data: \"{3}\".")
        @MethodSource("getKeyDataPaddingAndExpectedEncryptedData")
        void shouldEncryptData(final String key,
                               final String data,
                               final boolean padding,
                               final String expectedEncryptedData,
                               final byte[] iv) {
            // Given
            // When
            final byte[] actualEncryptedData =
                    des.encrypt(new BitArray(key), DatatypeConverter.parseHexBinary(data), padding, iv);

            // Then
            Assertions.assertEquals(expectedEncryptedData, DatatypeConverter.printHexBinary(actualEncryptedData));
        }

        Stream<Arguments> getKeyDataPaddingAndExpectedEncryptedData() {
            return Stream.of(
                    Arguments.of(
                            "0258F3E7770A5F61", // Key
                            "0000000000000000", // Data
                            false, // Padding
                            "3F1E698119F57324", // Encrypted data
                            new byte[8]
                    ),
                    Arguments.of(
                            "0258F3E7770A5F61", // Key
                            "0000000000000000", // Data
                            false, // Padding
                            "CBDDCE0844348885", // Encrypted data
                            DatatypeConverter.parseHexBinary("1234567890123456")
                    ),
                    Arguments.of(
                            "0258F3E7770A5F61", // Key
                            "", // Data
                            true, // Padding
                            "9F24202C537707FD", // Encrypted data
                            new byte[8]
                    )
            );
        }

        @Test
        void shouldThrowOnWrongKey() {
            // Given
            final BitArray wrongKey = new BitArray("FF");
            final byte[] data = "".getBytes();

            // When
            final IllegalStateException illegalStateException =
                    Assertions.assertThrows(
                            IllegalStateException.class,
                            () -> des.encrypt(wrongKey, data, false, new byte[8])
                    );

            // Then
            Assertions.assertEquals(
                    "Wrong DES key: 'FF'",
                    illegalStateException.getMessage()
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
                    des.decrypt(new BitArray(key), DatatypeConverter.parseHexBinary(data), padding);

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

        @Test
        void shouldThrowOnWrongKey() {
            // Given
            final BitArray wrongKey = new BitArray("FF");
            final byte[] data = "".getBytes();

            // When
            final IllegalStateException illegalStateException =
                    Assertions.assertThrows(
                            IllegalStateException.class,
                            () -> des.decrypt(wrongKey, data)
                    );

            // Then
            Assertions.assertEquals(
                    "Wrong DES key: 'FF'",
                    illegalStateException.getMessage()
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
            Assertions.assertEquals("DES/CBC/PKCS5Padding", des.padding());
        }

        @Test
        void shouldReturnNoPadding() {
            // Given
            // When
            // Then
            Assertions.assertEquals("DES/CBC/NoPadding", des.noPadding());
        }

    }

    @Nested
    class WhenGetEncryptionKeyMethodIsCalled {

        @Test
        void shouldCreateEncryptionKey() {
            // Given
            final BitArray key = new BitArray("0258F3E7770A5F61");

            // When
            final SecretKey secretKey = des.getEncryptionKey(key);

            // Then
            Assertions.assertEquals("DES", secretKey.getAlgorithm());
            Assertions.assertEquals("RAW", secretKey.getFormat());
            Assertions.assertEquals(
                    "0258F2E6760B5E61",
                    DatatypeConverter.printHexBinary(secretKey.getEncoded())
            );
        }

        @Test
        void shouldThrowOnWrongKey() {
            // Given
            final BitArray wrongKey = new BitArray("FF");

            // When
            final IllegalStateException illegalStateException = Assertions.assertThrows(
                    IllegalStateException.class,
                    () -> des.getEncryptionKey(wrongKey)
            );

            // Then
            Assertions.assertEquals(
                    "Wrong DES key: 'FF'",
                    illegalStateException.getMessage()
            );
        }

    }

}
