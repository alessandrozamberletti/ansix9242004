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

    private ansi.x9_24_2004.encryption.TripleDes tripleDes;

    @BeforeEach
    void init() {
        this.tripleDes = new ansi.x9_24_2004.encryption.TripleDes();
    }

    @Nested
    @TestInstance(TestInstance.Lifecycle.PER_CLASS)
    class WhenEncryptMethodIsCalled {

        @ParameterizedTest
        @MethodSource("getKeyDataPaddingAndExpectedEncryptedData")
        void shouldEncryptData(final String key, final String data, final boolean padding, final String expectedEncryptedData) {
            // Given
            // When
            final byte[] actualEncryptedData = tripleDes.encrypt(CustomBitSet.toBitSet(key), DatatypeConverter.parseHexBinary(data), padding);

            // Then
            Assertions.assertEquals(expectedEncryptedData, DatatypeConverter.printHexBinary(actualEncryptedData));
        }

        Stream<Arguments> getKeyDataPaddingAndExpectedEncryptedData() {
            return Stream.of(
                    // 8 bytes key
                    Arguments.of("0258F3E7770A5F61", "0000000000000000", false, "3F1E698119F57324"),
                    Arguments.of("0258F3E7770A5F61", "0000000000000000", true, "3F1E698119F57324322C70A55FADB9EE"),
                    Arguments.of("0258F3E7770A5F61", "", true, "9F24202C537707FD"),
                    // 16 bytes key
                    Arguments.of("0258F3E7770A5F610258F3E7770A5F61", "0000000000000000", false, "3F1E698119F57324"),
                    Arguments.of("0258F3E7770A5F610258F3E7770A5F61", "0000000000000000", true, "3F1E698119F57324322C70A55FADB9EE"),
                    Arguments.of("0258F3E7770A5F610258F3E7770A5F61", "", true, "9F24202C537707FD"),
                    // 24 bytes key
                    Arguments.of("0258F3E7770A5F610258F3E7770A5F610258F3E7770A5F61", "0000000000000000", false, "3F1E698119F57324"),
                    Arguments.of("0258F3E7770A5F610258F3E7770A5F610258F3E7770A5F61", "0000000000000000", true, "3F1E698119F57324322C70A55FADB9EE"),
                    Arguments.of("0258F3E7770A5F610258F3E7770A5F610258F3E7770A5F61", "", true, "9F24202C537707FD")
            );
        }

    }

    @Nested
    @TestInstance(TestInstance.Lifecycle.PER_CLASS)
    class WhenDecryptMethodIsCalled {

        @ParameterizedTest
        @MethodSource("getKeyDataPaddingAndExpectedEncryptedData")
        void shouldDecryptData(final String key, final String data, final boolean padding, final String expectedEncryptedData) {
            // Given
            // When
            final byte[] actualEncryptedData = tripleDes.decrypt(CustomBitSet.toBitSet(key), DatatypeConverter.parseHexBinary(data), padding);

            // Then
            Assertions.assertEquals(expectedEncryptedData, DatatypeConverter.printHexBinary(actualEncryptedData));
        }

        Stream<Arguments> getKeyDataPaddingAndExpectedEncryptedData() {
            return Stream.of(
                    Arguments.of("0258F3E7770A5F61", "3F1E698119F57324", false, "0000000000000000"),
                    Arguments.of("0258F3E7770A5F61", "3F1E698119F57324322C70A55FADB9EE", false, "00000000000000000808080808080808"),
                    Arguments.of("0258F3E7770A5F61", "9F24202C537707FD", false, "0808080808080808")
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
            final CustomBitSet key = CustomBitSet.toBitSet("0258F3E7770A5F61");

            // When
            final SecretKey secretKey = tripleDes.getEncryptionKey(key);

            // Then
            Assertions.assertEquals("DESede", secretKey.getAlgorithm());
            Assertions.assertEquals("RAW", secretKey.getFormat());
            Assertions.assertEquals("0258F2E6760B5E610258F2E6760B5E610258F2E6760B5E61", DatatypeConverter.printHexBinary(secretKey.getEncoded()));
        }

    }

}
