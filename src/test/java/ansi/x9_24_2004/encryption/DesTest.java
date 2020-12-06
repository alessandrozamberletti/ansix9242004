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
public class DesTest {

    private ansi.x9_24_2004.encryption.Des des;

    @BeforeEach
    void init() {
        this.des = new ansi.x9_24_2004.encryption.Des();
    }

    @Nested
    @TestInstance(TestInstance.Lifecycle.PER_CLASS)
    class WhenEncryptMethodIsCalled {

        @ParameterizedTest
        @MethodSource("getKeyDataPaddingAndExpectedEncryptedData")
        void shouldEncryptData(final CustomBitSet key,
                               final String data,
                               final boolean padding,
                               final String expectedEncryptedData) {
            // Given
            // When
            final byte[] actualEncryptedData = des.encrypt(key, DatatypeConverter.parseHexBinary(data), padding);

            // Then
            Assertions.assertEquals(expectedEncryptedData, DatatypeConverter.printHexBinary(actualEncryptedData));
        }

        Stream<Arguments> getKeyDataPaddingAndExpectedEncryptedData() {
            return Stream.of(
                    Arguments.of(new CustomBitSet("0258F3E7770A5F61"), "0000000000000000", false, "3F1E698119F57324"),
                    Arguments.of(new CustomBitSet("0258F3E7770A5F61"), "0000000000000000", true, "3F1E698119F57324322C70A55FADB9EE"),
                    Arguments.of(new CustomBitSet("0258F3E7770A5F61"), "", true, "9F24202C537707FD")
            );
        }

    }

    @Nested
    @TestInstance(TestInstance.Lifecycle.PER_CLASS)
    class WhenDecryptMethodIsCalled {

        @ParameterizedTest
        @MethodSource("getKeyDataPaddingAndExpectedEncryptedData")
        void shouldDecryptData(final CustomBitSet key,
                               final String data,
                               final boolean padding,
                               final String expectedEncryptedData) {
            // Given
            // When
            final byte[] actualEncryptedData =
                    des.decrypt(key, DatatypeConverter.parseHexBinary(data), padding);

            // Then
            Assertions.assertEquals(expectedEncryptedData, DatatypeConverter.printHexBinary(actualEncryptedData));
        }

        Stream<Arguments> getKeyDataPaddingAndExpectedEncryptedData() {
            return Stream.of(
                    Arguments.of(new CustomBitSet("0258F3E7770A5F61"), "3F1E698119F57324", false, "0000000000000000"),
                    Arguments.of(new CustomBitSet("0258F3E7770A5F61"), "3F1E698119F57324322C70A55FADB9EE", false, "00000000000000000808080808080808"),
                    Arguments.of(new CustomBitSet("0258F3E7770A5F61"), "9F24202C537707FD", false, "0808080808080808")
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
            final CustomBitSet key = new CustomBitSet("0258F3E7770A5F61");

            // When
            final SecretKey secretKey = des.getEncryptionKey(key);

            // Then
            Assertions.assertEquals("DES", secretKey.getAlgorithm());
            Assertions.assertEquals("RAW", secretKey.getFormat());
            Assertions.assertEquals("0258F2E6760B5E61", DatatypeConverter.printHexBinary(secretKey.getEncoded()));
        }

    }

}
