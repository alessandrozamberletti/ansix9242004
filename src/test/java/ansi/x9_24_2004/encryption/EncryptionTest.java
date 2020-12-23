package ansi.x9_24_2004.encryption;

import ansi.x9_24_2004.utils.BitArray;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.TestInstance;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

import javax.crypto.SecretKey;
import java.util.stream.Stream;

public class EncryptionTest {

    private final Encryption encryption = new Encryption() {
        @Override
        public SecretKey getEncryptionKey(BitArray key) {
            return null;
        }

        @Override
        public String padding() {
            return "wrongPadding";
        }

        @Override
        public String noPadding() {
            return "wrongPadding";
        }

    };

    @Nested
    @TestInstance(TestInstance.Lifecycle.PER_CLASS)
    class WhenGetCipherMethodIsCalled {

        @ParameterizedTest(name = "Should throw on wrong padding (never raised).")
        @MethodSource("getPadding")
        void shouldThrowOnWrongPadding() {
            // Given
            // When
            final IllegalStateException illegalStateException = Assertions.assertThrows(
                    IllegalStateException.class,
                    () -> encryption.getCipher(true)
            );

            // Then
            Assertions.assertEquals(
                    "Cannot find any provider supporting wrongPadding",
                    illegalStateException.getMessage()
            );
        }

        Stream<Arguments> getPadding() {
            return Stream.of(
                    Arguments.of(true),
                    Arguments.of(false)
            );
        }

    }

}
