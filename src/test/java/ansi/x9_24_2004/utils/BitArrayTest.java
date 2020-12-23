package ansi.x9_24_2004.utils;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.TestInstance;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

import javax.xml.bind.DatatypeConverter;
import java.util.stream.Stream;

public class BitArrayTest {

    @Nested
    @TestInstance(TestInstance.Lifecycle.PER_CLASS)
    class WhenToByteArrayMethodIsCalled {

        @ParameterizedTest(name = "Should return: \"{0}\".")
        @MethodSource("getValue")
        void shouldGetByteArray(final String value) {
            // Given
            // When
            final byte[] actualValue = new BitArray(value).toByteArray();

            // Then
            Assertions.assertArrayEquals(DatatypeConverter.parseHexBinary(value), actualValue);
        }

        Stream<Arguments> getValue() {
            return Stream.of(
                    Arguments.of(""),
                    Arguments.of("12"),
                    Arguments.of("1234"),
                    Arguments.of("123456"),
                    Arguments.of("12345678"),
                    Arguments.of("1234567890"),
                    Arguments.of("123456789012"),
                    Arguments.of("12345678901234")
            );
        }

    }

}
