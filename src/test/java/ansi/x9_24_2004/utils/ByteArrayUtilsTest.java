package ansi.x9_24_2004.utils;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInstance;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

import java.util.stream.Stream;

public class ByteArrayUtilsTest {

    @Nested
    @TestInstance(TestInstance.Lifecycle.PER_CLASS)
    class WhenConcatMethodIsCalled {

        @ParameterizedTest(name = "Should concatenate \"{0}\" and \"{1}\" and return: \"{2}\".")
        @MethodSource("getComponentsAndExpectedResult")
        void shouldConcatenate(final String first,
                               final String second,
                               final String expectedResult) {
            // Given
            // When
            final byte[] actualResult = ByteArrayUtils.concat(first.getBytes(), second.getBytes());

            // Then
            Assertions.assertArrayEquals(expectedResult.getBytes(), actualResult);
        }

        Stream<Arguments> getComponentsAndExpectedResult() {
            return Stream.of(
                    Arguments.of("first", "second", "firstsecond"),
                    Arguments.of("", "second", "second"),
                    Arguments.of("first", "", "first"),
                    Arguments.of("", "", "")
            );
        }

        @Test
        void shouldThrowOnException() {
            // Given
            // When
            final IllegalStateException illegalStateException =
                    Assertions.assertThrows(
                            IllegalStateException.class,
                            () -> ByteArrayUtils.concat(null, "second".getBytes())
                    );

            // Then
            Assertions.assertEquals(
                    "Error while concatenating 'null' and '[115, 101, 99, 111, 110, 100]'",
                    illegalStateException.getMessage()
            );
        }

    }

}
