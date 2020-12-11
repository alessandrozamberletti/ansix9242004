package ansi.x9_24_2004.utils;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.TestInstance;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

import java.util.stream.Stream;

@SuppressWarnings({"java:S1192"})
public class StringUtilsTest {

    @Nested
    @TestInstance(TestInstance.Lifecycle.PER_CLASS)
    class WhenRightPadMethodIsCalled {

        @ParameterizedTest
        @MethodSource("getElementTargetLengthFillerAndExpectedResult")
        void shouldRightPad(final String element, final int targetLength, final char filler, final String expectedResult) {
            // Given
            // When
            final String actualResult = StringUtils.rightPad(element, targetLength, filler);

            // Then
            Assertions.assertEquals(expectedResult, actualResult);
        }

        Stream<Arguments> getElementTargetLengthFillerAndExpectedResult() {
            return Stream.of(
                    Arguments.of("A", 5, 'F', "AFFFF"),
                    Arguments.of("", 16, 'F', "FFFFFFFFFFFFFFFF"),
                    Arguments.of("FFFFFFFFFFFFFFFF", 16, 'A', "FFFFFFFFFFFFFFFF"),
                    Arguments.of("FFFFFFFFFFFFFFFFABC", 16, 'A', "FFFFFFFFFFFFFFFFABC")
            );
        }

    }

    @Nested
    @TestInstance(TestInstance.Lifecycle.PER_CLASS)
    class WhenLeftPadMethodIsCalled {

        @ParameterizedTest
        @MethodSource("getElementTargetLengthFillerAndExpectedResult")
        void shouldLeftPad(final String element, final int targetLength, final char filler, final String expectedResult) {
            // Given
            // When
            final String actualResult = StringUtils.leftPad(element, targetLength, filler);

            // Then
            Assertions.assertEquals(expectedResult, actualResult);
        }

        Stream<Arguments> getElementTargetLengthFillerAndExpectedResult() {
            return Stream.of(
                    Arguments.of("A", 5, 'F', "FFFFA"),
                    Arguments.of("", 16, 'F', "FFFFFFFFFFFFFFFF"),
                    Arguments.of("FFFFFFFFFFFFFFFF", 16, 'A', "FFFFFFFFFFFFFFFF"),
                    Arguments.of("FFFFFFFFFFFFFFFFABC", 16, 'A', "FFFFFFFFFFFFFFFFABC")
            );
        }

    }

}
