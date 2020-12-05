package ansi.x9_24_2004.dukpt;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.TestInstance;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

import java.util.stream.Stream;

public class KeyMaskTest {

    @Nested
    @TestInstance(TestInstance.Lifecycle.PER_CLASS)
    class WhenValueMethodIsCalled {

        @ParameterizedTest
        @MethodSource("getMaskAndExpectedValue")
        void shouldHaveExpectedValue(final Mask mask, final String expectedValue) {
            // Given
            // When
            // Then
            Assertions.assertEquals(expectedValue, mask.value().toString());
        }

        Stream<Arguments> getMaskAndExpectedValue() {
            return Stream.of(
                    Arguments.of(Mask.KEY_REGISTER_BITMASK, "C0C0C0C000000000C0C0C0C000000000"),
                    Arguments.of(Mask.REQUEST_DATA_MASK, "0000000000FF00000000000000FF0000"),
                    Arguments.of(Mask.REQUEST_MAC_MASK, "000000000000FF00000000000000FF00"),
                    Arguments.of(Mask.PIN_MASK, "00000000000000FF00000000000000FF")
            );
        }

    }

}
