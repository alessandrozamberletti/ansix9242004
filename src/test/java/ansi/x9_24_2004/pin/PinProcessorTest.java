package ansi.x9_24_2004.pin;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.TestInstance;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

import javax.xml.bind.DatatypeConverter;
import java.util.stream.Stream;

public class PinProcessorTest {

    private PinProcessor pinProcessor;

    @BeforeEach
    void init() {
        this.pinProcessor = new PinProcessor();
    }

    @Nested
    @TestInstance(TestInstance.Lifecycle.PER_CLASS)
    class WhenDecodeIso0PinBlockMethodIsCalled {

        @ParameterizedTest
        @MethodSource("getIso0PinBlockPanAndExpectedClearPin")
        void shouldReturnPin(final String iso0Pin, final String pan, final String expectedPin) {
            // Given
            // When
            final String pin = pinProcessor.decodeIso0PinBlock(DatatypeConverter.parseHexBinary(iso0Pin), pan);

            // Then
            Assertions.assertEquals(expectedPin, pin);
        }

        Stream<Arguments> getIso0PinBlockPanAndExpectedClearPin() {
            return Stream.of(
                    Arguments.of(
                            // Clear Iso0 PinBlock
                            "0612076FFFFFFEAE",
                            // Pan
                            "5413339000001513",
                            // Clear PIN
                            "123456"
                    )
            );
        }

    }

    @Nested
    @TestInstance(TestInstance.Lifecycle.PER_CLASS)
    class WhenGetAccountNumberBlockMethodIsCalled {

        @ParameterizedTest
        @MethodSource("getPanAndExpectedAccountNumberBlock")
        void shouldReturnAccountNumber(final String pan, final String expectedAccountNumberBlock) {
            // Given
            // When
            final String accountNumberBlock = PinProcessor.getAccountNumberBlock(pan);

            // Then
            Assertions.assertEquals(expectedAccountNumberBlock, accountNumberBlock);
        }

        Stream<Arguments> getPanAndExpectedAccountNumberBlock() {
            return Stream.of(
              Arguments.of("376100000000004", "0000610000000000"),
              Arguments.of("341111597241002", "0000111159724100"),
              Arguments.of("36555500001111", "0000655550000111"),
              Arguments.of("6011000991300009", "0000100099130000"),
              Arguments.of("3561000000000005", "0000100000000000"),
              Arguments.of("3566000020000410", "0000600002000041"),
              Arguments.of("6761000000000006", "0000100000000000"),
              Arguments.of("6333000023456788", "0000300002345678"),
              Arguments.of("5123450000000008", "0000345000000000"),
              Arguments.of("5413339000001513", "0000333900000151")
            );
        }

    }

}
