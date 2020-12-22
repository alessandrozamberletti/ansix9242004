package ansi.x9_24_2004.pin;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.TestInstance;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

import java.util.stream.Stream;

@SuppressWarnings({"java:S1192"})
public class PinProcessorTest {

    private final PinProcessor pinProcessor = new PinProcessor();

    @Nested
    @TestInstance(TestInstance.Lifecycle.PER_CLASS)
    class WhenFromIso0PinMethodIsCalled {

        @ParameterizedTest(name = "Should return PIN: \"{2}\".")
        @MethodSource("getIso0PinBlockPanAndExpectedClearPin")
        void shouldReturnPin(final String iso0Pin,
                             final String pan,
                             final String expectedPin) {
            // Given
            // When
            final String pin = pinProcessor.fromIso0Pin(iso0Pin, pan);

            // Then
            Assertions.assertEquals(expectedPin, pin);
        }

        Stream<Arguments> getIso0PinBlockPanAndExpectedClearPin() {
            return Stream.of(
                    Arguments.of(
                            "0612076FFFFFFEAE", // Clear ISO-0 PIN
                            "5413339000001513", // PAN
                            "123456" // Clear PIN
                    ),
                    Arguments.of(
                            "0412AC89ABCDEF67", // Clear ISO-0 PIN
                            "43219876543210987", // PAN
                            "1234" // Clear PIN
                    ),
                    Arguments.of(
                            "04439CFFFFFF8FFE", // Clear ISO-0 PIN
                            "6799998900000070017", // PAN
                            "4315" // Clear PIN
                    ),
                    Arguments.of(
                            "0612076FFFFFFEAE", // Clear ISO-0 PIN
                            "5413339000001513", // PAN
                            "123456" // Clear PIN
                    ),
                    Arguments.of(
                            "06123556FFFFFFFE", // Clear ISO-0 PIN
                            "6799990100000000019", // PAN
                            "123456" // Clear PIN
                    )
            );
        }

    }

    @Nested
    @TestInstance(TestInstance.Lifecycle.PER_CLASS)
    class WhenToIso0FormatPinBlockIsCalled {

        @ParameterizedTest(name = "Should return ISO-0 PIN: \"{2}\".")
        @MethodSource("getPinPanAndExpectedIso0FormatPinBlock")
        void shouldReturnIs0Pin(final String pin,
                                final String pan,
                                final String expectedIso0FormatPinBlock) {
            // Given
            // When
            final String actualIso0FormatPinBlock = pinProcessor.toIso0Pin(pin, pan);

            // Then
            Assertions.assertEquals(expectedIso0FormatPinBlock, actualIso0FormatPinBlock);
        }

        Stream<Arguments> getPinPanAndExpectedIso0FormatPinBlock() {
            return Stream.of(
                    Arguments.of(
                            "1234", // Clear PIN
                            "43219876543210987", // PAN
                            "0412AC89ABCDEF67" // Clear ISO-0 PIN
                    ),
                    Arguments.of(
                            "6543", // Clear PIN
                            "6333000023456788", // PAN
                            "046573FFFDCBA987" // Clear ISO-0 PIN
                    ),
                    Arguments.of(
                            "123456", // Clear PIN
                            "341111597241002", // PAN
                            "06122547A68DBEFF" // Clear ISO-0 PIN
                    ),
                    Arguments.of(
                            "87654321", // Clear PIN
                            "3566000020000410", // PAN
                            "0887054323FFFFBE" // Clear ISO-0 PIN
                    ),
                    Arguments.of(
                            "123456", // Clear PIN
                            "6799990100000000019", // PAN
                            "06123556FFFFFFFE" // Clear ISO-0 PIN
                    )
            );
        }

    }

    @Nested
    @TestInstance(TestInstance.Lifecycle.PER_CLASS)
    class WhenGetAccountNumberBlockMethodIsCalled {

        @ParameterizedTest(name = "Should return Account Number block: \"{1}\".")
        @MethodSource("getPanAndExpectedAccountNumberBlock")
        void shouldReturnAccountNumber(final String pan,
                                       final String expectedAccountNumberBlock) {
            // Given
            // When
            final String accountNumberBlock = pinProcessor.getAccountNumberBlock(pan);

            // Then
            Assertions.assertEquals(expectedAccountNumberBlock, accountNumberBlock);
        }

        Stream<Arguments> getPanAndExpectedAccountNumberBlock() {
            return Stream.of(
                    Arguments.of(
                            "376100000000004", // PAN
                            "0000610000000000" // Account Number Block
                    ),
                    Arguments.of(
                            "341111597241002", // PAN
                            "0000111159724100" // Account Number Block
                    ),
                    Arguments.of(
                            "36555500001111", // PAN
                            "0000655550000111" // Account Number Block
                    ),
                    Arguments.of(
                            "6011000991300009", // PAN
                            "0000100099130000" // Account Number Block
                    ),
                    Arguments.of(
                            "3561000000000005", // PAN
                            "0000100000000000" // Account Number Block
                    ),
                    Arguments.of(
                            "3566000020000410", // PAN
                            "0000600002000041" // Account Number Block
                    ),
                    Arguments.of(
                            "6761000000000006", // PAN
                            "0000100000000000" // Account Number Block
                    ),
                    Arguments.of(
                            "6333000023456788", // PAN
                            "0000300002345678" // Account Number Block
                    ),
                    Arguments.of(
                            "5123450000000008", // PAN
                            "0000345000000000" // Account Number Block
                    ),
                    Arguments.of(
                            "5413339000001513", // PAN
                            "0000333900000151" // Account Number Block
                    )
            );
        }

    }

}
