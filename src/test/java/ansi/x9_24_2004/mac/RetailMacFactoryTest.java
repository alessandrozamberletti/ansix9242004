package ansi.x9_24_2004.mac;

import ansi.x9_24_2004.utils.CustomBitSet;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.TestInstance;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

import javax.xml.bind.DatatypeConverter;
import java.util.stream.Stream;

public class RetailMacFactoryTest {

    private final RetailMacFactory retailMacFactory = new RetailMacFactory();

    @Nested
    @TestInstance(TestInstance.Lifecycle.PER_CLASS)
    class WhenXorMethodIsCalled {

        @ParameterizedTest(name = "Should XOR \"{0}\" and \"{1}\" and return: \"{2}\".")
        @MethodSource("getValuesAndExpectedXorResult")
        void shouldXorValues(final String first,
                             final String second,
                             final String expectedResult) {
            // Given
            // When
            final byte[] actualResult =
                    retailMacFactory.xor(DatatypeConverter.parseHexBinary(first), DatatypeConverter.parseHexBinary(second));
            // Then
            Assertions.assertEquals(expectedResult, DatatypeConverter.printHexBinary(actualResult));
        }

        Stream<Arguments> getValuesAndExpectedXorResult() {
            return Stream.of(
                    Arguments.of("1111", "0000", "1111"),
                    Arguments.of("0000", "0000", "0000"),
                    Arguments.of("1010", "1111", "0101"),
                    Arguments.of("ABCDEF", "0B0D0F", "A0C0E0")
            );
        }

    }

    @Nested
    @TestInstance(TestInstance.Lifecycle.PER_CLASS)
    class WhenCreateMethodIsCalled {

        @ParameterizedTest(name = "Should compute MAC: \"{2}\".")
        @MethodSource("getKeyDataAndExpectedMac")
        void shouldComputeRetailMac(final CustomBitSet key,
                                    final String data,
                                    final String expectedMac) {
            // Given
            // When
            final byte[] actualMac = retailMacFactory.create(key, DatatypeConverter.parseHexBinary(data));

            // Then
            Assertions.assertEquals(expectedMac, DatatypeConverter.printHexBinary(actualMac));
        }

        Stream<Arguments> getKeyDataAndExpectedMac() {
            return Stream.of(
                    Arguments.of(
                            // Key
                            new CustomBitSet("0258F3E777F5A061241AE6523458C430"),
                            // Data
                            "2C37F1179040F7E7D7BFF535DEEA4B19A50FD9C4E72AE3BEA134034B733C128F",
                            // MAC
                            "64B3C0D742B9F4A8"
                    ),
                    Arguments.of(
                            // Key
                            new CustomBitSet("1B90D9C9AEE3A9ADF9938F6084D19344"),
                            // Data
                            "24EE4A2AB303D2D5CA4BEFE3DC74DE42E05D30716DFD099D45033F5897E4AF52",
                            // MAC
                            "ED390835504E04B7"
                    )
            );
        }
    }

}
