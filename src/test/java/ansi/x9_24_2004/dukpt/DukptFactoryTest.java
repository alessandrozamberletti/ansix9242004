package ansi.x9_24_2004.dukpt;

import ansi.x9_24_2004.encryption.Des;
import ansi.x9_24_2004.encryption.TripleDes;
import ansi.x9_24_2004.utils.CustomBitSet;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.TestInstance;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

import java.util.stream.Stream;

@SuppressWarnings({"java:S1192"})
public class DukptFactoryTest {

    private DukptFactory dukptFactory;

    @BeforeEach
    void init() {
        this.dukptFactory = new DukptFactory(new Des(), new TripleDes());
    }

    @Nested
    @TestInstance(TestInstance.Lifecycle.PER_CLASS)
    class WhenGetIpekMethodIsCalled {

        @ParameterizedTest
        @MethodSource("getBdkKsnAndExpectedIpek")
        void shouldCreateExpectedIpek(final String bdk,
                                      final String ksn,
                                      final String expectedIpek) {
            // Given
            // When
            final CustomBitSet ipek = dukptFactory.getIpek(new CustomBitSet(bdk), new CustomBitSet(ksn));

            // Then
            Assertions.assertEquals(expectedIpek, ipek.toString());
        }

        Stream<Arguments> getBdkKsnAndExpectedIpek() {
            return Stream.of(
                    Arguments.of("BDBD1234BDBD567890ABBDBDCDEFBDBD", "FFFF9876543210E01E9D", "1B90D9C9AEE356ADF9938F6084D16C44"),
                    Arguments.of("BDBD1234BDBD567890ABBDBDCDEFBDBD", "FFFF9876543210E00000", "1B90D9C9AEE356ADF9938F6084D16C44"),
                    Arguments.of("BDBD1234BDBD567890ABBDBDCDEFBDBD", "FFFF9876543210E01E99", "1B90D9C9AEE356ADF9938F6084D16C44"),
                    Arguments.of("BDBD1234BDBD567890ABBDBDCDEFBDBD", "FFFF9876543210E022B1", "1B90D9C9AEE356ADF9938F6084D16C44"),
                    Arguments.of("BDBD1234BDBD567890ABBDBDCDEFBDBD", "FFFF9876543210E022BB", "1B90D9C9AEE356ADF9938F6084D16C44")
            );
        }

    }

    @Nested
    @TestInstance(TestInstance.Lifecycle.PER_CLASS)
    class WhenDeriveTransactionKeyMethodIsCalled {

        @ParameterizedTest
        @MethodSource("getIpekKsnAndExpectedSessionKey")
        void shouldCreateExpectedSessionKey(final String ipek,
                                            final String ksn,
                                            final String expectedSessionKey) {
            // Given
            // When
            final CustomBitSet transactionKey = dukptFactory.deriveSessionKey(new CustomBitSet(ipek), new CustomBitSet(ksn));

            // Then
            Assertions.assertEquals(expectedSessionKey, transactionKey.toString());
        }

        Stream<Arguments> getIpekKsnAndExpectedSessionKey() {
            return Stream.of(
                    Arguments.of("1B90D9C9AEE356ADF9938F6084D16C44", "FFFF9876543210E01E9D", "0258F3E777F55F61241AE65234583B30"),
                    Arguments.of("1B90D9C9AEE356ADF9938F6084D16C44", "FFFF9876543210E01E99", "931A8CF00C1829DE28E5AA70F3417D68"),
                    Arguments.of("1B90D9C9AEE356ADF9938F6084D16C44", "FFFF9876543210E022B0", "240DAEBB19C6941DDC2708893377F844"),
                    Arguments.of("1B90D9C9AEE356ADF9938F6084D16C44", "FFFF9876543210E022BB", "DE2623E85CCAFD815CEB8D828A6438A2")
            );
        }

    }

    @Nested
    @TestInstance(TestInstance.Lifecycle.PER_CLASS)
    class WhenComputeKeyVariantMethodIsCalled {

        @ParameterizedTest(name = "Should create key {3} for mask {2}.")
        @MethodSource("getMaskAndExpectedKey")
        void shouldComputeExpectedKeyVariant(final String bdk,
                                             final String ksn,
                                             final IfsfKeyMask ifsfKeyMask,
                                             final String expectedKey) {
            // Given
            // When
            final CustomBitSet actualKey = dukptFactory.computeKey(new CustomBitSet(bdk), new CustomBitSet(ksn), ifsfKeyMask);

            // Then
            Assertions.assertEquals(expectedKey, actualKey.toString());
        }

        Stream<Arguments> getMaskAndExpectedKey() {
            return Stream.of(
                    Arguments.of("BDBD1234BDBD567890ABBDBDCDEFBDBD", "FFFF9876543210E01E9D", IfsfKeyMask.REQUEST_DATA_MASK, "0258F3E7770A5F61241AE65234A73B30"),
                    Arguments.of("BDBD1234BDBD567890ABBDBDCDEFBDBD", "FFFF9876543210E01E9D", IfsfKeyMask.REQUEST_MAC_MASK, "0258F3E777F5A061241AE6523458C430"),
                    Arguments.of("BDBD1234BDBD567890ABBDBDCDEFBDBD", "FFFF9876543210E01E9D", IfsfKeyMask.REQUEST_PIN_MASK, "0258F3E777F55F9E241AE65234583BCF"),
                    Arguments.of("BDBD1234BDBD567890ABBDBDCDEFBDBD", "FFFF9876543210E01E99", IfsfKeyMask.REQUEST_DATA_MASK, "931A8CF00CE729DE28E5AA70F3BE7D68"),
                    Arguments.of("BDBD1234BDBD567890ABBDBDCDEFBDBD", "FFFF9876543210E01E99", IfsfKeyMask.REQUEST_MAC_MASK, "931A8CF00C18D6DE28E5AA70F3418268"),
                    Arguments.of("BDBD1234BDBD567890ABBDBDCDEFBDBD", "FFFF9876543210E01E99", IfsfKeyMask.REQUEST_PIN_MASK, "931A8CF00C18292128E5AA70F3417D97"),
                    Arguments.of("BDBD1234BDBD567890ABBDBDCDEFBDBD", "FFFF9876543210E00000", IfsfKeyMask.REQUEST_MAC_MASK, "1B90D9C9AEE3A9ADF9938F6084D19344"),
                    Arguments.of("BDBD1234BDBD567890ABBDBDCDEFBDBD", "FFFF9876543210E022B0", IfsfKeyMask.REQUEST_PIN_MASK, "240DAEBB19C694E2DC2708893377F8BB"),
                    Arguments.of("BDBD1234BDBD567890ABBDBDCDEFBDBD", "FFFF9876543210E022B0", IfsfKeyMask.REQUEST_MAC_MASK, "240DAEBB19C66B1DDC27088933770744"),
                    Arguments.of("BDBD1234BDBD567890ABBDBDCDEFBDBD", "FFFF9876543210E022B0", IfsfKeyMask.REQUEST_DATA_MASK, "240DAEBB1939941DDC2708893388F844"),
                    Arguments.of("BDBD1234BDBD567890ABBDBDCDEFBDBD", "FFFF9876543210E022B0", IfsfKeyMask.RESPONSE_MAC_MASK, "240DAEBBE6C6941DDC270889CC77F844"),
                    Arguments.of("BDBD1234BDBD567890ABBDBDCDEFBDBD", "FFFF9876543210E022BB", IfsfKeyMask.REQUEST_PIN_MASK, "DE2623E85CCAFD7E5CEB8D828A64385D"),
                    Arguments.of("BDBD1234BDBD567890ABBDBDCDEFBDBD", "FFFF9876543210E022BB", IfsfKeyMask.REQUEST_MAC_MASK, "DE2623E85CCA02815CEB8D828A64C7A2"),
                    Arguments.of("BDBD1234BDBD567890ABBDBDCDEFBDBD", "FFFF9876543210E022BB", IfsfKeyMask.REQUEST_DATA_MASK, "DE2623E85C35FD815CEB8D828A9B38A2"),
                    Arguments.of("BDBD1234BDBD567890ABBDBDCDEFBDBD", "FFFF9876543210E022BB", IfsfKeyMask.RESPONSE_MAC_MASK, "DE2623E8A3CAFD815CEB8D82756438A2")
            );
        }
    }

    @Nested
    @TestInstance(TestInstance.Lifecycle.PER_CLASS)
    class WhenComputeAnsiX924version2009DataKeyMethodIsCalled {

        @ParameterizedTest
        @MethodSource("getBdkKsnAndExpected2009DataKey")
        void shouldCreateExpected2009DataKey(final String bdk,
                                             final String ksn,
                                             final String expectedKey) {
            // Given
            // When
            final CustomBitSet ansiX924version2009DataKey = dukptFactory.computeAnsiX924version2009DataKey(new CustomBitSet(bdk), new CustomBitSet(ksn));

            // Then
            Assertions.assertEquals(expectedKey, ansiX924version2009DataKey.toString());
        }

        Stream<Arguments> getBdkKsnAndExpected2009DataKey() {
            return Stream.of(
                    Arguments.of("BDBD1234BDBD567890ABBDBDCDEFBDBD", "FFFF9876543210E01E9D", "37A2F17ACF991C65DE530197AA1ACC2B"),
                    Arguments.of("BDBD1234BDBD567890ABBDBDCDEFBDBD", "FFFF9876543210E01E99", "A0B9D255BABF9DDBF01CDD32769CCA2B"),
                    Arguments.of("BDBD1234BDBD567890ABBDBDCDEFBDBD", "FFFF9876543210E022B0", "97528F277251355DF77BCAF41F0E56A2"),
                    Arguments.of("BDBD1234BDBD567890ABBDBDCDEFBDBD", "FFFF9876543210E022BB", "ECCFC46CB1ABB55D272F31361B85E179")
            );
        }

    }

}
