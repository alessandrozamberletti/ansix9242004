package ansi.x9_24_2004.dukpt;

import ansi.x9_24_2004.encryption.Des;
import ansi.x9_24_2004.encryption.TripleDes;
import ansi.x9_24_2004.utils.BitArray;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.TestInstance;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

import java.util.stream.Stream;

@SuppressWarnings({"java:S1192"})
public class DukptFactoryTest {

    private final DukptFactory dukptFactory = new DukptFactory(new Des(), new TripleDes());

    @Nested
    @TestInstance(TestInstance.Lifecycle.PER_CLASS)
    class WhenGetIpekMethodIsCalled {

        @ParameterizedTest(name = "Should return IPEK: \"{2}\".")
        @MethodSource("getBdkKsnAndExpectedIpek")
        void shouldCreateExpectedIpek(final String bdk,
                                      final String ksn,
                                      final String expectedIpek) {
            // Given
            // When
            final BitArray ipek = dukptFactory.getIpek(new BitArray(bdk), new BitArray(ksn));

            // Then
            Assertions.assertEquals(expectedIpek, ipek.toString());
        }

        Stream<Arguments> getBdkKsnAndExpectedIpek() {
            return Stream.of(
                    Arguments.of(
                            "BDBD1234BDBD567890ABBDBDCDEFBDBD", // BDK
                            "FFFF9876543210E01E9D", // KSN
                            "1B90D9C9AEE356ADF9938F6084D16C44" // IPEK
                    ),
                    Arguments.of(
                            "BDBD1234BDBD567890ABBDBDCDEFBDBD", // BDK
                            "FFFF9876543210E00000", // KSN
                            "1B90D9C9AEE356ADF9938F6084D16C44" // IPEK
                    ),
                    Arguments.of(
                            "BDBD1234BDBD567890ABBDBDCDEFBDBD", // BDK
                            "FFFF9876543210E01E99", // KSN
                            "1B90D9C9AEE356ADF9938F6084D16C44" // IPEK
                    ),
                    Arguments.of(
                            "BDBD1234BDBD567890ABBDBDCDEFBDBD", // BDK
                            "FFFF9876543210E022B1", // KSN
                            "1B90D9C9AEE356ADF9938F6084D16C44" // IPEK
                    ),
                    Arguments.of(
                            "BDBD1234BDBD567890ABBDBDCDEFBDBD", // BDK
                            "FFFF9876543210E022BB", // KSN
                            "1B90D9C9AEE356ADF9938F6084D16C44" // IPEK
                    )
            );
        }

    }

    @Nested
    @TestInstance(TestInstance.Lifecycle.PER_CLASS)
    class WhenDeriveTransactionKeyMethodIsCalled {

        @ParameterizedTest(name = "Should return session key: \"{2}\".")
        @MethodSource("getIpekKsnAndExpectedSessionKey")
        void shouldCreateExpectedSessionKey(final String ipek,
                                            final String ksn,
                                            final String expectedSessionKey) {
            // Given
            // When
            final BitArray transactionKey =
                    dukptFactory.deriveSessionKey(new BitArray(ipek), new BitArray(ksn));

            // Then
            Assertions.assertEquals(expectedSessionKey, transactionKey.toString());
        }

        Stream<Arguments> getIpekKsnAndExpectedSessionKey() {
            return Stream.of(
                    Arguments.of(
                            "1B90D9C9AEE356ADF9938F6084D16C44", // BDK
                            "FFFF9876543210E01E9D", // KSN
                            "0258F3E777F55F61241AE65234583B30" // Session key
                    ),
                    Arguments.of(
                            "1B90D9C9AEE356ADF9938F6084D16C44", // BDK
                            "FFFF9876543210E01E99", // KSN
                            "931A8CF00C1829DE28E5AA70F3417D68" // Session key
                    ),
                    Arguments.of(
                            "1B90D9C9AEE356ADF9938F6084D16C44", // BDK
                            "FFFF9876543210E022B0", // KSN
                            "240DAEBB19C6941DDC2708893377F844" // Session key
                    ),
                    Arguments.of(
                            "1B90D9C9AEE356ADF9938F6084D16C44", // BDK
                            "FFFF9876543210E022BB", // KSN
                            "DE2623E85CCAFD815CEB8D828A6438A2" // Session key
                    )
            );
        }

    }

    @Nested
    @TestInstance(TestInstance.Lifecycle.PER_CLASS)
    class WhenComputeKeyVariantMethodIsCalled {

        @ParameterizedTest(name = "Should compute key: \"{3}\".")
        @MethodSource("getMaskAndExpectedKey")
        void shouldComputeExpectedKeyVariant(final String bdk,
                                             final String ksn,
                                             final IfsfKeyMask ifsfKeyMask,
                                             final String expectedKey) {
            // Given
            // When
            final BitArray actualKey =
                    dukptFactory.computeKey(new BitArray(bdk), new BitArray(ksn), ifsfKeyMask);

            // Then
            Assertions.assertEquals(expectedKey, actualKey.toString());
        }

        Stream<Arguments> getMaskAndExpectedKey() {
            return Stream.of(
                    Arguments.of(
                            "BDBD1234BDBD567890ABBDBDCDEFBDBD", // BDK
                            "FFFF9876543210E01E9D", // KSN
                            IfsfKeyMask.REQUEST_DATA_MASK, // Mask
                            "0258F3E7770A5F61241AE65234A73B30" // Key
                    ),
                    Arguments.of(
                            "BDBD1234BDBD567890ABBDBDCDEFBDBD", // BDK
                            "FFFF9876543210E01E9D", // KSN
                            IfsfKeyMask.REQUEST_MAC_MASK, // Mask
                            "0258F3E777F5A061241AE6523458C430" // Key
                    ),
                    Arguments.of(
                            "BDBD1234BDBD567890ABBDBDCDEFBDBD", // BDK
                            "FFFF9876543210E01E9D", // KSN
                            IfsfKeyMask.REQUEST_PIN_MASK, // Mask
                            "0258F3E777F55F9E241AE65234583BCF" // Key
                    ),
                    Arguments.of(
                            "BDBD1234BDBD567890ABBDBDCDEFBDBD", // BDK
                            "FFFF9876543210E01E99", // KSN
                            IfsfKeyMask.REQUEST_DATA_MASK, // Mask
                            "931A8CF00CE729DE28E5AA70F3BE7D68" // Key
                    ),
                    Arguments.of(
                            "BDBD1234BDBD567890ABBDBDCDEFBDBD", // BDK
                            "FFFF9876543210E01E99", // KSN
                            IfsfKeyMask.REQUEST_MAC_MASK, // Mask
                            "931A8CF00C18D6DE28E5AA70F3418268" // Key
                    ),
                    Arguments.of(
                            "BDBD1234BDBD567890ABBDBDCDEFBDBD", // BDK
                            "FFFF9876543210E01E99", // KSN
                            IfsfKeyMask.REQUEST_PIN_MASK, // Mask
                            "931A8CF00C18292128E5AA70F3417D97" // Key
                    ),
                    Arguments.of(
                            "BDBD1234BDBD567890ABBDBDCDEFBDBD", // BDK
                            "FFFF9876543210E00000", // KSN
                            IfsfKeyMask.REQUEST_MAC_MASK, // Mask
                            "1B90D9C9AEE3A9ADF9938F6084D19344" // Key
                    ),
                    Arguments.of(
                            "BDBD1234BDBD567890ABBDBDCDEFBDBD", // BDK
                            "FFFF9876543210E022B0", // KSN
                            IfsfKeyMask.REQUEST_PIN_MASK, // Mask
                            "240DAEBB19C694E2DC2708893377F8BB" // Key
                    ),
                    Arguments.of(
                            "BDBD1234BDBD567890ABBDBDCDEFBDBD", // BDK
                            "FFFF9876543210E022B0", // KSN
                            IfsfKeyMask.REQUEST_MAC_MASK, // Mask
                            "240DAEBB19C66B1DDC27088933770744" // Key
                    ),
                    Arguments.of(
                            "BDBD1234BDBD567890ABBDBDCDEFBDBD", // BDK
                            "FFFF9876543210E022B0", // KSN
                            IfsfKeyMask.REQUEST_DATA_MASK, // Mask
                            "240DAEBB1939941DDC2708893388F844" // Key
                    ),
                    Arguments.of(
                            "BDBD1234BDBD567890ABBDBDCDEFBDBD", // BDK
                            "FFFF9876543210E022B0", // KSN
                            IfsfKeyMask.RESPONSE_MAC_MASK, // Mask
                            "240DAEBBE6C6941DDC270889CC77F844" // Key
                    ),
                    Arguments.of(
                            "BDBD1234BDBD567890ABBDBDCDEFBDBD", // BDK
                            "FFFF9876543210E022BB", // KSN
                            IfsfKeyMask.REQUEST_PIN_MASK, // Mask
                            "DE2623E85CCAFD7E5CEB8D828A64385D" // Key
                    ),
                    Arguments.of(
                            "BDBD1234BDBD567890ABBDBDCDEFBDBD", // BDK
                            "FFFF9876543210E022BB", // KSN
                            IfsfKeyMask.REQUEST_MAC_MASK, // Mask
                            "DE2623E85CCA02815CEB8D828A64C7A2" // Key
                    ),
                    Arguments.of(
                            "BDBD1234BDBD567890ABBDBDCDEFBDBD", // BDK
                            "FFFF9876543210E022BB", // KSN
                            IfsfKeyMask.REQUEST_DATA_MASK, // Mask
                            "DE2623E85C35FD815CEB8D828A9B38A2" // Key
                    ),
                    Arguments.of(
                            "BDBD1234BDBD567890ABBDBDCDEFBDBD", // BDK
                            "FFFF9876543210E022BB", // KSN
                            IfsfKeyMask.RESPONSE_MAC_MASK, // Mask
                            "DE2623E8A3CAFD815CEB8D82756438A2" // Key
                    )
            );
        }
    }

    @Nested
    @TestInstance(TestInstance.Lifecycle.PER_CLASS)
    class WhenComputeAnsiX924version2009DataKeyMethodIsCalled {

        @ParameterizedTest(name = "Should compute data key: \"{2}\".")
        @MethodSource("getBdkKsnAndExpected2009DataKey")
        void shouldCreateExpected2009DataKey(final String bdk,
                                             final String ksn,
                                             final String expectedKey) {
            // Given
            // When
            final BitArray ansiX924version2009DataKey =
                    dukptFactory.computeAnsiX924version2009DataKey(new BitArray(bdk), new BitArray(ksn));

            // Then
            Assertions.assertEquals(expectedKey, ansiX924version2009DataKey.toString());
        }

        Stream<Arguments> getBdkKsnAndExpected2009DataKey() {
            return Stream.of(
                    Arguments.of(
                            "BDBD1234BDBD567890ABBDBDCDEFBDBD", // BDK
                            "FFFF9876543210E01E9D", // KSN
                            "37A2F17ACF991C65DE530197AA1ACC2B" // Data key
                    ),
                    Arguments.of(
                            "BDBD1234BDBD567890ABBDBDCDEFBDBD", // BDK
                            "FFFF9876543210E01E99", // KSN
                            "A0B9D255BABF9DDBF01CDD32769CCA2B" // Data key
                    ),
                    Arguments.of(
                            "BDBD1234BDBD567890ABBDBDCDEFBDBD", // BDK
                            "FFFF9876543210E022B0", // KSN
                            "97528F277251355DF77BCAF41F0E56A2" // Data key
                    ),
                    Arguments.of(
                            "BDBD1234BDBD567890ABBDBDCDEFBDBD", // BDK
                            "FFFF9876543210E022BB", // KSN
                            "ECCFC46CB1ABB55D272F31361B85E179" // Data key
                    )
            );
        }

    }

}
