package ansi.x9_24_2004.dukpt;

import ansi.x9_24_2004.encryption.Des;
import ansi.x9_24_2004.encryption.TripleDes;
import ansi.x9_24_2004.utils.CustomBitSet;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInstance;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

import java.util.stream.Stream;

public class DukptFactoryTest {

    private static final CustomBitSet BDK = new CustomBitSet("BDBD1234BDBD567890ABBDBDCDEFBDBD");
    private static final CustomBitSet KSN = new CustomBitSet("FFFF9876543210E01E9D");

    private DukptFactory dukptFactory;

    @BeforeEach
    void init() {
        this.dukptFactory = new DukptFactory(new Des(), new TripleDes());
    }

    @Nested
    class WhenGetIpekMethodIsCalled {

        @Test
        void shouldCreateExpectedIpek() {
            // Given
            // When
            final CustomBitSet ipek = dukptFactory.getIpek(BDK, KSN);

            // Then
            Assertions.assertEquals("1B90D9C9AEE356ADF9938F6084D16C44", ipek.toString());
        }

    }

    @Nested
    class WhenDeriveTransactionKeyMethodIsCalled {

        @Test
        void shouldCreateExpectedDukpt() {
            // Given
            final CustomBitSet ipek = new CustomBitSet("1B90D9C9AEE356ADF9938F6084D16C44");

            // When
            final CustomBitSet transactionKey = dukptFactory.deriveTransactionKey(ipek, KSN);

            // Then
            Assertions.assertEquals("0258F3E777F55F61241AE65234583B30", transactionKey.toString());
        }

    }

    @Nested
    @TestInstance(TestInstance.Lifecycle.PER_CLASS)
    class WhenComputeKeyVariantMethodIsCalled {

        @ParameterizedTest(name = "Should create key {1} for mask {0}.")
        @MethodSource("getMaskAndExpectedKey")
        void shouldComputeExpectedKeyVariant(final IfsfKeyMask ifsfKeyMask, final String expectedKey) {
            // Given
            // When
            final CustomBitSet actualKey = dukptFactory.computeKey(BDK, KSN, ifsfKeyMask);

            // Then
            Assertions.assertEquals(expectedKey, actualKey.toString());
        }

        Stream<Arguments> getMaskAndExpectedKey() {
            return Stream.of(
                    Arguments.of(IfsfKeyMask.REQUEST_DATA_MASK, "0258F3E7770A5F61241AE65234A73B30"),
                    Arguments.of(IfsfKeyMask.REQUEST_MAC_MASK, "0258F3E777F5A061241AE6523458C430"),
                    Arguments.of(IfsfKeyMask.REQUEST_PIN_MASK, "0258F3E777F55F9E241AE65234583BCF")
            );
        }
    }

    @Nested
    class WhenComputeAnsiX924version2009DataKeyMethodIsCalled {

        @Test
        void shouldCreateExpected2009DataKey() {
            // Given
            // When
            final CustomBitSet ansiX924version2009DataKey = dukptFactory.computeAnsiX924version2009DataKey(BDK, KSN);

            // Then
            Assertions.assertEquals("37A2F17ACF991C65DE530197AA1ACC2B", ansiX924version2009DataKey.toString());
        }

    }

}
