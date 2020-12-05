package ansix9242004.dukpt;

import ansix9242004.encryption.Des;
import ansix9242004.encryption.TripleDes;
import ansix9242004.utils.BitSet;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInstance;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

import java.util.stream.Stream;

public class DukptTest {

    private static final BitSet BDK = BitSet.toBitSet("BDBD1234BDBD567890ABBDBDCDEFBDBD");
    private static final BitSet KSN = BitSet.toBitSet("FFFF9876543210E01E9D");

    private Dukpt dukpt;

    @BeforeEach
    void init() {
        this.dukpt = new Dukpt(new Des(), new TripleDes());
    }

    @Nested
    class WhenGetIpekMethodIsCalled {

        @Test
        void shouldCreateExpectedIpek() throws Exception {
            // Given
            // When
            final BitSet ipek = dukpt.getIpek(BDK, KSN);

            // Then
            Assertions.assertEquals("1B90D9C9AEE356ADF9938F6084D16C44", BitSet.toString(ipek));
        }

    }

    @Nested
    class WhenGetTransactionKeyMethodIsCalled {

        @Test
        void shouldCreateExpectedDukpt() throws Exception {
            // Given
            final BitSet ipek = BitSet.toBitSet("1B90D9C9AEE356ADF9938F6084D16C44");

            // When
            final BitSet transactionKey = dukpt.getCurrentKey(ipek, KSN);

            // Then
            Assertions.assertEquals("0258F3E777F55F61241AE65234583B30", BitSet.toString(transactionKey));
        }

    }

    @Nested
    @TestInstance(TestInstance.Lifecycle.PER_CLASS)
    class WhenComputeKeyVariantMethodIsCalled {

        @ParameterizedTest(name = "Should create key {1} for mask {0}.")
        @MethodSource("getMaskAndExpectedKey")
        void shouldComputeExpectedKeyVariant(final Mask mask, final String expectedKey) throws Exception {
            // Given
            // When
            final BitSet actualKey = dukpt.computeKey(BDK, KSN, mask);

            // Then
            Assertions.assertEquals(expectedKey, BitSet.toString(actualKey));
        }

        Stream<Arguments> getMaskAndExpectedKey() {
            return Stream.of(
                    Arguments.of(Mask.REQUEST_DATA_MASK, "0258F3E7770A5F61241AE65234A73B30"),
                    Arguments.of(Mask.REQUEST_MAC_MASK, "0258F3E777F5A061241AE6523458C430"),
                    Arguments.of(Mask.PIN_MASK, "0258F3E777F55F9E241AE65234583BCF")
            );
        }
    }

}
