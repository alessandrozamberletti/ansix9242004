package ansi.x9_24_2004;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInstance;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

import java.util.stream.Stream;

public class DataProcessorTest {

    private DataProcessor dataProcessor;

    @BeforeEach
    void init() {
        this.dataProcessor = new DataProcessor("BDBD1234BDBD567890ABBDBDCDEFBDBD");
    }

    @Nested
    class WhenEncryptRequestDataMethodIsCalled {

        @Test
        void shouldEncryptRequestData() {
            // Given
            final String data = "020010353431333333393030303030313531330E000431343132000000000000";
            final String ksn = "FFFF9876543210E01E9D";

            // When
            final String encryptedRequestData = dataProcessor.encryptRequestData(ksn, data);

            // Then
            Assertions.assertEquals("534BD2AF5E5F208DBD66AE6D371D5543EFCF74FB528DCBB17CEA6BD4708AE3A9", encryptedRequestData);
        }

    }

    @Nested
    @TestInstance(TestInstance.Lifecycle.PER_CLASS)
    class WhenCalculateRequestMacMethodIsCalled {

        @ParameterizedTest
        @MethodSource("getMessageHashKsnAndExpectedMac")
        void shouldCalculateRequestMac(final String messageHash, final String ksn, final String expectedMac) {
            // Given
            // When
            final String requestMac = dataProcessor.calculateRequestMac(ksn, messageHash);

            // Then
            Assertions.assertEquals(expectedMac, requestMac);
        }

        Stream<Arguments> getMessageHashKsnAndExpectedMac() {
            return Stream.of(
                    Arguments.of("2C37F1179040F7E7D7BFF535DEEA4B19A50FD9C4E72AE3BEA134034B733C128F", "FFFF9876543210E01E9D", "64B3C0D742B9F4A8"),
                    Arguments.of("24EE4A2AB303D2D5CA4BEFE3DC74DE42E05D30716DFD099D45033F5897E4AF52", "FFFF9876543210E00000", "ED390835504E04B7")
            );
        }

    }

}
