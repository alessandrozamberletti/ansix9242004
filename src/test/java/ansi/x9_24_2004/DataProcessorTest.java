package ansi.x9_24_2004;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.TestInstance;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

import java.util.stream.Stream;

@SuppressWarnings({"java:S1192"})
public class DataProcessorTest {

    private DataProcessor dataProcessor;

    @BeforeEach
    void init() {
        this.dataProcessor = new DataProcessor("BDBD1234BDBD567890ABBDBDCDEFBDBD");
    }

    @Nested
    @TestInstance(TestInstance.Lifecycle.PER_CLASS)
    class WhenEncryptRequestDataMethodIsCalled {

        @ParameterizedTest(name = "Should compute encrypted data: \"{2}\" for plain data: \"{0}\" and ksn: \"{1}\".")
        @MethodSource("getDataKsnAndExpectedEncryptedData")
        void shouldEncryptRequestData(final String plainData,
                                      final String ksn,
                                      final String expectedEncryptedData) {
            // Given
            // When
            final String encryptedRequestData = dataProcessor.encryptRequestData(ksn, plainData);

            // Then
            Assertions.assertEquals(expectedEncryptedData, encryptedRequestData);
        }

        Stream<Arguments> getDataKsnAndExpectedEncryptedData() {
            return Stream.of(
                    Arguments.of(
                            // Plain data
                            "020010353431333333393030303030313531330E000431343132000000000000",
                            // KSN
                            "FFFF9876543210E01E9D",
                            // Encrypted data
                            "534BD2AF5E5F208DBD66AE6D371D5543EFCF74FB528DCBB17CEA6BD4708AE3A9"),
                    Arguments.of(
                            // Plain data
                            "",
                            // KSN
                            "FFFF9876543210E01E9D",
                            // Encrypted data
                            ""
                    )
            );
        }

    }

    @Nested
    @TestInstance(TestInstance.Lifecycle.PER_CLASS)
    class WhenCalculateRequestMacMethodIsCalled {

        @ParameterizedTest(name = "Should compute request MAC: \"{2}\" for data: \"{0}\" and ksn: \"{1}\".")
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
                    Arguments.of(
                            // Data
                            "2C37F1179040F7E7D7BFF535DEEA4B19A50FD9C4E72AE3BEA134034B733C128F",
                            // KSN
                            "FFFF9876543210E01E9D",
                            // MAC
                            "64B3C0D742B9F4A8"
                    ),
                    Arguments.of(
                            // Data
                            "24EE4A2AB303D2D5CA4BEFE3DC74DE42E05D30716DFD099D45033F5897E4AF52",
                            // KSN
                            "FFFF9876543210E00000",
                            // MAC
                            "ED390835504E04B7"
                    )
            );
        }

    }

}
