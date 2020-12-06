package ansi.x9_24_2004;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

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
    class WhenCalculateRequestMacMethodIsCalled {

        @Test
        void shouldCalculateRequestMac() {
            // Given
            final String messageHash = "2C37F1179040F7E7D7BFF535DEEA4B19A50FD9C4E72AE3BEA134034B733C128F";
            final String ksn = "FFFF9876543210E01E9D";

            // When
            final String requestMac = dataProcessor.calculateRequestMac(ksn, messageHash);

            // Then
            Assertions.assertEquals("64B3C0D742B9F4A8", requestMac);
        }

    }

}
