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

@SuppressWarnings({"java:S1192"})
public class IfsfSecurityFieldFactoryTest {

    private IfsfSecurityFieldFactory ifsfSecurityFieldFactory;

    @BeforeEach
    void init() {
        this.ifsfSecurityFieldFactory = new IfsfSecurityFieldFactory("BDBD1234BDBD567890ABBDBDCDEFBDBD");
    }

    @Nested
    @TestInstance(TestInstance.Lifecycle.PER_CLASS)
    class WhenEncryptRequestData2004MethodIsCalled {

        @ParameterizedTest(name = "Should compute encrypted data: \"{2}\" for plain data: \"{0}\" and ksn: \"{1}\".")
        @MethodSource("getDataKsnAndExpectedEncryptedData")
        void shouldEncryptRequestData(final String plainData,
                                      final String ksn,
                                      final String expectedEncryptedData) {
            // Given
            // When
            final String encryptedRequestData = ifsfSecurityFieldFactory.encryptRequestData2004(ksn, plainData);

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
                    ),
                    Arguments.of(
                            // Plain data
                            "020010353232363630393930303032363239300E000432303034230025353232363630393930303032363239303D3230303432303130313836373031313030303030000000000000",
                            // KSN
                            "FFFF9876543210E01E9D",
                            // Encrypted data
                            "08CF84A121C36ABD4C2404E00A4A20B56DAA50B208B1247B4174A6FE0594567BAED7DE256089F2E838BDF45AB0053D259DA7B6FAF8E4C729718F3400256A4B02312E5C87242B4AB1"
                    )
            );
        }

    }

    @Nested
    @TestInstance(TestInstance.Lifecycle.PER_CLASS)
    class WhenEncryptRequestData2009MethodIsCalled {

        @ParameterizedTest
        @MethodSource("getDataKsnAndExpectedEncryptedData")
        void shouldEncryptRequestData(final String plainData,
                                      final String ksn,
                                      final String expectedEncryptedData) {
            // Given
            // When
            final String encryptedRequestData = ifsfSecurityFieldFactory.encryptRequestData2009(ksn, plainData);

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
                            "D9D60AB25BF3CADB98BB302BDFF46E18936B6C6BD03F1FFE7161113E5D8DEAC8"
                    ),
                    Arguments.of(
                            // Plain data
                            "020010353431333333393030303030313531330E00063037313233312300243534313333333930303030303135313344343931323630313030303030303030303030300000000000",
                            // KSN
                            "FFFF9876543210E01E99",
                            // Encrypted data
                            "C7471B773CC940C386D16D68995B125597C38B977F9AD11D769F59E7B868E538AE7F22B1E6A8E3C9584C0021D51A0ECB8C3807B46200EE6EC0F73587B458EE56490A2DB4FDB92A4A"
                    )
            );
        }

    }

    @Nested
    @TestInstance(TestInstance.Lifecycle.PER_CLASS)
    class WhenDecryptRequest2004DataMethodIsCalled {

        @ParameterizedTest
        @MethodSource("getDataKsnAndExpectedDecryptedData")
        void shouldDecryptRequestData(final String plainData,
                                      final String ksn,
                                      final String expectedEncryptedData) {
            // Given
            // When
            final String encryptedRequestData = ifsfSecurityFieldFactory.decryptRequestData2004(ksn, plainData);

            // Then
            Assertions.assertEquals(expectedEncryptedData, encryptedRequestData);
        }

        Stream<Arguments> getDataKsnAndExpectedDecryptedData() {
            return Stream.of(
                    Arguments.of(
                            // Encrypted data
                            "E5168D2DC89002E5F96C7A243057401BA4464FFE5315563BEC3B7A613D4B7526",
                            // KSN
                            "FFFF9876543210E02279",
                            // Plain data
                            "020013363739393939303130303030303030303031390E000431343132000000"
                    ),
                    Arguments.of(
                            // Encrypted data
                            "9BBB88CE00BD935B2E786C9A7CA13D629BBCE3EB98ABAE51BFECE759A48EBFAF",
                            // KSN
                            "FFFF9876543210E02280",
                            // Plain data
                            "020013363739393939303130303030303030303031390E000431343132000000"
                    ),
                    Arguments.of(
                            // Encrypted data
                            "081C58A0AE337A92733EE8F44408AED15113E714DE814D8C7E6B76A8910344EAA1614B71A62BB8DBFCC773A394756C0BD836C43D6058272C569FE17CE51F35C58180C3266CD30805",
                            // KSN
                            "FFFF9876543210E01E9F",
                            // Plain data
                            "020010353431333333393030303030313531330E00063037313233312300243534313333333930303030303135313344343931323630313030303030303030303030300000000000"
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
            final String requestMac = ifsfSecurityFieldFactory.calculateRequestMac(ksn, messageHash);

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
                    ),
                    Arguments.of(
                            // Data
                            "24556429C96772A9D98AF4BC2BB4D8F20B79A75CCB5B5B44B8395FBC76C8C7BA",
                            // KSN
                            "FFFF9876543210E01E99",
                            // MAC
                            "25A3D3D9C07AC3A6"
                    )
            );
        }

    }

    @Nested
    @TestInstance(TestInstance.Lifecycle.PER_CLASS)
    class WhenEncryptIso0PinBlockMethodIsCalled {

        @ParameterizedTest
        @MethodSource("getIso0PinBlockKsnAndExpectedEncryptedIso0PinBlock")
        void shouldEncryptIso0PinBlock(final String iso0PinBlock, final String ksn, final String expectedEncryptedIso0PinBlock) {
            // Given
            // When
            final String actualEncryptedIso0PinBlock = ifsfSecurityFieldFactory.encryptIso0PinBlock(ksn, iso0PinBlock);

            // Then
            Assertions.assertEquals(expectedEncryptedIso0PinBlock, actualEncryptedIso0PinBlock);
        }

        Stream<Arguments> getIso0PinBlockKsnAndExpectedEncryptedIso0PinBlock() {
            return Stream.of(
                    Arguments.of(
                            "0612076FFFFFFEAE", // Clear ISO-0 PIN
                            "FFFF9876543210E01E9D", // KSN
                            "55025D81E85C8BF9" // Encrypted ISO-0 PIN
                    ),
                    Arguments.of(
                            "0612076FFFFFFEAE", // Clear ISO-0 PIN
                            "FFFF9876543210E01E9F", // KSN
                            "BC0E47A5906B585D" // Encrypted ISO-0 PIN
                    )
            );
        }

    }

    @Nested
    @TestInstance(TestInstance.Lifecycle.PER_CLASS)
    class WhenDecryptIso0PinBlockMethodIsCalled {

        @ParameterizedTest
        @MethodSource("getIso0PinBlockPanKsnAndClearIso0Pin")
        void shouldDecryptRequestData(final String encryptedIso0Pin,
                                      final String ksn,
                                      final String expectedClearIso0Pin) {
            // Given
            // When
            final String actualClearIso0Pin = ifsfSecurityFieldFactory.decryptIso0PinBlock(ksn, encryptedIso0Pin);

            // Then
            Assertions.assertEquals(expectedClearIso0Pin, actualClearIso0Pin);
        }

        Stream<Arguments> getIso0PinBlockPanKsnAndClearIso0Pin() {
            return Stream.of(
                    Arguments.of(
                            "55025D81E85C8BF9", // Encrypted ISO-0 PIN
                            "FFFF9876543210E01E9D", // KSN
                            "0612076FFFFFFEAE" // Clear ISO-0 PIN
                    ),
                    Arguments.of(
                            "BC0E47A5906B585D", // Encrypted ISO-0 PIN
                            "FFFF9876543210E01E9F", // KSN
                            "0612076FFFFFFEAE" // Clear ISO-0 PIN
                    )
            );
        }

    }

    @Nested
    class WhenDecryptFixedMethodIsCalled {

        @Test
        void shouldDecryptUsingFixedKey() {
            // Given
            final String key = "43CD51408CB629DC195B52A292D538B3";
            final String encryptedData = "A1485CDD1C68FA02";

            // When
            final String actualClearData = ifsfSecurityFieldFactory.decryptFixed(key, encryptedData);

            // Then
            Assertions.assertEquals("04439CFFFFFF8FFE", actualClearData);
        }

    }

}
