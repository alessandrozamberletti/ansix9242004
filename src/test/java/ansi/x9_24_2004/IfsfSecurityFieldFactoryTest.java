package ansi.x9_24_2004;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.TestInstance;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

import java.util.stream.Stream;

@SuppressWarnings({"java:S1192"})
public class IfsfSecurityFieldFactoryTest {

    @Nested
    @TestInstance(TestInstance.Lifecycle.PER_CLASS)
    class WhenEncryptRequestData2004MethodIsCalled {

        @ParameterizedTest(name = "Should encrypt data (2004) for KSN: \"{2}\".")
        @MethodSource("getDataKsnAndExpectedEncryptedData")
        void shouldEncryptRequestData(final String bdk,
                                      final String plainData,
                                      final String ksn,
                                      final String expectedEncryptedData) {
            // Given
            final IfsfSecurityFieldFactory ifsfSecurityFieldFactory = new IfsfSecurityFieldFactory(bdk);

            // When
            final String encryptedRequestData = ifsfSecurityFieldFactory.encryptRequestData2004(ksn, plainData);

            // Then
            Assertions.assertEquals(expectedEncryptedData, encryptedRequestData);
        }

        Stream<Arguments> getDataKsnAndExpectedEncryptedData() {
            return Stream.of(
                    Arguments.of(
                            "BDBD1234BDBD567890ABBDBDCDEFBDBD", // BDK
                            "020010353431333333393030303030313531330E000431343132000000000000", // Plain data
                            "FFFF9876543210E01E9D", // KSN
                            "534BD2AF5E5F208DBD66AE6D371D5543EFCF74FB528DCBB17CEA6BD4708AE3A9" // Encrypted data
                    ),
                    Arguments.of(
                            "BDBD1234BDBD567890ABBDBDCDEFBDBD", // BDK
                            "", // Plain data
                            "FFFF9876543210E01E9D", // KSN
                            "" // Encrypted data
                    ),
                    Arguments.of(
                            "BDBD1234BDBD567890ABBDBDCDEFBDBD", // BDK
                            "020010353232363630393930303032363239300E000432303034230025353232363630393930303032363239303D3230303432303130313836373031313030303030000000000000", // Plain data
                            "FFFF9876543210E01E9D", // KSN
                            "08CF84A121C36ABD4C2404E00A4A20B56DAA50B208B1247B4174A6FE0594567BAED7DE256089F2E838BDF45AB0053D259DA7B6FAF8E4C729718F3400256A4B02312E5C87242B4AB1" // Encrypted data
                    )
            );
        }

    }

    @Nested
    @TestInstance(TestInstance.Lifecycle.PER_CLASS)
    class WhenEncryptRequestData2009MethodIsCalled {

        @ParameterizedTest(name = "Should encrypt data (2009) for KSN: \"{2}\".")
        @MethodSource("getDataKsnAndExpectedEncryptedData")
        void shouldEncryptRequestData(final String bdk,
                                      final String plainData,
                                      final String ksn,
                                      final String expectedEncryptedData) {
            // Given
            final IfsfSecurityFieldFactory ifsfSecurityFieldFactory = new IfsfSecurityFieldFactory(bdk);

            // When
            final String encryptedRequestData = ifsfSecurityFieldFactory.encryptRequestData2009(ksn, plainData);

            // Then
            Assertions.assertEquals(expectedEncryptedData, encryptedRequestData);
        }

        Stream<Arguments> getDataKsnAndExpectedEncryptedData() {
            return Stream.of(
                    Arguments.of(
                            "BDBD1234BDBD567890ABBDBDCDEFBDBD", // BDK
                            "020010353431333333393030303030313531330E000431343132000000000000", // Plain data
                            "FFFF9876543210E01E9D", // KSN
                            "D9D60AB25BF3CADB98BB302BDFF46E18936B6C6BD03F1FFE7161113E5D8DEAC8" // Encrypted data
                    ),
                    Arguments.of(
                            "BDBD1234BDBD567890ABBDBDCDEFBDBD", // BDK
                            "020010353431333333393030303030313531330E00063037313233312300243534313333333930303030303135313344343931323630313030303030303030303030300000000000", // Plain data
                            "FFFF9876543210E01E99", // KSN
                            "C7471B773CC940C386D16D68995B125597C38B977F9AD11D769F59E7B868E538AE7F22B1E6A8E3C9584C0021D51A0ECB8C3807B46200EE6EC0F73587B458EE56490A2DB4FDB92A4A" // Encrypted data
                    ),
                    Arguments.of(
                            "BDBD1234BDBD567890ABBDBDCDEFBDBD", // BDK
                            "020010353431333333393030303030313531330E00063037313233312300243534313333333930303030303135313344343931323630313030303030303030303030300000000000", // Plain data
                            "FFFF9876543210E022B0", // KSN
                            "7D90934CDFF4B0CF383F54FA2FF5A220CDFB4B097E4A565AB2699CB718F85104EFA78169AB6D5951BE3FDF6387A992FFAD9A703137CA6076BA0E0A143684B998DB4F4A409F2CA615" // Encrypted data
                    ),
                    Arguments.of(
                            "0123456789ABCDEFFEDCBA9876543210", // BDK
                            "020010353431333333393030303030313531330E00063037313233312300243534313333333930303030303135313344343931323630313030303030303030303030308000000000", // Plain data (padded method 2)
                            "FFFF9876543210E022B0", // KSN
                            "713D5DC33D3D6E0730B05899E8EE062F04101F7EE55A5B294F46D1C7D098B43860E41DDF4DF2E5D6C489D418D54A07B1D9C2E9254F60E52EF3AE4EC45B643EA32DD7532975312F32" // Encrypted data
                    )
            );
        }

    }

    @Nested
    @TestInstance(TestInstance.Lifecycle.PER_CLASS)
    class WhenDecryptRequest2004DataMethodIsCalled {

        @ParameterizedTest(name = "Should decrypt data (2004) for KSN: \"{2}\".")
        @MethodSource("getDataKsnAndExpectedDecryptedData")
        void shouldDecryptRequestData(final String bdk,
                                      final String plainData,
                                      final String ksn,
                                      final String expectedEncryptedData) {
            // Given
            final IfsfSecurityFieldFactory ifsfSecurityFieldFactory = new IfsfSecurityFieldFactory(bdk);

            // When
            final String encryptedRequestData = ifsfSecurityFieldFactory.decryptRequestData2004(ksn, plainData);

            // Then
            Assertions.assertEquals(expectedEncryptedData, encryptedRequestData);
        }

        Stream<Arguments> getDataKsnAndExpectedDecryptedData() {
            return Stream.of(
                    Arguments.of(
                            "BDBD1234BDBD567890ABBDBDCDEFBDBD", // BDK
                            "E5168D2DC89002E5F96C7A243057401BA4464FFE5315563BEC3B7A613D4B7526", // Encrypted data
                            "FFFF9876543210E02279", // KSN
                            "020013363739393939303130303030303030303031390E000431343132000000" // Plain data
                    ),
                    Arguments.of(
                            "BDBD1234BDBD567890ABBDBDCDEFBDBD", // BDK
                            "9BBB88CE00BD935B2E786C9A7CA13D629BBCE3EB98ABAE51BFECE759A48EBFAF", // Encrypted data
                            "FFFF9876543210E02280", // KSN
                            "020013363739393939303130303030303030303031390E000431343132000000" // Plain data
                    ),
                    Arguments.of(
                            "BDBD1234BDBD567890ABBDBDCDEFBDBD", // BDK
                            "081C58A0AE337A92733EE8F44408AED15113E714DE814D8C7E6B76A8910344EAA1614B71A62BB8DBFCC773A394756C0BD836C43D6058272C569FE17CE51F35C58180C3266CD30805", // Encrypted data
                            "FFFF9876543210E01E9F", // KSN
                            "020010353431333333393030303030313531330E00063037313233312300243534313333333930303030303135313344343931323630313030303030303030303030300000000000" // Plain data
                    )
            );
        }

    }

    @Nested
    @TestInstance(TestInstance.Lifecycle.PER_CLASS)
    class WhenCalculateRequestMacMethodIsCalled {

        @ParameterizedTest(name = "Should compute MAC for KSN: \"{2}\".")
        @MethodSource("getMessageHashKsnAndExpectedMac")
        void shouldCalculateRequestMac(final String bdk,
                                       final String messageHash,
                                       final String ksn,
                                       final String expectedMac) {
            // Given
            final IfsfSecurityFieldFactory ifsfSecurityFieldFactory = new IfsfSecurityFieldFactory(bdk);

            // When
            final String requestMac = ifsfSecurityFieldFactory.calculateRequestMac(ksn, messageHash);

            // Then
            Assertions.assertEquals(expectedMac, requestMac);
        }

        Stream<Arguments> getMessageHashKsnAndExpectedMac() {
            return Stream.of(
                    Arguments.of(
                            "BDBD1234BDBD567890ABBDBDCDEFBDBD", // BDK
                            "2C37F1179040F7E7D7BFF535DEEA4B19A50FD9C4E72AE3BEA134034B733C128F", // Data
                            "FFFF9876543210E01E9D", // KSN
                            "64B3C0D742B9F4A8" // MAC
                    ),
                    Arguments.of(
                            "BDBD1234BDBD567890ABBDBDCDEFBDBD", // BDK
                            "24EE4A2AB303D2D5CA4BEFE3DC74DE42E05D30716DFD099D45033F5897E4AF52", // Data
                            "FFFF9876543210E00000", // KSN
                            "ED390835504E04B7" // MAC
                    ),
                    Arguments.of(
                            "BDBD1234BDBD567890ABBDBDCDEFBDBD", // BDK
                            "24556429C96772A9D98AF4BC2BB4D8F20B79A75CCB5B5B44B8395FBC76C8C7BA", // Data
                            "FFFF9876543210E01E99", // KSN
                            "25A3D3D9C07AC3A6" // MAC
                    ),
                    Arguments.of(
                            "BDBD1234BDBD567890ABBDBDCDEFBDBD", // BDK
                            "B12557DC341A0EB357EE5F24499D0745E41065E30486C38E65E9F2881ADA5EB8", // Data
                            "FFFF9876543210E022B0", // KSN
                            "FCCCA5E097A3A67F" // MAC
                    ),
                    Arguments.of(
                            "0123456789ABCDEFFEDCBA9876543210", // BDK
                            "B12557DC341A0EB357EE5F24499D0745E41065E30486C38E65E9F2881ADA5EB8", // Data
                            "FFFF9876543210E022B0", // KSN
                            "5CD1E77B373F7DD4" // MAC
                    )
            );
        }

    }

    @Nested
    @TestInstance(TestInstance.Lifecycle.PER_CLASS)
    class WhenEncryptIso0PinBlockMethodIsCalled {

        @ParameterizedTest(name = "Should encrypt ISO-0 pin block for KSN: \"{2}\".")
        @MethodSource("getIso0PinBlockKsnAndExpectedEncryptedIso0PinBlock")
        void shouldEncryptIso0PinBlock(final String bdk,
                                       final String iso0PinBlock,
                                       final String ksn,
                                       final String expectedEncryptedIso0PinBlock) {
            // Given
            final IfsfSecurityFieldFactory ifsfSecurityFieldFactory = new IfsfSecurityFieldFactory(bdk);

            // When
            final String actualEncryptedIso0PinBlock = ifsfSecurityFieldFactory.encryptIso0PinBlock(ksn, iso0PinBlock);

            // Then
            Assertions.assertEquals(expectedEncryptedIso0PinBlock, actualEncryptedIso0PinBlock);
        }

        Stream<Arguments> getIso0PinBlockKsnAndExpectedEncryptedIso0PinBlock() {
            return Stream.of(
                    Arguments.of(
                            "BDBD1234BDBD567890ABBDBDCDEFBDBD", // BDK
                            "0612076FFFFFFEAE", // Clear ISO-0 PIN
                            "FFFF9876543210E01E9D", // KSN
                            "55025D81E85C8BF9" // Encrypted ISO-0 PIN
                    ),
                    Arguments.of(
                            "BDBD1234BDBD567890ABBDBDCDEFBDBD", // BDK
                            "0612076FFFFFFEAE", // Clear ISO-0 PIN
                            "FFFF9876543210E01E9F", // KSN
                            "BC0E47A5906B585D" // Encrypted ISO-0 PIN
                    ),
                    Arguments.of(
                            "BDBD1234BDBD567890ABBDBDCDEFBDBD", // BDK
                            "0612076FFFFFFEAE", // Clear ISO-0 PIN
                            "FFFF9876543210E022B0", // KSN
                            "19FCB1CFEC414F4F" // Encrypted ISO-0 PIN
                    ),
                    Arguments.of(
                            "BDBD1234BDBD567890ABBDBDCDEFBDBD", // BDK
                            "06123556FFFFFFFE", // Clear ISO-0 PIN
                            "FFFF9876543210E02279", // KSN
                            "C66EE1542E0A5018" // Encrypted ISO-0 PIN
                    ),
                    Arguments.of(
                            "BDBD1234BDBD567890ABBDBDCDEFBDBD", // BDK
                            "0612525F6FFFD9D6", // Clear ISO-0 PIN
                            "FFFF98765434E7E00001", // KSN
                            "E7AEE225B1849123" // Encrypted ISO-0 PIN
                    )
            );
        }

    }

    @Nested
    @TestInstance(TestInstance.Lifecycle.PER_CLASS)
    class WhenDecryptIso0PinBlockMethodIsCalled {

        @ParameterizedTest(name = "Should decrypt ISO-0 pin block for KSN: \"{2}\".")
        @MethodSource("getIso0PinBlockPanKsnAndClearIso0Pin")
        void shouldDecryptRequestData(final String bdk,
                                      final String encryptedIso0Pin,
                                      final String ksn,
                                      final String expectedClearIso0Pin) {
            // Given
            final IfsfSecurityFieldFactory ifsfSecurityFieldFactory = new IfsfSecurityFieldFactory(bdk);

            // When
            final String actualClearIso0Pin = ifsfSecurityFieldFactory.decryptIso0PinBlock(ksn, encryptedIso0Pin);

            // Then
            Assertions.assertEquals(expectedClearIso0Pin, actualClearIso0Pin);
        }

        Stream<Arguments> getIso0PinBlockPanKsnAndClearIso0Pin() {
            return Stream.of(
                    Arguments.of(
                            "BDBD1234BDBD567890ABBDBDCDEFBDBD", // BDK
                            "55025D81E85C8BF9", // Encrypted ISO-0 PIN
                            "FFFF9876543210E01E9D", // KSN
                            "0612076FFFFFFEAE" // Clear ISO-0 PIN
                    ),
                    Arguments.of(
                            "BDBD1234BDBD567890ABBDBDCDEFBDBD", // BDK
                            "BC0E47A5906B585D", // Encrypted ISO-0 PIN
                            "FFFF9876543210E01E9F", // KSN
                            "0612076FFFFFFEAE" // Clear ISO-0 PIN
                    ),
                    Arguments.of(
                            "BDBD1234BDBD567890ABBDBDCDEFBDBD", // BDK
                            "19FCB1CFEC414F4F", // Encrypted ISO-0 PIN
                            "FFFF9876543210E022B0", // KSN
                            "0612076FFFFFFEAE" // Clear ISO-0 PIN
                    ),
                    Arguments.of(
                            "BDBD1234BDBD567890ABBDBDCDEFBDBD", // BDK
                            "C66EE1542E0A5018", // Encrypted ISO-0 PIN
                            "FFFF9876543210E02279", // KSN
                            "06123556FFFFFFFE" // Clear ISO-0 PIN
                    ),
                    Arguments.of(
                            "BDBD1234BDBD567890ABBDBDCDEFBDBD", // BDK
                            "8D186C31884B1120", // Encrypted ISO-0 PIN
                            "FFFF98765434E8200001", // KSN
                            "06123556FFFFFFFE" // Clear ISO-0 PIN
                    )
            );
        }

    }

    @Nested
    @TestInstance(TestInstance.Lifecycle.PER_CLASS)
    class WhenDecryptFixedMethodIsCalled {

        @ParameterizedTest(name = "Should decrypt using fixed key for KEY: \"{0}\".")
        @MethodSource("getFixedKeyEncryptedDataAndExpectedPlainData")
        void shouldDecryptUsingFixedKey(final String key,
                                        final String encryptedData,
                                        final String expectedPlainData) {
            // Given
            final IfsfSecurityFieldFactory ifsfSecurityFieldFactory = new IfsfSecurityFieldFactory("ABCDEFABCDEFABCDEFABCDEFABCDEFAB");

            // When
            final String actualClearData = ifsfSecurityFieldFactory.decryptFixed(key, encryptedData);

            // Then
            Assertions.assertEquals(expectedPlainData, actualClearData);
        }

        Stream<Arguments> getFixedKeyEncryptedDataAndExpectedPlainData() {
            return Stream.of(
                    Arguments.of(
                            "43CD51408CB629DC195B52A292D538B3", // Fixed key
                            "A1485CDD1C68FA02", // Encrypted fixed PIN block
                            "04439CFFFFFF8FFE" // Plain PIN block
                    ),
                    Arguments.of(
                            "43CD51408CB629DC195B52A292D538B3", // Fixed key
                            "F88FCA91735E882A", // Encrypted fixed PIN block
                            "0612525F6FFFD9D6" // Plain PIN block
                    )
            );
        }

    }

    @Nested
    @TestInstance(TestInstance.Lifecycle.PER_CLASS)
    class WhenEncryptFixedMethodIsCalled {

        @ParameterizedTest(name = "Should encrypt using fixed key for KEY: \"{0}\".")
        @MethodSource("getFixedKeyEncryptedDataAndExpectedPlainData")
        void shouldEncryptUsingFixedKey(final String key,
                                        final String data,
                                        final String expectedEncryptedData) {
            // Given
            final IfsfSecurityFieldFactory ifsfSecurityFieldFactory = new IfsfSecurityFieldFactory("ABCDEFABCDEFABCDEFABCDEFABCDEFAB");

            // When
            final String actualClearData = ifsfSecurityFieldFactory.encryptFixed(key, data);

            // Then
            Assertions.assertEquals(expectedEncryptedData, actualClearData);
        }

        Stream<Arguments> getFixedKeyEncryptedDataAndExpectedPlainData() {
            return Stream.of(
                    Arguments.of(
                            "43CD51408CB629DC195B52A292D538B3", // Fixed key
                            "06123556FFFFFFFE", // Clear ISO-0 PIN block
                            "18139637BE9AFB2B" // Encrypted PIN block
                    )
            );
        }

    }

}
