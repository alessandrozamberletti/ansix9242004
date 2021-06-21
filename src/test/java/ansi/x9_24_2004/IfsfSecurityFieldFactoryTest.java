package ansi.x9_24_2004;

import ansi.x9_24_2004.dukpt.IfsfKeyMask;
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
                    ),
                    Arguments.of(
                            "0123456789ABCDEFFEDCBA9876543210", // BDK
                            "020010353431333333393030303030313531330E000431343132000000000000", // Plain data
                            "FFFF9876543210E022B0", // KSN
                            "713D5DC33D3D6E0730B05899E8EE062F9B8B477EEBB1DBB2BD5E5075E88292AE" // Encrypted data
                    ),
                    Arguments.of(
                            "BDBD1234BDBD567890ABBDBDCDEFBDBD", // BDK
                            "020010353431333333393030303030313531330E000431343132000000000000", // Plain data
                            "FFFF9876543210E022BB", // KSN
                            "D214003575F6C7F72413B057126814CBA5A0393127D4895D48AEC9FA71ECFFF5" // Encrypted data
                    ),
                    Arguments.of(
                            "BDBD1234BDBD567890ABBDBDCDEFBDBD", // BDK
                            "020010353431333333393030303030313531330E000431343132000000000000", // Plain data
                            "FFFF9876543210E022BC", // KSN
                            "ED387B80539FBA285BD90EEA7681D1B7D5F0E1FFF62F8F2F27D1720303EAF26F" // Encrypted data
                    ),
                    Arguments.of(
                            "0123456789ABCDEFFEDCBA9876543210", // BDK
                            "230025363739393939303130303030303030313D3132313435303230303030303030303031323330", // Plain data
                            "FFFF98765439E9400001", // KSN
                            "CDD852B8ED9C9A0CE2C342D99887AD9FDD01055BE2B945DD92140864DFC45CEACF1FBF02C87C0BE4" // Encrypted data
                    ),
                    Arguments.of(
                            "0123456789ABCDEFFEDCBA9876543210", // BDK
                            "230025363739393939303130303030303030313D3132313435303230303030303030303031323330", // Plain data
                            "FFFF98765439F0C00001", // KSN
                            "8C4524A19BA8D470F5832ABC8EE766980255F6249C4CF2DAF4020B4AE19F6E94A929F4ED95B5F0BF" // Encrypted data
                    )
            );
        }
    }

    @Nested
    @TestInstance(TestInstance.Lifecycle.PER_CLASS)
    class WhenEncryptRequestData2009MethodIsCalledWithIV {

        @ParameterizedTest(name = "Should encrypt data (2009) for KSN: \"{2}\".")
        @MethodSource("getDataKsnAndExpectedEncryptedData")
        void shouldEncryptRequestData(final String bdk,
                                      final String plainData,
                                      final String ksn,
                                      final String expectedEncryptedData,
                                      final String iv) {
            // Given
            final IfsfSecurityFieldFactory ifsfSecurityFieldFactory = new IfsfSecurityFieldFactory(bdk);

            // When
            final String encryptedRequestData = ifsfSecurityFieldFactory.encryptRequestData2009(ksn, plainData, iv);

            // Then
            Assertions.assertEquals(expectedEncryptedData, encryptedRequestData);
        }

        Stream<Arguments> getDataKsnAndExpectedEncryptedData() {
            return Stream.of(
                    Arguments.of(
                            "BDBD1234BDBD567890ABBDBDCDEFBDBD", // BDK
                            "020010353431333333393030303030313531330E000431343132000000000000", // Plain data
                            "FFFF9876543210E01E9D", // KSN
                            "D9D60AB25BF3CADB98BB302BDFF46E18936B6C6BD03F1FFE7161113E5D8DEAC8", // Encrypted data
                            "0000000000000000" // InitialisationVector (IV)
                    ),
                    Arguments.of(
                            "BDBD1234BDBD567890ABBDBDCDEFBDBD", // BDK
                            "020010353431333333393030303030313531330E000431343132000000000000", // Plain data
                            "FFFF9876543210E01E9D", // KSN
                            "D6576D2527D15714BF2877B87CC56DB803FEE5BD110E25D8D8009712C83266E5", // Encrypted data
                            "1234567890123456" // InitialisationVector (IV)
                    )
            );
        }



    }

    @Nested
    @TestInstance(TestInstance.Lifecycle.PER_CLASS)
    class WhenDecryptRequestData2004MethodIsCalled {

        @ParameterizedTest(name = "Should decrypt data (2004) for KSN: \"{2}\".")
        @MethodSource("getDataKsnAndExpectedDecryptedData")
        void shouldDecryptRequestData(final String bdk,
                                      final String encryptedData,
                                      final String ksn,
                                      final String expectedPlainData) {
            // Given
            final IfsfSecurityFieldFactory ifsfSecurityFieldFactory = new IfsfSecurityFieldFactory(bdk);

            // When
            final String encryptedRequestData = ifsfSecurityFieldFactory.decryptRequestData2004(ksn, encryptedData);

            // Then
            Assertions.assertEquals(expectedPlainData, encryptedRequestData);
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
                    ),
                    Arguments.of(
                            "BDBD1234BDBD567890ABBDBDCDEFBDBD", // BDK
                            "6720D7711D4C2448303602A400B93540FBCC7907A6704035BC67CC097B2B83817F03972AE619BBC1", // Encrypted data
                            "FFFF98765434ECC00001", // KSN
                            "230025353230393033313030303030313834313D3234303231303130303030303030303030303030" // Plain data
                    ),
                    Arguments.of(
                            "BDBD1234BDBD567890ABBDBDCDEFBDBD", // BDK
                            "1965ACA377CD7E68D17CE89025F17BE02A363C06095891123A7E64FC57931C9AD8AB140E0B2ECBB4", // Encrypted data
                            "FFFF98765434EDA00001", // KSN
                            "230025353535393033313030303030313834313D3233303331303130303030303030303030303030" // Plain data
                    )
            );
        }

    }

    @Nested
    @TestInstance(TestInstance.Lifecycle.PER_CLASS)
    class WhenDecryptRequestData2009MethodIsCalled {

        @ParameterizedTest(name = "Should decrypt data (2009) for KSN: \"{2}\".")
        @MethodSource("getDataKsnAndExpectedDecryptedData")
        void shouldDecryptRequestData(final String bdk,
                                      final String encryptedData,
                                      final String ksn,
                                      final String expectedPlainData) {
            // Given
            final IfsfSecurityFieldFactory ifsfSecurityFieldFactory = new IfsfSecurityFieldFactory(bdk);

            // When
            final String encryptedRequestData = ifsfSecurityFieldFactory.decryptRequestData2009(ksn, encryptedData);

            // Then
            Assertions.assertEquals(expectedPlainData, encryptedRequestData);
        }

        Stream<Arguments> getDataKsnAndExpectedDecryptedData() {
            return Stream.of(
                    Arguments.of(
                            "0123456789ABCDEFFEDCBA9876543210", // BDK
                            "713D5DC33D3D6E0730B05899E8EE062F9B8B477EEBB1DBB2BD5E5075E88292AEF36098232EB27D6B", // Encrypted data
                            "FFFF9876543210E022B0", // KSN
                            "020010353431333333393030303030313531330E0004313431320000000000008000000000000000" // Plain data
                    ),
                    Arguments.of(
                            "BDBD1234BDBD567890ABBDBDCDEFBDBD", // BDK
                            "7A6E66AB9F2571FDC75113992060B6DB44FB55A4A4513AE5DA3BF4CA50D959518A76395366B92BC399F370CA0FE76D6658C97C734C2439ABBD8280E2C234A57D662BAA856CB3A403", // Encrypted data
                            "FFFF9876543210E022BE", // KSN
                            "020010353431333333393030303030313531330E00063037313233312300243534313333333930303030303135313344343931323630313030303030303030303030300000000000" // Plain data
                    ),
                    Arguments.of(
                            "BDBD1234BDBD567890ABBDBDCDEFBDBD", // BDK
                            "88FA8654DB7A3153E3036BE7DC92424E9C3325479209A3EDB9A1793493F091C9", // Encrypted data
                            "FFFF9876543210E022C0", // KSN
                            "020010353431333333393030303030313531330E000630373132333100000000" // Plain data
                    ),
                    Arguments.of(
                            "BDBD1234BDBD567890ABBDBDCDEFBDBD", // BDK
                            "ED387B80539FBA285BD90EEA7681D1B7D5F0E1FFF62F8F2F27D1720303EAF26F", // Encrypted data
                            "FFFF9876543210E022BC", // KSN
                            "020010353431333333393030303030313531330E000431343132000000000000" // Plain data
                    ),
                    Arguments.of(
                            "BDBD1234BDBD567890ABBDBDCDEFBDBD", // BDK
                            "D214003575F6C7F72413B057126814CBA5A0393127D4895D48AEC9FA71ECFFF5", // Encrypted data
                            "FFFF9876543210E022BB", // KSN
                            "020010353431333333393030303030313531330E000431343132000000000000" // Plain data
                    ),
                    Arguments.of(
                            "0123456789ABCDEFFEDCBA9876543210", // BDK
                            "3EE5BCEECDC5E649D3AD6A2D46FC486CC23053FE0D75AF27ECE6CA19D48384CF0358ABC871265B70", // Encrypted data
                            "FFFF9876543A00E00001", // KSN
                            "230024363739393939383930303030303230303033363D3235313231323030373435353030363100" // Plain data
                    )
            );
        }

    }

    @Nested
    @TestInstance(TestInstance.Lifecycle.PER_CLASS)
    class WhenCalculateMacMethodIsCalled {

        @ParameterizedTest(name = "Should compute MAC for KSN: \"{2}\".")
        @MethodSource("getMessageHashKsnAndExpectedMac")
        void shouldCalculateRequestMac(final String bdk,
                                       final String messageHash,
                                       final String ksn,
                                       final String expectedMac) {
            // Given
            final IfsfSecurityFieldFactory ifsfSecurityFieldFactory = new IfsfSecurityFieldFactory(bdk);

            // When
            final String requestMac = ifsfSecurityFieldFactory.calculateMac(ksn, messageHash);

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
                    ),
                    Arguments.of(
                            "BDBD1234BDBD567890ABBDBDCDEFBDBD", // BDK
                            "A186AE5EBA21D27C49814F3605542D62C989FABBAF3BEED2361DF0BCBA749646", // Data
                            "FFFF9876543210E022BB", // KSN
                            "4D7E83E9B7AB6F11" // MAC
                    ),
                    Arguments.of(
                            "BDBD1234BDBD567890ABBDBDCDEFBDBD", // BDK
                            "5A2C71AEFA0BA6E475D072E6C61CB8DA3188D05E4B9DE20F212BA566039D995D", // Data
                            "FFFF9876543210E022BC", // KSN
                            "99C063BFA89E7972" // MAC
                    ),
                    Arguments.of(
                            "0123456789ABCDEFFEDCBA9876543210", // BDK
                            "29A981123D342C7599A265E57A64001B96E967F9B0BC4EAA80B9E146E7A70CEB", // Data
                            "FFFF98765439F0C00001", // KSN
                            "A372F088A5B48F6F" // MAC
                    )
            );
        }

    }

    @Nested
    @TestInstance(TestInstance.Lifecycle.PER_CLASS)
    class WhenCalculateMacUsingMaskMethodIsCalled {

        @ParameterizedTest(name = "Should compute MAC for KSN: \"{2}\".")
        @MethodSource("getMessageHashKsnAndExpectedMac")
        void shouldCalculateMacUsingMask(final String bdk,
                                         final String messageHash,
                                         final String ksn,
                                         final IfsfKeyMask ifsfKeyMask,
                                         final String expectedMac) {
            // Given
            final IfsfSecurityFieldFactory ifsfSecurityFieldFactory = new IfsfSecurityFieldFactory(bdk);

            // When
            final String requestMac = ifsfSecurityFieldFactory.calculateMac(ksn, messageHash, ifsfKeyMask);

            // Then
            Assertions.assertEquals(expectedMac, requestMac);
        }

        Stream<Arguments> getMessageHashKsnAndExpectedMac() {
            return Stream.of(
                    Arguments.of(
                            "0123456789ABCDEFFEDCBA9876543210", // BDK
                            "B12557DC341A0EB357EE5F24499D0745E41065E30486C38E65E9F2881ADA5EB8", // Data
                            "FFFF9876543210E022B0", // KSN
                            IfsfKeyMask.RESPONSE_MAC_MASK, // Mask
                            "892F9BCFCE7F437F" // MAC
                    )
            );
        }

    }

    @Nested
    @TestInstance(TestInstance.Lifecycle.PER_CLASS)
    class WhenEncryptPinBlockMethodIsCalled {

        @ParameterizedTest(name = "Should encrypt PIN block for KSN: \"{2}\".")
        @MethodSource("getBdkClearPinBlockKsnAndEncryptedPinBlock")
        void shouldEncryptIso0PinBlock(final String bdk,
                                       final String iso0PinBlock,
                                       final String ksn,
                                       final String expectedEncryptedIso0PinBlock) {
            // Given
            final IfsfSecurityFieldFactory ifsfSecurityFieldFactory = new IfsfSecurityFieldFactory(bdk);

            // When
            final String actualEncryptedIso0PinBlock = ifsfSecurityFieldFactory.encryptPinBlock(ksn, iso0PinBlock);

            // Then
            Assertions.assertEquals(expectedEncryptedIso0PinBlock, actualEncryptedIso0PinBlock);
        }

        Stream<Arguments> getBdkClearPinBlockKsnAndEncryptedPinBlock() {
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
                    ),
                    Arguments.of(
                            "0123456789ABCDEFFEDCBA9876543210", // BDK
                            "06123556FFFFFFFE", // Clear ISO-0 PIN
                            "FFFF9876543210E00001", // KSN
                            "5C68E38A4C1DC4B5" // Encrypted ISO-0 PIN
                    ),
                    Arguments.of(
                            "165785BF78A1A675DBBF1C025A04125E", // BDK
                            "06123556FFFFFFFE", // Clear ISO-0 PIN
                            "FFFF7A9D3F3210E00001", // KSN
                            "C3E632E8A1543AD7" // Encrypted ISO-0 PIN
                    )
            );
        }

    }

    @Nested
    @TestInstance(TestInstance.Lifecycle.PER_CLASS)
    class WhenDecryptPinBlockMethodIsCalled {

        @ParameterizedTest(name = "Should decrypt PIN block for KSN: \"{2}\".")
        @MethodSource("getBdkEncryptedPinBlockKsnAndClearPinBlock")
        void shouldDecryptPinBlockData(final String bdk,
                                       final String encryptedIso0Pin,
                                       final String ksn,
                                       final String expectedClearIso0Pin) {
            // Given
            final IfsfSecurityFieldFactory ifsfSecurityFieldFactory = new IfsfSecurityFieldFactory(bdk);

            // When
            final String actualClearIso0Pin = ifsfSecurityFieldFactory.decryptPinBlock(ksn, encryptedIso0Pin);

            // Then
            Assertions.assertEquals(expectedClearIso0Pin, actualClearIso0Pin);
        }

        Stream<Arguments> getBdkEncryptedPinBlockKsnAndClearPinBlock() {
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
                    ),
                    Arguments.of(
                            "FEDCBA98765432100123456789ABCDEF", // BDK
                            "04A845119D336036", // Encrypted ISO-0 PIN
                            "FEDCBA98769072400073", // KSN
                            "0495E1CEFFFFFE7B" // Clear ISO-0 PIN
                    ),
                    Arguments.of(
                            "0123456789ABCDEFFEDCBA9876543210", // BDK
                            "CD932C7DAD2C33D7", // Encrypted ISO-0 PIN
                            "FFFF98765439D9A00001", // KSN
                            "0495E1CEFFFFFE7B" // Clear ISO-0 PIN
                    ),
                    Arguments.of(
                            "FEDCBA98765432100123456789ABCDEF", // BDK
                            "704721069D3ABDA9", // Encrypted ISO-0 PIN
                            "FEDCBA98769072400095", // KSN
                            "0495E1CEFFFFFE7B" // Clear ISO-0 PIN
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

    @Nested
    @TestInstance(TestInstance.Lifecycle.PER_CLASS)
    class WhenCalculateResponseMac2009MethodIsCalled {

        @ParameterizedTest(name = "Should compute response MAC for KSN: \"{2}\".")
        @MethodSource("getMessageHashKsnAndExpectedMac")
        void shouldCalculateResponseMac2009(final String bdk,
                                            final String messageHash,
                                            final String ksn,
                                            final String expectedMac) {
            // Given
            final IfsfSecurityFieldFactory ifsfSecurityFieldFactory = new IfsfSecurityFieldFactory(bdk);

            // When
            final String requestMac = ifsfSecurityFieldFactory.calculateResponseMac2009(ksn, messageHash);

            // Then
            Assertions.assertEquals(expectedMac, requestMac);
        }

        Stream<Arguments> getMessageHashKsnAndExpectedMac() {
            return Stream.of(
                    Arguments.of(
                            "BDBD1234BDBD567890ABBDBDCDEFBDBD", // BDK
                            "DE2FA92EEE8E3E581702D73DD98391962D051F3C91661E4D09D63DEE38A74995", // Data
                            "FFFF9876543210E022BB", // KSN
                            "DE9990C6B05DD94D" // MAC
                    )
            );
        }

    }

}
