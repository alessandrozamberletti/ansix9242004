package ansi.x9_24_2004.mac;

import ansi.x9_24_2004.encryption.Des;
import ansi.x9_24_2004.utils.CustomBitSet;

/**
 * ANSI X9.19 Retail MAC (3DES) and IFSF Retail MAC
 *
 * Sources and explanations:
 * - Retail MAC Calculation in Java (Bharathi Subramanian).
 *   https://bharathisubramanian.wordpress.com/2013/03/23/retail-mac-calculation-in-java/
 * - Message Authentication Code (MAC) algorithm (Mohammad).
 *   https://medium.com/@mohammad2603/message-authentication-code-mac-algorithm-ea9edaf66b3c
 * - IFSF Recommended Security Standards v2.00.
 **/
public class RetailMacFactory {

    private final Des des;

    public RetailMacFactory() {
        this.des = new Des();
    }

    public byte[] create(final CustomBitSet key, final byte[] data) {
        final CustomBitSet key1a = key.get(0, 64);
        final CustomBitSet key1b = key.get(64, 128);

        byte[] tmp = new byte[8];
        System.arraycopy(data, 0, tmp, 0, 8);

        byte[] retailMac = des.encrypt(key1a, tmp);
        for (int i = 8; i < data.length; i += 8) {
            System.arraycopy(data, i, tmp, 0, 8);
            retailMac = des.encrypt(key1a, xor(retailMac, tmp));
        }
        retailMac = des.decrypt(key1b, retailMac);
        retailMac = des.encrypt(key1a, retailMac);

        return retailMac;
    }

    private byte[] xor(byte[] first, byte[] second) {
        byte[] result = new byte[first.length];
        for (int i = 0; i < result.length; i++) {
            result[i] = (byte) (first[i] ^ second[i]);
        }
        return result;
    }

}
