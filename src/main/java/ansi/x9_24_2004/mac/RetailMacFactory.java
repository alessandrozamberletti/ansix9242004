package ansi.x9_24_2004.mac;

import ansi.x9_24_2004.encryption.Des;
import ansi.x9_24_2004.utils.BitArray;

/**
 * ANSI X9.19 Retail MAC (DES) and IFSF Retail MAC
 *
 * Code adapted from:
 * - Retail MAC Calculation in Java (Bharathi Subramanian).
 *   https://bharathisubramanian.wordpress.com/2013/03/23/retail-mac-calculation-in-java/
 *
 * Algorithm overview and pseudo-code:
 * - Message Authentication Code (MAC) algorithm (Mohammad).
 *   https://medium.com/@mohammad2603/message-authentication-code-mac-algorithm-ea9edaf66b3c
 * - IFSF Recommended Security Standards v2.00.
 **/
public class RetailMacFactory {

    private final Des des;

    public RetailMacFactory() {
        this.des = new Des();
    }

    public byte[] create(final BitArray key, final byte[] data) {
        final BitArray keyLow = key.get(0, 64);
        final BitArray keyHigh = key.get(64, 128);

        byte[] tmp = new byte[8];
        System.arraycopy(data, 0, tmp, 0, 8);

        byte[] retailMac = des.encrypt(keyLow, tmp);
        for (int i = 8; i < data.length; i += 8) {
            System.arraycopy(data, i, tmp, 0, 8);
            retailMac = des.encrypt(keyLow, xor(retailMac, tmp));
        }
        retailMac = des.decrypt(keyHigh, retailMac);
        retailMac = des.encrypt(keyLow, retailMac);

        return retailMac;
    }

    byte[] xor(byte[] first, byte[] second) {
        byte[] result = new byte[first.length];
        for (int i = 0; i < result.length; i++) {
            result[i] = (byte) (first[i] ^ second[i]);
        }
        return result;
    }

}
