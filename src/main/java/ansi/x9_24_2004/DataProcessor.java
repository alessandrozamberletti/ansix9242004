package ansi.x9_24_2004;

import ansi.x9_24_2004.dukpt.Dukpt;
import ansi.x9_24_2004.dukpt.Mask;
import ansi.x9_24_2004.encryption.Des;
import ansi.x9_24_2004.encryption.TripleDes;
import ansi.x9_24_2004.utils.CustomBitSet;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import javax.xml.bind.DatatypeConverter;
import java.util.Arrays;

public class DataProcessor {

    private final CustomBitSet bdk;
    private final TripleDes tripleDes;
    private final Des des;
    private final Dukpt dukpt;

    DataProcessor(final String bdk) {
        this.bdk = new CustomBitSet(bdk);
        this.des = new Des();
        this.tripleDes = new TripleDes();
        this.dukpt = new Dukpt(des, tripleDes);
    }

    String encryptRequestData(final String ksn, final String data) {
        final CustomBitSet requestDataKey = dukpt.computeKey(bdk, new CustomBitSet(ksn), Mask.REQUEST_DATA_MASK);
        final byte[] encryptedRequestData = tripleDes.encrypt(requestDataKey, DatatypeConverter.parseHexBinary(data), false);

        return DatatypeConverter.printHexBinary(encryptedRequestData);
    }

    String calculateRequestMac(final String ksn, final String messageHash) {
        CustomBitSet requestMacKey = dukpt.computeKey(bdk, new CustomBitSet(ksn), Mask.REQUEST_MAC_MASK);
        final byte[] messageHashBytes = DatatypeConverter.parseHexBinary(messageHash);

        byte[] requestMac = retailMac(requestMacKey.toByteArray(), messageHashBytes);

        return DatatypeConverter.printHexBinary(requestMac);
    }

    public byte[] retailMac(byte[] key, byte[] data) {
        int loc = 0;
        byte[] edata;
        // Create Keys
        byte[] key1 = Arrays.copyOf(key, 8);
        byte[] key2 = Arrays.copyOfRange(key, 8, 16);

        try {
            SecretKey ka = new SecretKeySpec(key1, "DES");
            Cipher cipherA = Cipher.getInstance("DES/CBC/NoPadding");
            cipherA.init(Cipher.ENCRYPT_MODE, ka, new IvParameterSpec(new byte[8]));

            SecretKey kb = new SecretKeySpec(key2, "DES");
            Cipher cipherB = Cipher.getInstance("DES/CBC/NoPadding");
            cipherB.init(Cipher.DECRYPT_MODE, kb, new IvParameterSpec(new byte[8]));

            byte[] x = new byte[8];
            System.arraycopy(data, loc, x, 0, 8);

            edata = cipherA.doFinal(x);

            for (loc = 8; loc < data.length; loc += 8)
            {
                System.arraycopy(data, loc, x, 0, 8);
                byte[] y = xor_array(edata, x);
                edata = cipherA.doFinal(y);
            }

            // Decrypt the resulting block with Key-B
            edata = cipherB.doFinal(edata);
            // Encrypt the resulting block with Key-A
            edata = cipherA.doFinal(edata);
        } catch (Exception e) {
            e.printStackTrace();
            return null;
        }
        return edata;
    }

    private byte[] xor_array( byte[] aFirstArray, byte[] aSecondArray)
    {
        byte[] result = new byte[aFirstArray.length];
        for ( int i = 0; i < result.length; i++ )
        {
            result[i] = (byte) ( aFirstArray[i] ^ aSecondArray[i] );
        }
        return result;
    }

}
