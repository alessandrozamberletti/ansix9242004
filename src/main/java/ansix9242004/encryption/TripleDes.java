package ansix9242004.encryption;

import ansix9242004.utils.BitSet;
import ansix9242004.utils.ByteArrayUtils;

import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.DESedeKeySpec;
import java.security.InvalidParameterException;

public class TripleDes implements Encryption {

    @Override
    public SecretKey getEncryptionKey(BitSet key) {
        BitSet k1, k2, k3;
        if (key.bitSize() == 64) {
            // single length
            k1 = key.get(0, 64);
            k2 = k1;
            k3 = k1;
        } else if (key.bitSize() == 128) {
            // double length
            k1 = key.get(0, 64);
            k2 = key.get(64, 128);
            k3 = k1;
        } else {
            // triple length
            if (key.bitSize() != 192) {
                throw new InvalidParameterException("Key is not 8/16/24 bytes long.");
            }
            k1 = key.get(0, 64);
            k2 = key.get(64, 128);
            k3 = key.get(128, 192);
        }
        byte[] kb1 = BitSet.toByteArray(k1);
        byte[] kb2 = BitSet.toByteArray(k2);
        byte[] kb3 = BitSet.toByteArray(k3);
        byte[] key16 = ByteArrayUtils.concat(kb1, kb2);
        byte[] key24 = ByteArrayUtils.concat(key16, kb3);

        try {
            final DESedeKeySpec deSedeKeySpec = new DESedeKeySpec(key24);
            return SecretKeyFactory.getInstance("DESede").generateSecret(deSedeKeySpec);
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }

    @Override
    public String padding() {
        return "DESede/CBC/PKCS5Padding";
    }

    @Override
    public String noPadding() {
        return "DESede/CBC/NoPadding";
    }

}
