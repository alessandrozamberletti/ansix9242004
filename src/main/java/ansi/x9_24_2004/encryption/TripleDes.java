package ansi.x9_24_2004.encryption;

import ansi.x9_24_2004.utils.CustomBitSet;
import ansi.x9_24_2004.utils.ByteArrayUtils;

import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.DESedeKeySpec;

public class TripleDes implements Encryption {

    @Override
    public SecretKey getEncryptionKey(final CustomBitSet key) {
        CustomBitSet k1;
        CustomBitSet k2;
        CustomBitSet k3;
        try {
            if (key.size() == 64) {
                // single length
                k1 = key.get(0, 64);
                k2 = k1;
                k3 = k1;
            } else if (key.size() == 128) {
                // double length
                k1 = key.get(0, 64);
                k2 = key.get(64, 128);
                k3 = k1;
            } else {
                // triple length
                k1 = key.get(0, 64);
                k2 = key.get(64, 128);
                k3 = key.get(128, 192);
            }

            final byte[] key16 = ByteArrayUtils.concat(k1.toByteArray(), k2.toByteArray());
            final byte[] key24 = ByteArrayUtils.concat(key16, k3.toByteArray());

            final DESedeKeySpec deSedeKeySpec = new DESedeKeySpec(key24);
            return SecretKeyFactory.getInstance("DESede").generateSecret(deSedeKeySpec);
        } catch (Exception e) {
            throw new IllegalStateException("Wrong 3-DES key: '" + key + "'", e);
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
