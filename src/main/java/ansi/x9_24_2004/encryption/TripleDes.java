package ansi.x9_24_2004.encryption;

import ansi.x9_24_2004.utils.BitArray;
import ansi.x9_24_2004.utils.ByteArrayUtils;

import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.DESedeKeySpec;

public class TripleDes implements Encryption {

    @Override
    public SecretKey getEncryptionKey(final BitArray key) {
            final BitArray keyLow = key.get(0, 64);
            final BitArray keyHigh = key.get(64, 128);
            final byte[] tripleDesKey =
                    ByteArrayUtils.concat(keyLow.toByteArray(), keyHigh.toByteArray(), keyLow.toByteArray());

        try {
            final DESedeKeySpec deSedeKeySpec = new DESedeKeySpec(tripleDesKey);
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
