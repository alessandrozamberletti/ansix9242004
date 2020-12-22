package ansi.x9_24_2004.encryption;

import ansi.x9_24_2004.utils.CustomBitSet;

import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.DESKeySpec;

public class Des implements Encryption {

    @Override
    public SecretKey getEncryptionKey(final CustomBitSet key) {
        try {
            final DESKeySpec desKeySpec = new DESKeySpec(key.toByteArray());
            return SecretKeyFactory.getInstance("DES").generateSecret(desKeySpec);
        } catch (Exception e) {
            throw new IllegalStateException("Wrong DES key: '" + key + "'", e);
        }
    }

    @Override
    public String padding() {
        return "DES/CBC/PKCS5Padding";
    }

    @Override
    public String noPadding() {
        return "DES/CBC/NoPadding";
    }

}
