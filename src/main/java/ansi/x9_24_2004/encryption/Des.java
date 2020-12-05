package ansi.x9_24_2004.encryption;

import ansi.x9_24_2004.utils.CustomBitSet;

import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.DESKeySpec;

public class Des implements ansi.x9_24_2004.encryption.Encryption {

    @Override
    public SecretKey getEncryptionKey(final CustomBitSet key) {
        try {
            final DESKeySpec desKeySpec = new DESKeySpec(CustomBitSet.toByteArray(key));
            return SecretKeyFactory.getInstance("DES").generateSecret(desKeySpec);
        } catch (Exception e) {
            throw new IllegalStateException(e);
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
