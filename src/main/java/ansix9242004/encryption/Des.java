package ansix9242004.encryption;

import ansix9242004.utils.BitSet;

import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.DESKeySpec;

public class Des implements Encryption {

    @Override
    public SecretKey getEncryptionKey(final BitSet key) {
        try {
            final DESKeySpec desKeySpec = new DESKeySpec(BitSet.toByteArray(key));
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
