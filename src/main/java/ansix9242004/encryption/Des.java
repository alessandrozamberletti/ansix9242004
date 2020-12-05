package ansix9242004.encryption;

import ansix9242004.utils.BitSet;

import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.DESKeySpec;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;

public class Des implements Encryption {

    @Override
    public SecretKey getEncryptionKey(final BitSet key) throws NoSuchAlgorithmException, InvalidKeyException, InvalidKeySpecException {
        final DESKeySpec desKeySpec = new DESKeySpec(BitSet.toByteArray(key));
        return SecretKeyFactory.getInstance("DES").generateSecret(desKeySpec);
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
