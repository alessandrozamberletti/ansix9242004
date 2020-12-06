package ansi.x9_24_2004.encryption;

import ansi.x9_24_2004.utils.CustomBitSet;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;

public interface Encryption {

    default byte[] encrypt(CustomBitSet key, byte[] data, boolean padding) {
        try {
            final SecretKey secretKey = getEncryptionKey(key);
            final IvParameterSpec iv = new IvParameterSpec(new byte[8]);
            final Cipher cipher = getCipher(padding);

            cipher.init(Cipher.ENCRYPT_MODE, secretKey, iv);

            return cipher.doFinal(data);
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }

    default byte[] encrypt(CustomBitSet key, byte[] data) {
        return encrypt(key, data, false);
    }

    default byte[] decrypt(CustomBitSet key, byte[] data, boolean padding) {
        try {
            final SecretKey secretKey = getEncryptionKey(key);
            final IvParameterSpec iv = new IvParameterSpec(new byte[8]);
            final Cipher cipher = getCipher(padding);

            cipher.init(Cipher.DECRYPT_MODE, secretKey, iv);

            return cipher.doFinal(data);
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }

    default byte[] decrypt(CustomBitSet key, byte[] data) {
        return decrypt(key, data, false);
    }

    SecretKey getEncryptionKey(CustomBitSet key);

    String padding();

    String noPadding();

    default Cipher getCipher(boolean padding) {
        try {
            return Cipher.getInstance(padding ? padding() : noPadding());
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }

}
