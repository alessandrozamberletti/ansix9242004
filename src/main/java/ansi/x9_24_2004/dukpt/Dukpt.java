package ansi.x9_24_2004.dukpt;

import ansi.x9_24_2004.encryption.Des;
import ansi.x9_24_2004.encryption.TripleDes;
import ansi.x9_24_2004.utils.CustomBitSet;
import ansi.x9_24_2004.utils.ByteArrayUtils;

/**
 * <p>The Dukpt class acts a name-space for the Derived
 * Unique Key-Per-Transaction (Dukpt) standard using the
 * Data Encryption Standard, DES, (often referred to in practice as
 * "DEA", for Data Encryption Algorithm).
 *
 * <p>The functions provided attempt to aid a user in performing
 * encryption, decryption, and possibly more complex operations
 * using these.
 *
 * <p>There is also a set of conversion methods to hopefully make
 * the class even easier to interface with.  Many of these involve
 * the BitSet wrapper of java.util.BitSet which was designed to have
 * a proper "bitSize()" function as Java's BitSet does not have a method
 * that returns the constructed length of the BitSet, only its actual
 * size in memory and its "logical" size (1 + the index of the left-most 1).
 *
 * <p>To further augment to the security of Dukpt, two "oblivate()" methods are
 * included, one for the extended BitSet and one for byte arrays.  These
 * overwrite their respective arguments with random data as supplied by
 * java.secruty.SecureRandom to ensure that their randomness is
 * cryptographically strong.  The default number of overwrites is specified by
 * the static constant NUM_OVERWRITES but the user can supply a different number
 * should they desire the option.
 *
 * @author Software Verde: Andrew Groot
 * @author Software Verde: Josh Green
 */
public class Dukpt {

    private final Des des;
    private final TripleDes tripleDes;

    Dukpt(final Des des, final TripleDes tripleDes) {
        this.des = des;
        this.tripleDes = tripleDes;
    }

    CustomBitSet computeKey(final CustomBitSet bdk, final CustomBitSet ksn, final ansi.x9_24_2004.dukpt.Mask mask) {
        CustomBitSet ipek = getIpek(bdk, ksn);
        CustomBitSet key = getCurrentKey(ipek, ksn);

        key.xor(mask.value());

        return key;
    }

    CustomBitSet getIpek(final CustomBitSet key, final CustomBitSet ksn) {
        byte[][] ipek = new byte[2][];
        CustomBitSet keyRegister = key.get(0, key.bitSize());
        CustomBitSet data = ksn.get(0, ksn.bitSize());
        data.clear(59, 80);

        ipek[0] = tripleDes.encrypt(keyRegister, CustomBitSet.toByteArray(data.get(0, 64)), false);

        keyRegister.xor(ansi.x9_24_2004.dukpt.Mask.KEY_REGISTER_BITMASK.value());
        ipek[1] = tripleDes.encrypt(keyRegister, CustomBitSet.toByteArray(data.get(0, 64)), false);

        return ByteArrayUtils.toBitSet(ByteArrayUtils.concat(ipek[0], ipek[1]));
    }

    CustomBitSet getCurrentKey(final CustomBitSet ipek, final CustomBitSet ksn) {
        CustomBitSet key = ipek.get(0, ipek.bitSize());
        CustomBitSet counter = ksn.get(0, ksn.bitSize());
        counter.clear(59, ksn.bitSize());

        for (int i = 59; i < ksn.bitSize(); i++) {
            if (ksn.get(i)) {
                counter.set(i);
                key = nonReversibleKeyGenerationProcess(key, counter.get(16, 80), ansi.x9_24_2004.dukpt.Mask.KEY_REGISTER_BITMASK.value());
            }
        }

        return key;
    }

    CustomBitSet nonReversibleKeyGenerationProcess(final CustomBitSet pKey, final CustomBitSet data, final CustomBitSet keyRegisterBitmask) {
        CustomBitSet keyReg = pKey.get(0, pKey.bitSize());
        CustomBitSet reg1 = data.get(0, data.bitSize());
        // step 1: Crypto Register-1 XORed with the right half of the Key Register goes to Crypto Register-2.
        CustomBitSet reg2 = reg1.get(0, 64); // reg2 is being used like a temp here
        reg2.xor(keyReg.get(64, 128));   // and here, too, kind of
        // step 2: Crypto Register-2 DEA-encrypted using, as the key, the left half of the Key Register goes to Crypto Register-2
        reg2 = ByteArrayUtils.toBitSet(des.encrypt(keyReg.get(0, 64), CustomBitSet.toByteArray(reg2), false));
        // step 3: Crypto Register-2 XORed with the right half of the Key Register goes to Crypto Register-2
        reg2.xor(keyReg.get(64, 128));
        // done messing with reg2

        // step 4: XOR the Key Register with hexadecimal C0C0 C0C0 0000 0000 C0C0 C0C0 0000 0000
        keyReg.xor(keyRegisterBitmask);
        // step 5: Crypto Register-1 XORed with the right half of the Key Register goes to Crypto Register-1
        reg1.xor(keyReg.get(64, 128));
        // step 6: Crypto Register-1 DEA-encrypted using, as the key, the left half of the Key Register goes to Crypto Register-1
        reg1 = ByteArrayUtils.toBitSet(des.encrypt(keyReg.get(0, 64), CustomBitSet.toByteArray(reg1), false));
        // step 7: Crypto Register-1 XORed with the right half of the Key Register goes to Crypto Register-1
        reg1.xor(keyReg.get(64, 128));
        // done

        byte[] reg1b = CustomBitSet.toByteArray(reg1);
        byte[] reg2b = CustomBitSet.toByteArray(reg2);

        return ByteArrayUtils.toBitSet(ByteArrayUtils.concat(reg1b, reg2b));
    }

}
