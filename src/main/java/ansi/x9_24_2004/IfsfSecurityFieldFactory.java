package ansi.x9_24_2004;

import ansi.x9_24_2004.dukpt.DukptFactory;
import ansi.x9_24_2004.dukpt.IfsfKeyMask;
import ansi.x9_24_2004.encryption.Des;
import ansi.x9_24_2004.encryption.TripleDes;
import ansi.x9_24_2004.mac.RetailMacFactory;
import ansi.x9_24_2004.utils.BitArray;

import javax.xml.bind.DatatypeConverter;

public class IfsfSecurityFieldFactory {

    private final BitArray bdk;
    private final TripleDes tripleDes;
    private final DukptFactory dukptFactory;
    private final RetailMacFactory retailMacFactory;

    public IfsfSecurityFieldFactory(final String bdk) {
        this.bdk = new BitArray(bdk);

        this.tripleDes = new TripleDes();
        this.retailMacFactory = new RetailMacFactory();
        this.dukptFactory = new DukptFactory(new Des(), tripleDes);
    }

    // Sensitive data encryption using ANSI X9.24 2004 data key
    public String encryptRequestData2004(final String ksn, final String data) {
        final BitArray requestDataKey = dukptFactory.computeKey(bdk, new BitArray(ksn), IfsfKeyMask.REQUEST_DATA_MASK);
        final byte[] encryptedRequestData = tripleDes.encrypt(requestDataKey, DatatypeConverter.parseHexBinary(data));

        return DatatypeConverter.printHexBinary(encryptedRequestData);
    }

    // Sensitive data encryption using ANSI X9.24 2009 data key
    public String encryptRequestData2009(final String ksn, final String data) {
        final BitArray x924version2009DataKey = dukptFactory.computeAnsiX924version2009DataKey(bdk, new BitArray(ksn));
        final byte[] encryptedRequestData = tripleDes.encrypt(x924version2009DataKey, DatatypeConverter.parseHexBinary(data));

        return DatatypeConverter.printHexBinary(encryptedRequestData);
    }

    // Sensitive data encryption using ANSI X9.24 2009 data key
    public String encryptRequestData2009(final String ksn, final String data, final String iv) {
        final BitArray x924version2009DataKey = dukptFactory.computeAnsiX924version2009DataKey(bdk, new BitArray(ksn));
        final byte[] encryptedRequestData = tripleDes.encrypt(x924version2009DataKey, DatatypeConverter.parseHexBinary(data), false, DatatypeConverter.parseHexBinary(iv));

        return DatatypeConverter.printHexBinary(encryptedRequestData);
    }

    // Encrypt using fixed key
    public String encryptFixed(final String key, final String data) {
        final byte[] requestData = tripleDes.encrypt(new BitArray(key), DatatypeConverter.parseHexBinary(data));

        return DatatypeConverter.printHexBinary(requestData);
    }

    // Sensitive data decryption using ANSI X9.24 2004 data key
    public String decryptRequestData2004(final String ksn, final String encryptedData) {
        final BitArray requestDataKey = dukptFactory.computeKey(bdk, new BitArray(ksn), IfsfKeyMask.REQUEST_DATA_MASK);
        final byte[] requestData = tripleDes.decrypt(requestDataKey, DatatypeConverter.parseHexBinary(encryptedData));

        return DatatypeConverter.printHexBinary(requestData);
    }

    // Sensitive data decryption using ANSI X9.24 2009 data key
    public String decryptRequestData2009(final String ksn, final String encryptedData) {
        final BitArray requestDataKey = dukptFactory.computeAnsiX924version2009DataKey(bdk, new BitArray(ksn));
        final byte[] requestData = tripleDes.decrypt(requestDataKey, DatatypeConverter.parseHexBinary(encryptedData));

        return DatatypeConverter.printHexBinary(requestData);
    }

    // Decrypt using fixed key
    public String decryptFixed(final String key, final String encryptedData) {
        final byte[] requestData = tripleDes.decrypt(new BitArray(key), DatatypeConverter.parseHexBinary(encryptedData));

        return DatatypeConverter.printHexBinary(requestData);
    }

    // Compute retail MAC
    public String calculateMac(final String ksn, final String messageHash, final IfsfKeyMask ifsfKeyMask) {
        final BitArray requestMacKey = dukptFactory.computeKey(bdk, new BitArray(ksn), ifsfKeyMask);
        final byte[] requestMac = retailMacFactory.create(requestMacKey, DatatypeConverter.parseHexBinary(messageHash));

        return DatatypeConverter.printHexBinary(requestMac);
    }

    // Compute retail MAC
    // ANSI X9.24 2004: method can be used to calculate request and response MACs (mask is bi-directional)
    // ANSI X9.24 2009: method can be used to calculate only request MAC
    public String calculateMac(final String ksn, final String messageHash) {
        return calculateMac(ksn, messageHash, IfsfKeyMask.REQUEST_MAC_MASK);
    }

    // Compute response retail MAC
    // Should only be used for ANSI X9.24 version 2009
    public String calculateResponseMac2009(final String ksn, final String messageHash) {
        return calculateMac(ksn, messageHash, IfsfKeyMask.RESPONSE_MAC_MASK);
    }

    // Encrypt plain PIN block
    public String encryptPinBlock(final String ksn, final String pinBlock) {
        final BitArray pinKey = dukptFactory.computeKey(bdk, new BitArray(ksn), IfsfKeyMask.REQUEST_PIN_MASK);
        final byte[] encryptedPinBlock = tripleDes.encrypt(pinKey, DatatypeConverter.parseHexBinary(pinBlock));

        return DatatypeConverter.printHexBinary(encryptedPinBlock);
    }

    // Decrypt encrypted PIN block
    public String decryptPinBlock(final String ksn, final String encryptedPinBlock) {
        final BitArray pinKey = dukptFactory.computeKey(bdk, new BitArray(ksn), IfsfKeyMask.REQUEST_PIN_MASK);
        final byte[] clearPinBlock = tripleDes.decrypt(pinKey, DatatypeConverter.parseHexBinary(encryptedPinBlock));

        return DatatypeConverter.printHexBinary(clearPinBlock);
    }

}
