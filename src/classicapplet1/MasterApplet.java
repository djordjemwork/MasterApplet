/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package classicapplet1;

import javacard.framework.APDU;
import javacard.framework.Applet;
import javacard.framework.AppletEvent;
import javacard.framework.CardRuntimeException;
import javacard.framework.ISO7816;
import static javacard.framework.ISO7816.OFFSET_CDATA;
import static javacard.framework.ISO7816.OFFSET_CLA;
import static javacard.framework.ISO7816.OFFSET_INS;
import static javacard.framework.ISO7816.OFFSET_LC;
import static javacard.framework.ISO7816.OFFSET_P1;
import static javacard.framework.ISO7816.OFFSET_P2;
import static javacard.framework.ISO7816.SW_INCORRECT_P1P2;
import static javacard.framework.ISO7816.SW_INS_NOT_SUPPORTED;
import static javacard.framework.ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED;
import static javacard.framework.ISO7816.SW_WRONG_P1P2;
import javacard.framework.ISOException;
import javacard.framework.JCSystem;
import javacard.framework.OwnerPIN;
import javacard.framework.Util;
import javacard.security.KeyBuilder;
import javacard.security.MessageDigest;
import javacard.security.RSAPrivateKey;
import javacard.security.RandomData;
import javacard.security.Signature;
import javacardx.crypto.Cipher;
import javacardx.apdu.ExtendedLength;

/**
 *
 * @author Admin
 */
public class MasterApplet extends Applet implements ISO7816, AppletEvent, ExtendedLength {

    final static short GD_APPLET_VERSION = 0x0000;
    final static short GD_STATE = 0x0001;
    final static short GD_CERTIFICATE_LIST = 0x0002;
    final static short GD_CERTIFICATE = 0x0003;
    final static short GD_CPLC = 0x0004;

    final static short PD_ENCRYPTION_CERTIFICATE = 0x0002;
    final static short PD_PRIVATE_KEY = 0x0003;
    final static short PD_SIGNING_CERTIFICATE = 0x0004;
    final static short PD_SIGNING_PRIVATE_KEY = 0x0005;

    final static short NUM_TRANSIENT_SHORTS = 2;
    final static byte TN_SELECTED_FILE = 0;
    final static byte TN_CHAINING_OFFSET = 1;
    private short[] transientShorts;
    final static short NUM_TRANSIENT_OBJECTS = 3;
    final static byte TN_SELECTED_KEY = 0;
    final static byte TN_SELECTED_CERTIFICATE_SLOT = 1;
    final static byte TN_SELECTED_CHIPER = 2;
    private Object[] transientObjects;
    final static short NUM_TRANSIENT_BYTES = 2;
    final static byte TN_LAST_CHAINED_COMMAND = 0;
    final static byte TN_CURRENT_CLA = 1;
    private byte[] transientBytes;

    private MessageDigest digest;
    private Signature signature;
    private Cipher rsa;

    private AccessControl accessControl;
    private static final short TEMP_SIZE = 2048;
    private byte[] temp;
    private Cipher cipher = null;

    private PACEProtocol paceProtocol = null;
    private boolean locked;

    private byte[] additionalData;
    private byte[] documentNumber;

    // ----------- MOC -------------
    private byte[] fingerPrintArray;
    private boolean isRequiredMOC;
    private byte fingerPrintPosition = 0;

    // ----------- FOR GENERATE AES KEYS -------------
    private final short PACE_KEY_LENGTH = 0x80;
    private byte[] A;
    private byte[] a;
    private byte[] B;
    private byte[] param_K;

    private byte[] appletVersion = {0x31, 0x2e, 0x30, 0x2e, 0x30};

    /**
     * Installs this applet.
     *
     * @param bArray the array containing installation parameters
     * @param bOffset the starting offset in bArray
     * @param bLength the length in bytes of the parameter data in bArray
     */
    public static void install(byte[] bArray, short bOffset, byte bLength) {
        new MasterApplet().register();
    }

    /**
     * Only this class's install method should create the applet object.
     */
    protected MasterApplet() {
        transientBytes = JCSystem.makeTransientByteArray(NUM_TRANSIENT_BYTES, JCSystem.CLEAR_ON_RESET);
        transientShorts = JCSystem.makeTransientShortArray(NUM_TRANSIENT_SHORTS, JCSystem.CLEAR_ON_RESET);
        transientObjects = JCSystem.makeTransientObjectArray(NUM_TRANSIENT_OBJECTS, JCSystem.CLEAR_ON_RESET);
        temp = JCSystem.makeTransientByteArray(TEMP_SIZE, JCSystem.CLEAR_ON_DESELECT);
        accessControl = new AccessControl();
        digest = javacard.security.MessageDigest.getInstance(MessageDigest.ALG_SHA, false);
        signature = javacard.security.Signature.getInstance(Signature.ALG_RSA_SHA_256_PKCS1, false);
        rsa = javacardx.crypto.Cipher.getInstance(Cipher.ALG_RSA_PKCS1, false);
        paceProtocol = new PACEProtocol(temp);
        locked = false;

        // MOC
        isRequiredMOC = false;
        fingerPrintArray = new byte[500];

        documentNumber = new byte[8];
        // FOR AES Keys
        A = new byte[PACE_KEY_LENGTH];
        a = new byte[PACE_KEY_LENGTH];
        B = new byte[PACE_KEY_LENGTH];
        param_K = new byte[PACE_KEY_LENGTH];

        additionalData = new byte[2000];
    }

    public void uninstall() {
    }

    public void deselect() {
        accessControl.resetPins();
        super.deselect();
    }

    public void process(APDU apdu) {
        if (this.selectingApplet()) {
            return;
        }
        byte[] buffer = apdu.getBuffer();
        byte p2 = buffer[OFFSET_P2];
        transientBytes[TN_CURRENT_CLA] = buffer[OFFSET_CLA];
        byte ins = buffer[OFFSET_INS];

        if (transientBytes[TN_LAST_CHAINED_COMMAND] != 0x00) {
            if (ins != transientBytes[TN_LAST_CHAINED_COMMAND]) {
                transientBytes[TN_LAST_CHAINED_COMMAND] = 0x00;
                ISOException.throwIt(ISO7816EXT.SW_LAST_COMMAND_EXPECTED);
            }
        }
        try {
            switch (ins) {
                case (byte)0x20:
                    processVerify1(apdu);
                    break;
                case (byte)0x2C:
                    processResetRetryCounter(apdu);
                    break;
                case (byte) 0xDC:
                    processPutAdditionalData(apdu);
                    break;
                case (byte) 0xCC:
                    processGetAdditionalData(apdu);
                    break;
                case (byte) 0x88:
                    generateKey(apdu);
                    break;
                case (byte) 0x89:
                    validateKey(apdu);
                    break;
                default:
                    ISOException.throwIt(SW_INS_NOT_SUPPORTED);
            }
        } catch (CardRuntimeException ex) {
            this.resetChaining();
            throw ex;
        }
    }


    private void processPutAdditionalData(APDU apdu) {
        byte[] buffer = apdu.getBuffer();
        short len = apdu.setIncomingAndReceive();
        short offset = apdu.getOffsetCdata();
        short total = apdu.getIncomingLength();
        short recieved = len;
        Util.arrayCopyNonAtomic(buffer, offset, temp, (short) 0, len);
        while (recieved < total) {
            len = apdu.receiveBytes((short) 0);
            if (len == 0) {
                break;
            }
            Util.arrayCopyNonAtomic(buffer, (short) 0, temp, recieved, len);
            recieved += len;
        }

        if (locked) {
            if (!accessControl.checkIsMasterPinVerified()) {
                ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
            }
            Util.arrayCopyNonAtomic(temp, (short) 0, temp, (short)16, recieved);
            paceProtocol.decryptPACE(temp, (short) 16, recieved, temp, (short) 0);
        }

        len = Util.makeShort(temp[0], temp[1]);

        if (len >= (short) additionalData.length) {
            ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        }
        Util.arrayFillNonAtomic(additionalData, (short) 0, (short) additionalData.length, (byte) 0);
        Util.arrayCopyNonAtomic(temp, (short) 2, additionalData, (short) 0, len);
    }

    private void processGetAdditionalData(APDU apdu) {
        byte[] buffer = apdu.getBuffer();
        short length = 0;
        if (additionalData != null) {
            length = (short) additionalData.length;
        }

        // check verified user or master pin
        // 9.10.2018 commented line behind
        //accessControl.checkUserOrMaster();
        temp[16] = (byte) ((length >> 0x08) & 0xff);
        temp[17] = (byte) (length & 0xff);
        short le = 0;
        Util.arrayCopyNonAtomic(additionalData, (short) 0, temp, (short) 18, length);
        le = paceProtocol.encryptPACE(temp, (short) 16, (short) (length + 2), temp, (short) 0);

        apdu.setOutgoing();
        apdu.setOutgoingLength(le);
        apdu.sendBytesLong(temp, (short) 0, le);
    }

  

    private void resetChaining() {
        transientShorts[TN_CHAINING_OFFSET] = 0;
        transientBytes[TN_LAST_CHAINED_COMMAND] = 0;
        transientBytes[TN_CURRENT_CLA] = 0;
    }

    /**
     * Reponds to RESET RETRY COUNTER
     *
     * @param apdu
     */
    private void processResetRetryCounter(APDU apdu) {
        byte[] buffer = apdu.getBuffer();
        byte p1 = buffer[OFFSET_P1];
        byte p2 = buffer[OFFSET_P2];

        short byteRead = apdu.setIncomingAndReceive();
        if (locked) {
            paceProtocol.decryptPACE(buffer, OFFSET_CDATA, byteRead, buffer, (short) (OFFSET_CDATA - 1));
            byteRead = buffer[(short) (OFFSET_CDATA - 1)];
        }

        if (!(p1 >= 0x00 && p1 <= 0x003)) {
            ISOException.throwIt(SW_INCORRECT_P1P2);
        }
        switch (p1) {
            case 0x00:
                // reseting code followed without delimitation by new reference data
                ISOException.throwIt(SW_WRONG_P1P2);
                break;
            case 0x01:
                // reseting code
                ISOException.throwIt(SW_WRONG_P1P2);
                break;
            case 0x02:
                // new reference data
                accessControl.changePin(p2, buffer, OFFSET_CDATA, buffer[OFFSET_LC]);
                break;
            case 0x03:
                // Keep PIN, but reset it and ublock it
                accessControl.resetPin(p2);
                break;
            default:
                ISOException.throwIt(SW_WRONG_P1P2);
        }
        locked = true;
    }

    private void processVerify1(APDU apdu) {
        byte[] buffer = apdu.getBuffer();
        byte byteRead = (byte) apdu.setIncomingAndReceive();
        if (locked) {
            short le = paceProtocol.decryptPACE(buffer, OFFSET_CDATA, byteRead, buffer, (short) (OFFSET_CDATA - 1));
            byteRead = buffer[(short) (OFFSET_CDATA - 1)];
        }

        // Check parameters 		
        if (buffer[OFFSET_P1] != 0x00) {
            ISOException.throwIt(SW_WRONG_P1P2);
        }
        byte p2 = buffer[OFFSET_P2];
        OwnerPIN selectedPin = accessControl.getPin(p2);
        if (selectedPin == null) {
            ISOException.throwIt(SW_WRONG_P1P2);
        }
        byte remaining = selectedPin.getTriesRemaining();

        if (byteRead > 0) {
            if (remaining == 0x00) {
                ISOException.throwIt(ISO7816EXT.SW_AUTHENTICATION_METHOD_BLOCKED);
            }
            if (selectedPin.check(buffer, OFFSET_CDATA, byteRead) == false) {
                remaining = selectedPin.getTriesRemaining();
                ISOException.throwIt((short) (ISO7816EXT.SW_VERIFICTION_FAILED | remaining));
            }
        } else {
            ISOException.throwIt(SW_SECURITY_STATUS_NOT_SATISFIED);
        }
    }

    private void generateKey(APDU apdu) {
        byte[] buffer = apdu.getBuffer();
        // buffer (B) = g^b mod p
        // K = B^a mod p
        // kENC, kMAC
        
        byte[] param_p = {(byte) 0xb1, (byte) 0x0b, (byte) 0x8f, (byte) 0x96, (byte) 0xa0, (byte) 0x80, (byte) 0xe0, (byte) 0x1d, (byte) 0xde, (byte) 0x92, (byte) 0xde, (byte) 0x5e, (byte) 0xae, (byte) 0x5d, (byte) 0x54, (byte) 0xec, (byte) 0x52, (byte) 0xc9, (byte) 0x9f, (byte) 0xbc, (byte) 0xfb, (byte) 0x06, (byte) 0xa3, (byte) 0xc6, (byte) 0x9a, (byte) 0x6a, (byte) 0x9d, (byte) 0xca, (byte) 0x52, (byte) 0xd2, (byte) 0x3b, (byte) 0x61, (byte) 0x60, (byte) 0x73, (byte) 0xe2, (byte) 0x86, (byte) 0x75, (byte) 0xa2, (byte) 0x3d, (byte) 0x18, (byte) 0x98, (byte) 0x38, (byte) 0xef, (byte) 0x1e, (byte) 0x2e, (byte) 0xe6, (byte) 0x52, (byte) 0xc0, (byte) 0x13, (byte) 0xec, (byte) 0xb4, (byte) 0xae, (byte) 0xa9, (byte) 0x06, (byte) 0x11, (byte) 0x23, (byte) 0x24, (byte) 0x97, (byte) 0x5c, (byte) 0x3c, (byte) 0xd4, (byte) 0x9b, (byte) 0x83, (byte) 0xbf, (byte) 0xac, (byte) 0xcb, (byte) 0xdd, (byte) 0x7d, (byte) 0x90, (byte) 0xc4, (byte) 0xbd, (byte) 0x70, (byte) 0x98, (byte) 0x48, (byte) 0x8e, (byte) 0x9c, (byte) 0x21, (byte) 0x9a, (byte) 0x73, (byte) 0x72, (byte) 0x4e, (byte) 0xff, (byte) 0xd6, (byte) 0xfa, (byte) 0xe5, (byte) 0x64, (byte) 0x47, (byte) 0x38, (byte) 0xfa, (byte) 0xa3, (byte) 0x1a, (byte) 0x4f, (byte) 0xf5, (byte) 0x5b, (byte) 0xcc, (byte) 0xc0, (byte) 0xa1, (byte) 0x51, (byte) 0xaf, (byte) 0x5f, (byte) 0x0d, (byte) 0xc8, (byte) 0xb4, (byte) 0xbd, (byte) 0x45, (byte) 0xbf, (byte) 0x37, (byte) 0xdf, (byte) 0x36, (byte) 0x5c, (byte) 0x1a, (byte) 0x65, (byte) 0xe6, (byte) 0x8c, (byte) 0xfd, (byte) 0xa7, (byte) 0x6d, (byte) 0x4d, (byte) 0xa7, (byte) 0x08, (byte) 0xdf, (byte) 0x1f, (byte) 0xb2, (byte) 0xbc, (byte) 0x2e, (byte) 0x4a, (byte) 0x43, (byte) 0x71};
        byte[] param_g = {(byte) 0xa4, (byte) 0xd1, (byte) 0xcb, (byte) 0xd5, (byte) 0xc3, (byte) 0xfd, (byte) 0x34, (byte) 0x12, (byte) 0x67, (byte) 0x65, (byte) 0xa4, (byte) 0x42, (byte) 0xef, (byte) 0xb9, (byte) 0x99, (byte) 0x05, (byte) 0xf8, (byte) 0x10, (byte) 0x4d, (byte) 0xd2, (byte) 0x58, (byte) 0xac, (byte) 0x50, (byte) 0x7f, (byte) 0xd6, (byte) 0x40, (byte) 0x6c, (byte) 0xff, (byte) 0x14, (byte) 0x26, (byte) 0x6d, (byte) 0x31, (byte) 0x26, (byte) 0x6f, (byte) 0xea, (byte) 0x1e, (byte) 0x5c, (byte) 0x41, (byte) 0x56, (byte) 0x4b, (byte) 0x77, (byte) 0x7e, (byte) 0x69, (byte) 0xf, (byte) 0x55, (byte) 0x04, (byte) 0xf2, (byte) 0x13, (byte) 0x16, (byte) 0x02, (byte) 0x17, (byte) 0xb4, (byte) 0xb0, (byte) 0x1b, (byte) 0x88, (byte) 0x6a, (byte) 0x5e, (byte) 0x91, (byte) 0x54, (byte) 0x7f, (byte) 0x9e, (byte) 0x27, (byte) 0x49, (byte) 0xf4, (byte) 0xd7, (byte) 0xfb, (byte) 0xd7, (byte) 0xd3, (byte) 0xb9, (byte) 0xa9, (byte) 0x2e, (byte) 0xe1, (byte) 0x90, (byte) 0x9d, (byte) 0x0d, (byte) 0x22, (byte) 0x63, (byte) 0xf8, (byte) 0x0a, (byte) 0x76, (byte) 0xa6, (byte) 0xa2, (byte) 0x4c, (byte) 0x08, (byte) 0x7a, (byte) 0x09, (byte) 0x1f, (byte) 0x53, (byte) 0x1d, (byte) 0xbf, (byte) 0x0a, (byte) 0x01, (byte) 0x69, (byte) 0xb6, (byte) 0xa2, (byte) 0x8a, (byte) 0xd6, (byte) 0x62, (byte) 0xa4, (byte) 0xd1, (byte) 0x8e, (byte) 0x73, (byte) 0xaf, (byte) 0xa3, (byte) 0x2d, (byte) 0x77, (byte) 0x9d, (byte) 0x59, (byte) 0x18, (byte) 0xd0, (byte) 0x8b, (byte) 0xc8, (byte) 0x85, (byte) 0x8f, (byte) 0x4d, (byte) 0xce, (byte) 0xf9, (byte) 0x7c, (byte) 0x2a, (byte) 0x24, (byte) 0x85, (byte) 0x5e, (byte) 0x6e, (byte) 0xeb, (byte) 0x22, (byte) 0xb3, (byte) 0xb2, (byte) 0xe5};
        RSAPrivateKey secret_a = (RSAPrivateKey) KeyBuilder.buildKey(KeyBuilder.TYPE_RSA_PRIVATE, KeyBuilder.LENGTH_RSA_1024, false);
        RandomData randomData = RandomData.getInstance(RandomData.ALG_SECURE_RANDOM);
        randomData.generateData(a, (short) 0, (short) 128);

        secret_a.setExponent(a, (short) 0, (short) PACE_KEY_LENGTH);
        secret_a.setModulus(param_p, (short) 0, (short) PACE_KEY_LENGTH);
        Cipher cipher = Cipher.getInstance(Cipher.ALG_RSA_NOPAD, false);
        cipher.init(secret_a, Cipher.MODE_DECRYPT);
        //g^a mod p

        cipher.doFinal(param_g, (short) 0, PACE_KEY_LENGTH, A, (short) 0);

        short keyStart = OFFSET_CDATA;
        if (buffer[(short) (keyStart)] == (byte) 0x00) {
            keyStart++;
        }
        // calculate K = B^a mod P
        Util.arrayCopyNonAtomic(buffer, keyStart, B, (short) 0, (short) PACE_KEY_LENGTH);
        //Util.arrayCopyNonAtomic(param_g, (short)0, B, (short)0, (short)PACE_KEY_LENGTH);

        cipher.doFinal(B, (short) 0, PACE_KEY_LENGTH, param_K, (short) 0);

        // calculate kENC
        Util.arrayCopyNonAtomic(param_K, (short) 0, buffer, (short) 0, (short) PACE_KEY_LENGTH);
        deriveKey(buffer, (short) 0, (short) PACE_KEY_LENGTH, (byte) 0x01, (short) 0);
        paceProtocol.setEncKey(buffer, (short) 0);

        apdu.setOutgoing();
        apdu.setOutgoingLength((short) A.length);
        apdu.sendBytesLong(A, (short) 0, (short) A.length);
    }

    private void deriveKey(byte[] buffer, short keySeed_offset, short keySeed_length, byte mode, short key_offset) {
        byte[] c = {0x00, 0x00, 0x00, 0x00};
        c[(short) (c.length - 1)] = mode;
        Util.arrayCopyNonAtomic(buffer, keySeed_offset, buffer, key_offset, keySeed_length);
        Util.arrayCopyNonAtomic(c, (short) 0, buffer, (short) (key_offset + keySeed_length), (short) c.length);
        MessageDigest shaDigest = MessageDigest.getInstance(MessageDigest.ALG_SHA, false);
        shaDigest.doFinal(buffer, key_offset, (short) (keySeed_length + c.length), buffer, key_offset);
        shaDigest.reset();
    }
    
    private void validateKey(APDU apdu) {
        byte[] buffer = apdu.getBuffer();
        short byteRead = apdu.setIncomingAndReceive();
        
        paceProtocol.decryptPACE(buffer, OFFSET_CDATA, byteRead, temp, (short) 1);

        short lc = Util.makeShort((byte) 0x00, temp[1]);

        temp[0] = (byte) ((lc >> 0x08) & 0xff);
        temp[1] = (byte) (lc & 0xff);
        short le = paceProtocol.encryptPACE(temp, (short) 0, (short) (lc + 2), buffer, (short) 0);

        apdu.setOutgoing();
        apdu.setOutgoingLength(le);
        apdu.sendBytesLong(buffer, (short) 0, le);
    }

}
