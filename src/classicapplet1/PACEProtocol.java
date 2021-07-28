/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package classicapplet1;

import javacard.framework.APDU;
import javacard.framework.Util;
import javacard.security.AESKey;
import javacardx.crypto.Cipher;
import javacard.security.Signature;
import javacard.security.KeyBuilder;

/**
 *
 * @author Marko
 */
public class PACEProtocol {

    final short SW_INTERNAL_ERROR = (short) 0x6d66;

    private AESKey encKey;
    private Cipher aesCipher;
    private Signature aesSig;

    private byte[] fastBuffer;

    public PACEProtocol(byte[] fastBuffer) {
        encKey = (AESKey) KeyBuilder.buildKey(KeyBuilder.TYPE_AES, KeyBuilder.LENGTH_AES_128, false);

        aesCipher = Cipher.getInstance(Cipher.ALG_AES_ECB_ISO9797_M1, false);
        aesSig = Signature.getInstance(Signature.ALG_AES_MAC_128_NOPAD, false);

        this.fastBuffer = fastBuffer;
        
    }

    public void setEncKey(byte[] enc, short encOffset) {
        encKey.setKey(enc, encOffset);
    }

    /**
     * *
     * Space to reserve in buffer when using secure messaging.
     *
     * @param plaintextLength length of plaintext in which this offset depends.
     * @return
     */
    public short getApduBufferPACEOffset(short plaintextLength) {
        short do87Bytes = 2; // 0x87 len data 0x01
        // smallest multiple of 8 strictly larger than plaintextLen + 1
        // byte is probably the length of the ciphertext (including do87 0x01)
        short do87DataLen = (short) ((((short) (plaintextLength + 16) / 16) * 16) + 1);

        if (do87DataLen < 0x80) {
            do87Bytes++;
        } else if (do87DataLen <= 0xff) {
            do87Bytes += 2;
        } else {
            do87Bytes += (short) (plaintextLength > 0xff ? 2 : 1);
        }
        return do87Bytes;
    }

    // ---------- ENC START
    public short decryptPACE(byte[] in, short sIn, short lenIn, byte[] out, short sOut) {
        aesCipher.init(encKey, Cipher.MODE_DECRYPT);
        short le = aesCipher.doFinal(in, sIn, lenIn, out, sOut);
        return le;
    }

    public short encryptPACE(byte[] in, short sIn, short lenIn, byte[] out, short sOut) {
        aesCipher.init(encKey, Cipher.MODE_ENCRYPT);
        short newlen = PACEUtil.padPACE(in, sIn, lenIn);
        aesCipher.doFinal(in, sIn, newlen, out, sOut);
        return newlen;
    }
}
