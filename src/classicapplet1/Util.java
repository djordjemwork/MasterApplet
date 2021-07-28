package classicapplet1;

import javacard.framework.ISO7816;

public class Util implements ISO7816 {

    public static short pad(byte[] buffer, short offset, short len) {
        short padbytes = (short) (lengthWithPadding(len) - len);

        for (short i = 0; i < padbytes; i++) {
            buffer[(short) (offset + len + i)] = (i == 0 ? (byte) 0x80 : 0x00);
        }

        return (short) (len + padbytes);
    }

    public static short lengthWithPadding(short inputLength) {
        return (short) ((((short) (inputLength + 16)) / 16) * 16);
    }
}
