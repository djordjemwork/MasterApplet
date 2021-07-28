package classicapplet1;

public interface ISO7816EXT {

    /**
     * Defines instruction 7816-4 READ BINARY
     */
    final static byte INS_READ_BINARY = (byte) 0xB0;
    /**
     * Defines instruction 7816-4 UPDATE BINARY
     */
    final static byte INS_UPDATE_BINARY = (byte) 0xD6;
    /**
     * Defines instruction 7816-9 CREATE FILE
     */
    final static byte INS_CREATE_FILE = (byte) 0xE0;
    /**
     * Defines instruction for geting object data
     */
    final static byte INS_GET_DATA2 = (byte) 0xCB;
    /**
     * Defines instruction for importing data object
     */
    final static byte INS_PUT_DATA2 = (byte) 0xDB;
    final static byte INS_PUT_DATA1 = (byte) 0xDA;

    /**
     * Defines instruction for verification
     */
    final static byte INS_VERIFY_1 = 0x20;
    /**
     * Defines alternative instruction for verification
     */
    final static byte INS_VERIFY_2 = 0x21;
    /**
     * Defines RESET_RETRY_COUNTER
     */
    final static byte INS_RESET_RETRY_COUNTER = 0x2C;
    /**
     * Defines GET_RESPONSE command
     */
    static final byte INS_GET_RESPONSE = (byte) 0xC0;

    final static byte INS_GENERATE_ASYMMETRIC_KEY_PAIR_1 = 0x46;
    final static byte INS_GENERATE_ASYMMETRIC_KEY_PAIR_2 = 0x47;
    final static byte INS_PERFORM_SECURITY_OPERATION = 0x2A;
    final static byte INS_MANAGE_SECURITY_ENVIRONMENT = 0x22;

    /**
     * Designates blocked PIN code
     */
    final static short SW_AUTHENTICATION_METHOD_BLOCKED = 0x6983;
    final static short SW_VERIFICTION_FAILED = 0x63C0;
    final static short SW_REFERENCE_DATA_NOT_USABLE = 0x6984;
    /**
     * Error code indicating error in command chaining
     */

    final static byte MASK_MSE_FUNCTION = 0x0F;
    final static byte MSE_SET_FUNCTION = 0x01;
    final static byte MSE_STORE_FUNCTION = 0x02;
    final static byte MSE_RESTORE_FUNCTION = 0x03;
    final static byte MSE_ERASE_FUNCTION = 0x04;

    final static byte PSO_PLAIN_VALUE = (byte) 0x80;
    final static byte PSO_CRYPTOGRAPHIC_CHECKSUM = (byte) 0x8E;
    final static byte PSO_HASH_CODE = (byte) 0x90;
    final static byte PSO_CERTIFICATE = (byte) 0x92;
    final static byte PSO_PUBLIC_KEY = (byte) 0x9C;
    final static byte PSO_DIGITAL_SIGNATURE = (byte) 0x9E;

    final static byte PSO_TEMPLATE_HASH_CODE = (byte) 0xA0;
    final static byte PSO_TEMPLATE_CRYPTOGRAPHIC_CHECKSUM = (byte) 0xA2;
    final static byte PSO_TEMPLATE_VERIFY_DIGITAL_SIGNATURE = (byte) 0xA8;
    final static byte PSO_TEMPLATE_COMPUTE_DIGITAL_SIGNATURE_CONCATENATED = (byte) 0xAC;
    final static byte PSO_TEMPLATE_VERIFY_CERTIFICATE_CONCATENATED = (byte) 0xAE;
    final static byte PSO_TEMPLATE_COMPUTE_DIGITAL_SIGNATURE_SIGNED = (byte) 0xBC;
    final static byte PSO_TEMPLATE_VERIFY_CERTIFICATE_CERTIFIED = (byte) 0xBE;
    static final short SW_LAST_COMMAND_EXPECTED = 26755;
}
