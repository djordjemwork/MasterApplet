package classicapplet1;

import javacard.framework.ISO7816;
import javacard.framework.ISOException;
import javacard.framework.OwnerPIN;

public class AccessControl {

    private static final byte PIN_MASTER = 0x00;
    private static final byte PIN_TRANSPORT = 0x01;
    private static final byte PIN_USER = 0x02;
    private static final byte PIN_TRY_LIMIT = 3;
    private static final byte MAX_PIN_SIZE = 10;
    private static final short SW_PIN_VERIFICATION_REQUIRED = 0x6301; //TODO SW_PIN_VERIFICATION_REQUIRED
    private static final short SW_SECURITY_STATUS_NOT_SATISFIED = 0x6982;
    private OwnerPIN userPin;
    private OwnerPIN transportPin;
    private OwnerPIN masterPin;
    private byte documentState;

    public AccessControl() {
        masterPin = new OwnerPIN(PIN_TRY_LIMIT, MAX_PIN_SIZE);
        transportPin = new OwnerPIN(PIN_TRY_LIMIT, MAX_PIN_SIZE);
        userPin = new OwnerPIN(PIN_TRY_LIMIT, MAX_PIN_SIZE);
        documentState = DocumentState.ReadyForPersonalization;
    }

    public void assertIcaoWrite() {
        if (documentState != DocumentState.ReadyForPersonalization) {
            ISOException.throwIt(SW_SECURITY_STATUS_NOT_SATISFIED);
        }
    }

    public OwnerPIN getUserPin() {
        return userPin;
    }

    public OwnerPIN getTransportPin() {
        return transportPin;
    }

    public OwnerPIN getMasterPin() {
        return masterPin;
    }

    public void resetUserPin() {
        if (!masterPin.isValidated()) {
            ISOException.throwIt(SW_PIN_VERIFICATION_REQUIRED);
        }
        userPin.reset();
    }

    public OwnerPIN getPin(byte p2) {
        switch (p2) {
            case PIN_MASTER:
                return masterPin;
            case PIN_TRANSPORT:
                return transportPin;
            case PIN_USER:
                return userPin;
        }
        return null;
    }

    public void changePin(byte p2, byte[] buffer, short offset, byte length) {
        checkResetPinConditions(p2);
        OwnerPIN selectedPin = this.getPin(p2);
        selectedPin.update(buffer, offset, length);
        // Initial setting of master PIN will cause user pin to be set as well.
        if (DocumentState.ReadyForPersonalization == documentState) {
            if (PIN_MASTER == p2) {
                selectedPin = this.getPin(PIN_USER);
                selectedPin.update(buffer, offset, length);
            }
        }
    }

    public void resetPin(byte p2) {
        checkResetPinConditions(p2);
        OwnerPIN selectedPin = this.getPin(p2);
        selectedPin.resetAndUnblock();
    }

    public void checkResetPinConditions(byte pin) {
        switch (pin) {
            case PIN_MASTER:
                if (documentState != DocumentState.ReadyForPersonalization) {
                    ISOException.throwIt(SW_SECURITY_STATUS_NOT_SATISFIED);
                }
                break;
            case PIN_TRANSPORT:
                if (this.masterPin.isValidated() == false) {
                    ISOException.throwIt(SW_SECURITY_STATUS_NOT_SATISFIED);
                }
                break;
            case PIN_USER:
                if (userPin.isValidated() == false) {
                    if (masterPin.isValidated() == false) {
                        ISOException.throwIt(SW_SECURITY_STATUS_NOT_SATISFIED);
                    }
                }
                break;
        }
    }

    public void checkDocumentSetConditions(byte newState) {
        if (masterPin.isValidated() == false) {
            ISOException.throwIt(SW_SECURITY_STATUS_NOT_SATISFIED);
        }
        switch (documentState) {
            case DocumentState.ReadyForPersonalization:
                if (newState != DocumentState.Personalized) {
                    ISOException.throwIt(SW_SECURITY_STATUS_NOT_SATISFIED);
                }
                break;
            case DocumentState.Personalized:
                if (newState != DocumentState.Issued) {
                    ISOException.throwIt(SW_SECURITY_STATUS_NOT_SATISFIED);
                }
                break;
            case DocumentState.Issued:
                break;
            default:
                ISOException.throwIt(SW_SECURITY_STATUS_NOT_SATISFIED);
        }
    }

    public void checkAsymmetricKeyPairGenerationConditions() {
        if (userPin.isValidated() == false) {
            ISOException.throwIt(SW_SECURITY_STATUS_NOT_SATISFIED);
        }
    }

    public void checkCryptoOperationConditions() {
        if (userPin.isValidated() == false) {
            ISOException.throwIt(SW_SECURITY_STATUS_NOT_SATISFIED);
        }
    }
    
    public void checkCertificateModificationStatus() {
        if (DocumentState.ReadyForPersonalization == this.documentState) {
            // Allow modification by security officer only in this case
            if (this.masterPin.isValidated()) {
                return;
            }

        }
        if (userPin.isValidated() == false) {
            ISOException.throwIt(SW_SECURITY_STATUS_NOT_SATISFIED);
        }
    }

    public void checkUserOrMaster() {
        if (!userPin.isValidated() && !masterPin.isValidated()) {
            ISOException.throwIt(SW_SECURITY_STATUS_NOT_SATISFIED);
        }
    }

    public boolean checkIsMasterPinVerified() {
        return masterPin.isValidated();
    }

    public void setDocumentState(byte documentState) {
        checkDocumentSetConditions(documentState);
        this.documentState = documentState;
    }

    public byte getDocumentState() {
        return documentState;
    }

    public void resetPins() {
        masterPin.reset();
        transportPin.reset();
        userPin.reset();
    }
}
