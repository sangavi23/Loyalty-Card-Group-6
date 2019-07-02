package card;
import javacard.framework.*;
import javacard.security.*;
import javacardx.crypto.*;
import java.lang.*;
import java.util.*;

/**
 * This is the Card Applet for the Loyalty Card Project by:
 * @author Hvroje Fabris
 * @author Anna Guinet
 * The application is based on previous work as framework by Geert Smelt and Robin Oostrum
 */

public class Card extends Applet implements ISO7816 {
	private static final short AUTH_STEP = 0;
	private static final short AUTH_TERMINAL = 1;
	byte[] temp;
	byte[] authBuf;
	byte[] authState;
	byte[] N_T;
	byte[] terminalID;
	byte state = CONSTANTS.STATE_ISSUED;
	byte[] cardID = new byte[CONSTANTS.NAME_LENGTH];
	Crypto crypto;
	public Card() {
		crypto = new Crypto(this);
		try {
			temp = JCSystem.makeTransientByteArray(CONSTANTS.APDU_DATA_SIZE_MAX, JCSystem.CLEAR_ON_DESELECT);
			authBuf = JCSystem.makeTransientByteArray(CONSTANTS.DATA_SIZE_MAX, JCSystem.CLEAR_ON_DESELECT); 
			authState = JCSystem.makeTransientByteArray((short) 2, JCSystem.CLEAR_ON_DESELECT);
			N_T = JCSystem.makeTransientByteArray((short) CONSTANTS.NONCE_LENGTH, JCSystem.CLEAR_ON_DESELECT);
			terminalID = JCSystem.makeTransientByteArray(CONSTANTS.NAME_LENGTH, JCSystem.CLEAR_ON_DESELECT);
		} catch (SystemException e) {
			throwException(e.getReason());
		}
	}

	public static void install(byte[] bArray, short bOffset, byte bLength) {
		new Card().register(bArray, (short) (bOffset + 1), bArray[bOffset]);
	}

	public void process(APDU apdu) throws ISOException, APDUException {
		if (selectingApplet()) {
			return;
		}
		short responseSize = 0;
		byte[] buf = apdu.getBuffer();

		byte cla = buf[ISO7816.OFFSET_CLA];
		byte ins = buf[ISO7816.OFFSET_INS];
		byte p1 = buf[ISO7816.OFFSET_P1];
		byte p2 = buf[ISO7816.OFFSET_P2];
		short lc = (short) (buf[ISO7816.OFFSET_LC] & 0x00FF);

		if (lc > CONSTANTS.APDU_SIZE_MAX || lc == 0) {
			resetSession();
			return;
		}

		short bytesRead = 0;
		if (ins == CONSTANTS.INS_AUTHENTICATE) {
			bytesRead = readData(apdu, authBuf);
			responseSize = processFurther(authBuf, bytesRead, cla, ins, p1, p2);
		} else {
			bytesRead = readData(apdu, temp);
			responseSize = processFurther(temp, bytesRead, cla, ins, p1, p2);
		}

		if (responseSize != 0) {
			sendData(ins, ins == CONSTANTS.INS_AUTHENTICATE ? authBuf : temp, responseSize, apdu);
		} 
		return;
	}
	private short processFurther(byte[] buf, short length, byte cla, byte ins, byte p1, byte p2) {
		short responseSize = 0;

		try {
			responseSize = handleInstruction(cla, ins, p1, p2, length, buf);
		} catch (UserException e) {
			throwException(e.getReason());
		}
		if (responseSize > buf.length) {
			resetSession();
			return 0;
		}

		return responseSize;
	}
	private short handleInstruction(byte cla, byte ins, byte p1, byte p2, short length, byte[] buffer) throws UserException {
		short responseSize = 0;

		switch (state) {
		case CONSTANTS.STATE_ISSUED:
			switch (ins) {
			case CONSTANTS.INS_REVOKE:
				responseSize = revokeCard();
				break;
			case CONSTANTS.INS_GET_PUBKEY:
				responseSize = crypto.getPubKeyCard(buffer, (short) 0);
				break;
			case CONSTANTS.INS_AUTHENTICATE:
				responseSize = authenticate(p1, p2, length, buffer);
				break;
			case CONSTANTS.INS_BAL_INC:
				responseSize = addBalance(buffer, length);
				break;
			case CONSTANTS.INS_BAL_DEC:
				responseSize = subBalance(buffer, length);
				break;
			case CONSTANTS.INS_BAL_CHECK:
				responseSize = checkBalance(buffer);
				break;
			default:
				throwException(CONSTANTS.SW1_INS_NOT_SUPPORTED, ins);
			}
			break;
		case CONSTANTS.STATE_INIT:
			switch (ins) {
			case CONSTANTS.INS_PERSONALIZE_WRITE:
				issue(buffer, length);
				break;
			default:
				throwException(CONSTANTS.SW1_INS_NOT_SUPPORTED, ins);
			}
		case CONSTANTS.STATE_REVOKED:
			throwException(CONSTANTS.SW1_COMMAND_NOT_ALLOWED_00, CONSTANTS.SW2_CARD_REVOKED);
		default:
			ISOException.throwIt(SW_CONDITIONS_NOT_SATISFIED);
		}

		return responseSize;
	}

	short readData(APDU apdu, byte[] data) {
		byte[] buffer = apdu.getBuffer();

		short offset = 0;
		short readCount = apdu.setIncomingAndReceive();
		if (readCount > data.length) {
			memoryFull(data);
			return 0;
		}
		Util.arrayCopyNonAtomic(buffer, ISO7816.OFFSET_CDATA, data, offset, readCount);
		offset += readCount;

		while (apdu.getCurrentState() == APDU.STATE_PARTIAL_INCOMING) {
			readCount = apdu.receiveBytes(ISO7816.OFFSET_CDATA);
			if ((short)(offset + readCount) > (short) data.length) {
				memoryFull(data);
				return 0;
			}
			Util.arrayCopyNonAtomic(buffer, ISO7816.OFFSET_CDATA, data, offset, readCount);
			offset += readCount;
		}
		return offset;
	}
	
	private void sendData(short type, byte[] data, short length, APDU apdu) {
		switch (type) {
		case CONSTANTS.INS_AUTHENTICATE:
			sendRSAEncData(crypto.getPubKeySupermarket(), data, length, apdu);
			break;
		case CONSTANTS.INS_GET_PUBKEY:
			sendDataInClear(data, length, apdu);
			break;
		default:
			sendSymEncData(data, length, apdu);
			break;
		}
	}
	private void sendSymEncData(byte[] data, short length, APDU apdu) {
		if (crypto.authenticated()) {
			length = crypto.symEncrypt(data, (short) 0, length, data, (short) 0);
		} else {
			throwException(CONSTANTS.SW1_AUTH_EXCEPTION, CONSTANTS.SW2_NO_AUTH_PERFORMED);
		}
		if (length > CONSTANTS.APDU_DATA_SIZE_MAX || length <= 0) {
			throwException(ISO7816.SW_WRONG_LENGTH);
			return;
		}

		apdu.setOutgoing();
		apdu.setOutgoingLength(length);
		apdu.sendBytesLong(data, (short) 0, length);
		return;
	}

	private void sendRSAEncData(Key key, byte[] data, short length, APDU apdu) {
		length = crypto.pubEncrypt(key, data, (short) 0, length, data, (short) 0);
		 
		if (length > CONSTANTS.APDU_DATA_SIZE_MAX || length <= 0) {
			throwException(ISO7816.SW_WRONG_LENGTH);
			return;
		}
		apdu.setOutgoing();
		apdu.setOutgoingLength(length);
		apdu.sendBytesLong(data, (short) 0, length);
	}
	
	private void sendDataInClear(byte[] data, short length, APDU apdu) {
		if (length > CONSTANTS.APDU_DATA_SIZE_MAX || length <= 0) {
			throwException(ISO7816.SW_WRONG_LENGTH);
			return;
		}
		
		apdu.setOutgoing();
		apdu.setOutgoingLength(length);
		apdu.sendBytesLong(data, (short) 0, length);
	}

	public boolean checkIssued() {
		return (state == CONSTANTS.STATE_ISSUED);
	}
	
	private void issue(byte[] buffer, short length) {
		if (checkIssued()) {
			throwException(CONSTANTS.SW1_ALREADY_PERSONALIZED);
		}
		
		JCSystem.beginTransaction();
		Util.arrayCopyNonAtomic(buffer, (short) 0, cardID, (short) 0, length);
		state = CONSTANTS.STATE_ISSUED;
		JCSystem.commitTransaction();
		
		return;
	}
	
	
	private short authenticate(byte to, byte step, short length, byte[] buffer) throws UserException {
		short outLength = 0;
		if (step != authState[AUTH_STEP] + 1) {
			resetSession();
			return 0;
		}

		try {
			switch (step) {
			case CONSTANTS.P2_AUTHENTICATE_STEP1:
				outLength = authenticate2(to, length, buffer);
				break;
			case CONSTANTS.P2_AUTHENTICATE_STEP2:
				outLength = authenticate3(to, length, buffer);
				break;
			default:
				throwException(ISO7816.SW_WRONG_P1P2);
			}
		} catch (UserException e) {
			resetSession();
			return 0;
		}

		if (outLength == 0) {
			resetSession();
			return 0;
		} else {
			authState[AUTH_STEP] = step;
			authState[AUTH_TERMINAL] = to;
			if (authState[AUTH_STEP] == CONSTANTS.P2_AUTHENTICATE_STEP2) {
				crypto.enable();
			}
			return outLength;
		}
	}
	private short authenticate2(byte to, short length, byte[] buffer) throws UserException {
		short responseSize = 0;
		if (to != CONSTANTS.P1_AUTHENTICATE_CARD) {
			resetSession();
			UserException.throwIt(CONSTANTS.SW2_AUTH_WRONG_PARTNER);
			return 0; 
		}

		if (authState[AUTH_TERMINAL] != 0) {
			resetSession();
			throwException(CONSTANTS.SW1_WRONG_PARAMETERS, CONSTANTS.SW2_AUTH_WRONG_PARTNER);
			return 0;
		}

		try {
			Util.arrayCopyNonAtomic(buffer, CONSTANTS.AUTH_MSG_1_OFFSET_NAME_TERM, 
					terminalID, (short) 0, CONSTANTS.NAME_LENGTH);
		} catch (Exception e) {
			throwException(CONSTANTS.SW1_WRONG_PARAMETERS);
		}

		clear(buffer);

		try {
			responseSize += Util.arrayCopyNonAtomic(cardID, (short) 0, buffer, 
					CONSTANTS.AUTH_MSG_2_OFFSET_NAME_CARD, CONSTANTS.NAME_LENGTH);

			responseSize += Util.arrayCopyNonAtomic(terminalID, (short) 0, buffer,
					CONSTANTS.AUTH_MSG_2_OFFSET_NAME_TERM, CONSTANTS.NAME_LENGTH);

			crypto.generateCardNonce();
			responseSize += crypto.getCardNonce(buffer, CONSTANTS.AUTH_MSG_2_OFFSET_NC);
		} catch (Exception e) {
			throwException(((CardRuntimeException) e).getReason());
		}

		return responseSize;
	}

	
	private short authenticate3(byte to, short length, byte[] buffer) throws UserException {
		short responseSize = 0;

		if (authState[AUTH_TERMINAL] != to) {
			resetSession();
			UserException.throwIt((short) CONSTANTS.SW2_AUTH_WRONG_PARTNER);
			return 0;
		}

		if (to != CONSTANTS.P1_AUTHENTICATE_CARD) { 
			resetSession();
			Card.throwException(CONSTANTS.SW1_WRONG_PARAMETERS, CONSTANTS.SW2_AUTH_WRONG_PARTNER);
			return 0;
		}

		length = crypto.pubDecrypt(buffer, (short) 0, length, buffer, (short) 0);

		if (length != CONSTANTS.AUTH_MSG_3_TOTAL_LENGTH) {
			resetSession();
			throwException(CONSTANTS.SW1_WRONG_LE_FIELD_00, CONSTANTS.SW2_AUTH_WRONG_2);
			return 0;
		}

		if (Util.arrayCompare(buffer, CONSTANTS.AUTH_MSG_3_OFFSET_NAME_CARD, cardID, (short) 0, CONSTANTS.NAME_LENGTH) != 0) {
			resetSession();
			throwException(CONSTANTS.SW1_AUTH_EXCEPTION, CONSTANTS.SW2_AUTH_WRONG_PARTNER);
			return 0;
		}
	
		Util.arrayCopyNonAtomic(buffer, CONSTANTS.AUTH_MSG_3_OFFSET_NAME_TERM, terminalID, (short) 0, CONSTANTS.NAME_LENGTH);

		if (!crypto.checkCardNonce(buffer, CONSTANTS.AUTH_MSG_3_OFFSET_NC)) {
			resetSession();
			throwException(CONSTANTS.SW1_AUTH_EXCEPTION, CONSTANTS.SW2_AUTH_WRONG_NONCE);
			return 0;
		}

		Util.arrayCopyNonAtomic(buffer, CONSTANTS.AUTH_MSG_3_OFFSET_NT, N_T, (short) 0, CONSTANTS.NONCE_LENGTH);

		clear(buffer);

		try {
			responseSize += Util.arrayCopyNonAtomic(CONSTANTS.NAME_CARD, (short) 0, buffer, CONSTANTS.AUTH_MSG_4_OFFSET_NAME_CARD, CONSTANTS.NAME_LENGTH);
			responseSize += Util.arrayCopyNonAtomic(terminalID, (short) 0, buffer, CONSTANTS.AUTH_MSG_4_OFFSET_NAME_TERM, CONSTANTS.NAME_LENGTH);
			responseSize += Util.arrayCopyNonAtomic(N_T, (short) 0, buffer, CONSTANTS.AUTH_MSG_4_OFFSET_NT, CONSTANTS.NONCE_LENGTH);
		} catch (Exception e) {
			resetSession();
			throwException(((CardException) e).getReason());
			return 0;
		}

		crypto.generateSessionKey();
		if (crypto.getSessionKey(buffer, CONSTANTS.AUTH_MSG_4_OFFSET_SESSION_KEY) != CONSTANTS.AES_KEY_LENGTH) {
			resetSession();
			throwException(CONSTANTS.SW1_CRYPTO_EXCEPTION, CONSTANTS.SW2_UNSUPPORTED_CRYPTO_MODE);
			return 0;
		} else {
			responseSize += CONSTANTS.AES_KEY_LENGTH;
		}

		return responseSize;
	}

	private short addBalance(byte[] buffer, short length) throws UserException {
		short responseSize = 0;
		byte[] data = new byte[length];
		byte[] hash = new byte[CONSTANTS.MAC_LENGTH];
		byte[] credits = new byte[CONSTANTS.CREDITS_LENGTH];
		
		length = crypto.symDecrypt(buffer, (short) 0, length, data, (short) 0);
		if (length != CONSTANTS.CREDITS_LENGTH + CONSTANTS.MAC_LENGTH) {
			throwException(CONSTANTS.SW2_CREDITS_WRONG_LENGTH);
		}
		
		Util.arrayCopyNonAtomic(data, CONSTANTS.CREDITS_LENGTH, hash, (short) 0, CONSTANTS.MAC_LENGTH);
		Util.arrayCopyNonAtomic(data, (short) 0, credits, (short) 0, CONSTANTS.CREDITS_LENGTH);
		if (!crypto.verifyHash(credits, hash)) {
			throwException(CONSTANTS.SW1_CRYPTO_EXCEPTION, CONSTANTS.SW2_WRONG_HASH);
		}

		short amount = Util.getShort(credits, (short) 0);
		
		if (amount > CONSTANTS.CREDITS_MAX) {
			throwException(CONSTANTS.SW2_CREDITS_TOO_MANY);
		} else {
			try {
				JCSystem.beginTransaction();
				responseSize = Util.setShort(buffer, (short) 0, crypto.addCredits(amount));
				JCSystem.commitTransaction();
			} catch (ISOException ie) {
				throwException(CONSTANTS.SW2_CREDITS_NEGATIVE);
			} catch (TransactionException te) {
				throwException(CONSTANTS.SW2_INTERNAL_ERROR);
			}
		}
		return responseSize;
	}
	
	private short subBalance(byte[] buffer, short length) throws UserException {
		short responseSize = 0;
		byte[] data = new byte[length];
		byte[] hash = new byte[CONSTANTS.MAC_LENGTH];
		byte[] credits = new byte[CONSTANTS.CREDITS_LENGTH];
		
		length = crypto.symDecrypt(buffer, (short) 0, length, data, (short) 0);
		if (length != CONSTANTS.CREDITS_LENGTH + CONSTANTS.MAC_LENGTH) {
			throwException(CONSTANTS.SW2_CREDITS_WRONG_LENGTH);
		}
		
		Util.arrayCopyNonAtomic(data, CONSTANTS.CREDITS_LENGTH, hash, (short) 0, CONSTANTS.MAC_LENGTH);
		Util.arrayCopyNonAtomic(data, (short) 0, credits, (short) 0, CONSTANTS.CREDITS_LENGTH);

		if (!crypto.verifyHash(credits, hash)) {
			throwException(CONSTANTS.SW1_CRYPTO_EXCEPTION, CONSTANTS.SW2_WRONG_HASH);
		}
		
		short amount = Util.getShort(data, (short) 0);

		if (amount > CONSTANTS.CREDITS_MAX) {
			throwException(CONSTANTS.SW2_CREDITS_TOO_MANY);
		} else {
			try {
				JCSystem.beginTransaction();
				responseSize = Util.setShort(buffer, (short) 0, crypto.subCredits(amount));
				JCSystem.commitTransaction();
			} catch (ISOException ie) {
				throwException(CONSTANTS.SW2_CREDITS_NEGATIVE);
			} catch (TransactionException te) {
				throwException(CONSTANTS.SW2_INTERNAL_ERROR);
			}
		}

		return responseSize;
	}

	private short checkBalance(byte[] buffer) {
		short responseSize = 0;
		if (crypto.authenticated()) {
			responseSize = Util.setShort(buffer, (short) 0, crypto.getBalance());
		} else {
			throwException(CONSTANTS.SW1_COMMAND_NOT_ALLOWED_00, CONSTANTS.SW2_NO_AUTH_PERFORMED);
			return 0;
		}
		return responseSize;
	}

	private void memoryFull(byte[] buf) {
		throwException(ISO7816.SW_FILE_FULL);
		clear(buf);
	}

	private short revokeCard() {
		resetSession();
		JCSystem.beginTransaction();
		state = CONSTANTS.STATE_REVOKED;
		JCSystem.commitTransaction();
		return (short) 1;
	}

	void resetSession() {
		clear(temp);
		clear(authBuf);
		clear(authState);
		clear(terminalID);
		crypto.clearSessionData();
	}

	private void clear(byte[] buf) {
		Util.arrayFillNonAtomic(buf, (short) 0, (short) buf.length, (byte) 0);
	}
	
	public static final void throwException(byte b1, byte b2) {
		throwException(Util.makeShort(b1, b2));
	}

	public static final void throwException(short reason) {
		ISOException.throwIt(reason);
	}

}

final class Crypto {

	private Cipher rsaCipher;
	private Cipher aesCipher;

	private RandomData random;
	private byte[] cardNonce;
	private byte[] tmpKey;
	private AESKey sessionKey;
	private MessageDigest digest;
	private RSAPrivateCrtKey privKeyCard;
	private RSAPublicKey pubKeySupermarket;
	private RSAPublicKey pubKeyCard;
	private byte[] authState;
	private short balance;
	private Card c;
	public Crypto(Card card) {
		
		pubKeyCard = (RSAPublicKey) KeyBuilder.buildKey(KeyBuilder.TYPE_RSA_PUBLIC, 
				KeyBuilder.LENGTH_RSA_512, false); 
        privKeyCard = (RSAPrivateCrtKey) KeyBuilder.buildKey(KeyBuilder.TYPE_RSA_CRT_PRIVATE, 
        		KeyBuilder.LENGTH_RSA_512, false); 
                   
        KeyPair keypair = new KeyPair(KeyPair.ALG_RSA_CRT, KeyBuilder.LENGTH_RSA_512); 
        keypair.genKeyPair(); 
        pubKeyCard = (RSAPublicKey) keypair.getPublic(); 
        privKeyCard = (RSAPrivateCrtKey) keypair.getPrivate();
        
        pubKeySupermarket = (RSAPublicKey) KeyBuilder.buildKey(KeyBuilder.TYPE_RSA_PUBLIC,
        		KeyBuilder.LENGTH_RSA_512, false);
        pubKeySupermarket.setExponent(SupermarketRSAKey.getExponent(), (short) 0,
        		(short) SupermarketRSAKey.getExponent().length);
        pubKeySupermarket.setModulus(SupermarketRSAKey.getModulus(), (short) 0,
        		(short) SupermarketRSAKey.getModulus().length);
        
		sessionKey = (AESKey) KeyBuilder.buildKey(KeyBuilder.TYPE_AES_TRANSIENT_DESELECT, 
				KeyBuilder.LENGTH_AES_128, false);

		rsaCipher = Cipher.getInstance(Cipher.ALG_RSA_PKCS1, false);
		aesCipher = Cipher.getInstance(Cipher.ALG_AES_BLOCK_128_CBC_NOPAD, false);

		digest = MessageDigest.getInstance(MessageDigest.ALG_SHA, false);
		
		cardNonce = JCSystem.makeTransientByteArray(CONSTANTS.NONCE_LENGTH, JCSystem.CLEAR_ON_DESELECT);
		tmpKey = JCSystem.makeTransientByteArray(CONSTANTS.AES_KEY_LENGTH, JCSystem.CLEAR_ON_DESELECT);
		
		random = RandomData.getInstance(RandomData.ALG_SECURE_RANDOM);

		authState = JCSystem.makeTransientByteArray((short) 1, JCSystem.CLEAR_ON_DESELECT);

		balance = (short) 0;

		c = card;
	}

	short symEncrypt(byte[] plaintext, short ptOff, short ptLen, byte[] ciphertext, short ctOff) {
		if (!authenticated()) {
			return 0;
		}

		verifyBufferLength(plaintext, ptOff, ptLen);
		verifyBufferLength(ciphertext, ctOff);
		Util.arrayCopyNonAtomic(plaintext, ptOff, ciphertext, (short) (ctOff + 2), ptLen);

		ciphertext[0] = (byte) (ptLen >> 8 & 0xff);
		ciphertext[1] = (byte) (ptLen & 0xff);
		ptLen += 2;

		short pad = (short) (16 - (ptLen % 16));
		if ((short) (ptOff + ptLen + pad) > (short) plaintext.length) {
			c.resetSession();
			return 0;
		}

		Util.arrayFillNonAtomic(ciphertext, (short) (ctOff + ptLen), pad, (byte) 0);
		ptLen = (short) (ptLen + pad);

		if (ptLen % 16 != 0) {
			c.resetSession();
			return 0;
		}
		if (!sessionKey.isInitialized()) {
			generateSessionKey();
		}

		short length = 0;
		try {
			aesCipher.init(sessionKey, Cipher.MODE_ENCRYPT);
			length = aesCipher.doFinal(ciphertext, ctOff, ptLen, ciphertext, ctOff);
		} catch (CryptoException ce) {
			c.resetSession();
		}
		return length;
	}

	short symDecrypt(byte[] ciphertext, short ctOff, short ctLen, byte[] plaintext, short ptOff) {

		if (!authenticated()) {
			c.resetSession();
			return 0;
		}
		verifyBufferLength(ciphertext, ctOff, ctLen);
		verifyBufferLength(plaintext, ptOff);

		if ((short)(ctLen - ctOff) % 16 != 0) {
			c.resetSession();
			return 0;
		}
		
		short length = 0;
		try {
			aesCipher.init(sessionKey, Cipher.MODE_DECRYPT);
			length = aesCipher.doFinal(ciphertext, ctOff, ctLen, plaintext, ptOff);
		} catch (CryptoException ce) {
			c.resetSession();
		}

		length = Util.getShort(plaintext, ptOff);
		Util.arrayCopyNonAtomic(plaintext, (short) (ptOff + 2), plaintext, ptOff, length);

		return length;
	}

	short pubEncrypt(Key key, byte[] plaintext, short ptOff, short ptLen, byte[] ciphertext, short ctOff) {
		verifyBufferLength(plaintext, ptOff, ptLen);
		verifyBufferLength(ciphertext, ctOff);
		
		short numberOfBytes = 0;
		
		try {
			rsaCipher.init(key, Cipher.MODE_ENCRYPT);
			numberOfBytes = rsaCipher.doFinal(plaintext, ptOff, ptLen, ciphertext, ctOff);
		} catch (CryptoException ce) {
			c.resetSession();
			return 0;
		}
		return numberOfBytes;
	}

	short pubDecrypt(byte[] ciphertext, short ctOff, short ctLen, byte[] plaintext, short ptOff) {
		verifyBufferLength(ciphertext, ctOff, ctLen);
		verifyBufferLength(plaintext, ptOff);
		
		short numberOfBytes = 0;

		try {
			rsaCipher.init(privKeyCard, Cipher.MODE_DECRYPT);
			numberOfBytes = rsaCipher.doFinal(ciphertext, ctOff, ctLen, plaintext, ptOff);
		} catch (CryptoException ce) {
			c.resetSession();
			return 0;
		}

		return numberOfBytes;
	}

	public boolean verifyHash(byte[] input, byte[] hash) {
		byte[] hashedInput = new byte[CONSTANTS.MAC_LENGTH];
		digest.doFinal(input, (short) 0, (short) input.length, hashedInput, (short) 0);
		return (Util.arrayCompare(hashedInput, (short) 0, hash, (short) 0, CONSTANTS.MAC_LENGTH) == 0);
	}
	
	void generateSessionKey() {
		fillRandom(tmpKey);
		sessionKey.setKey(tmpKey, (short) 0);
		Util.arrayFillNonAtomic(tmpKey, (short) 0, (short) tmpKey.length, (byte) 0);
	}

	void generateCardNonce() {
		fillRandom(cardNonce);
	}

	boolean checkCardNonce(byte[] buffer, short offset) {
		return Util.arrayCompare(buffer, CONSTANTS.AUTH_MSG_3_OFFSET_NC, cardNonce, (short) 0, CONSTANTS.NONCE_LENGTH) == 0;
	}

	private void fillRandom(byte[] buf) {
		random.generateData(buf, (short) 0, (short) buf.length);
	}

	void clearSessionData() {
		sessionKey.clearKey();
		Util.arrayFillNonAtomic(tmpKey, (short) 0, (short) tmpKey.length, (byte) 0);
		Util.arrayFillNonAtomic(cardNonce, (short) 0, (short) cardNonce.length, (byte) 0);
		disable();
	}

	private void verifyBufferLength(byte[] buf, short offset) {
		if (offset < 0 || offset >= buf.length) {
			Card.throwException(CONSTANTS.SW1_NO_PRECISE_DIAGNOSIS, CONSTANTS.SW2_INTERNAL_ERROR);
		}
	}

	private void verifyBufferLength(byte[] buf, short offset, short length) {
		if (offset < 0 || length < 0 || (short) (offset + length) >= (short) buf.length) {
			Card.throwException(CONSTANTS.SW1_NO_PRECISE_DIAGNOSIS, CONSTANTS.SW2_INTERNAL_ERROR);
		}
	}
	
	short subCredits(short amount) {
		if (amount < 0 || balance < amount) {
			Card.throwException(CONSTANTS.SW1_WRONG_PARAMETERS, CONSTANTS.SW2_CREDITS_INSUFFICIENT);
		} else {
			balance -= amount;
		}
		return balance;
	}

	short addCredits(short amount) {
		if (amount < 0) {
			Card.throwException(CONSTANTS.SW1_WRONG_PARAMETERS, CONSTANTS.SW2_CREDITS_NEGATIVE);
		} else {
			balance += amount;
		}
		return balance;
	}

	boolean authenticated() {
		return authState[0] == CONSTANTS.SESSION_ESTABLISHED;
	}

	void enable() {
		authState[0] = CONSTANTS.SESSION_ESTABLISHED;
	}
	
	void disable() {
		authState[0] = CONSTANTS.NO_ACTIVE_SESSION;
	}

	short issueCard() {
		if (c.state == CONSTANTS.STATE_ISSUED) {
			Card.throwException(CONSTANTS.SW1_COMMAND_NOT_ALLOWED_00, CONSTANTS.SW2_ALREADY_ISSUED);
			return 0;
		} else {
			c.state = CONSTANTS.STATE_ISSUED;
			return 1;      
		}
	}

	short getBalance() {
		if (!authenticated()) {
			Card.throwException(CONSTANTS.SW1_AUTH_EXCEPTION, CONSTANTS.SW2_NO_AUTH_PERFORMED);
			return 0;
		} else {
			return balance;
		}
	}

	short getCardName(byte[] buffer, short offset) {
		try {
			Util.arrayCopyNonAtomic(CONSTANTS.NAME_CARD, (short) 0, buffer, offset, CONSTANTS.NAME_LENGTH);
		} catch (Exception e) {
			Card.throwException(((CardRuntimeException) e).getReason());
			return 0;
		}
		return CONSTANTS.NAME_LENGTH;
	}

	short getCardNonce(byte[] buffer, short offset) {
		return Util.arrayCopyNonAtomic(cardNonce, (short) 0, buffer, offset, CONSTANTS.NONCE_LENGTH);
	}

	short getSessionKey(byte[] buffer, short offset) {
		short len = 0;
		try {
			len = sessionKey.getKey(buffer, offset);
		} catch (CryptoException ce) {
			c.resetSession();
			Card.throwException(CONSTANTS.SW1_SECURITY_RELATED_ISSUE_00, (byte) ce.getReason()); 
			return 0;
		}
		return len;
	}

	public short getPubKeyCard(byte[] buf, short offset) {
		short totalLength = 0;
		if (!pubKeyCard.isInitialized()) {
			Card.throwException(CONSTANTS.SW1_CRYPTO_EXCEPTION, CONSTANTS.SW2_AUTH_PARTNER_KEY_NOT_INIT);
			return 0;
		} else if (buf.length < CONSTANTS.RSA_PUBKEY_LENGTH) {
			Card.throwException(CONSTANTS.SW1_WRONG_LENGTH);
			return 0;
		} else {
			totalLength += pubKeyCard.getExponent(buf, (short) (CONSTANTS.PUB_KEY_CARD_EXP_OFF + offset));
			totalLength += pubKeyCard.getModulus(buf, (short) (CONSTANTS.PUB_KEY_CARD_MOD_OFF + offset));
			return totalLength;
		}
		
	}
	
	RSAPublicKey getPubKeySupermarket() {
		if (!pubKeySupermarket.isInitialized()) {
			Card.throwException(CONSTANTS.SW1_CRYPTO_EXCEPTION, CONSTANTS.SW2_AUTH_PARTNER_KEY_NOT_INIT);
			return null;
		} else {
			return pubKeySupermarket;
		}
	}
}
class CONSTANTS {
	public static final short KEY_SIZE = (short) 512;
	public static final byte STATE_INIT = 0;
	public static final byte STATE_ISSUED = 1;
	public static final byte STATE_REVOKED = 2;

	public static final byte[] NAME_TERM = {(byte) 0x54, (byte) 0x45, (byte) 0x52, (byte) 0x4d}; // Hex for "TERM"
	public static final byte[] NAME_CARD = {(byte) 0x43, (byte) 0x41, (byte) 0x52, (byte) 0x44}; // Hex for "CARD"
	public static final short NAME_LENGTH = (short) 4;
	
	public static final byte CRYPTO_TYPE_SYMMETRIC = (byte) 0xC8;
	public static final byte CRYPTO_TYPE_ASYMMETRIC = (byte) 0xC9;
	
	public static final byte CLA_CHAIN_LAST_OR_NONE = (byte) 0x00;
	public static final byte CLA_CHAIN_FIRST_OR_NEXT = (byte) 0x10;
	public static final byte CLA_DEF = (byte) 0x01;

	public static final byte INS_PERSONALIZE_WRITE = (byte) 0x07;

	public static final byte INS_AUTHENTICATE = (byte) 0x09;
	public static final byte P1_AUTHENTICATE_OFFICE = (byte) 0x01;
	public static final byte P1_AUTHENTICATE_SUPERMARKET = (byte) 0x02;
	public static final byte P1_AUTHENTICATE_CARD = (byte) 0x03;
	public static final byte P2_AUTHENTICATE_STEP1 = (byte) 0x01;
	public static final byte P2_AUTHENTICATE_STEP2 = (byte) 0x02;

	public static final byte INS_REVOKE = (byte) 0x0A;
	public static final byte INS_GET_PUBKEY = (byte) 0x0E;

	public static final byte INS_BAL_INC = (byte) 0x0B;
	public static final byte INS_BAL_CHECK = (byte) 0x0C;
	public static final byte INS_BAL_DEC = (byte) 0x0D;

	public static final byte INS_MORE_DATA = (byte) 0x0F;

	public static final byte SESSION_ESTABLISHED = (byte) 0xCC;
	public static final byte NO_ACTIVE_SESSION = (byte) 0xDD;

	public static final byte SW1_SUCCESS = (byte) 0x90;

	public static final byte SW1_NON_VOLATILE_UNCHANGED_WARN_00 = (byte) 0x62;
	public static final byte SW1_NON_VOLATILE_CHANGED_WARN_00 = (byte) 0x63;

	public static final byte SW1_NON_VOLATILE_UNCHANGED_ERROR_00 = (byte) 0x64;
	public static final byte SW1_NON_VOLATILE_CHANGED_ERROR_00 = (byte) 0x65;
	public static final byte SW1_SECURITY_RELATED_ISSUE_00 = (byte) 0x66;

	public static final byte SW1_WRONG_LENGTH = (byte) 0x67;
	public static final byte SW1_FUNCTION_NOT_SUPPORTED_00 = (byte) 0x68;
	public static final byte SW1_COMMAND_NOT_ALLOWED_00 = (byte) 0x69;
	public static final byte SW1_WRONG_PARAMETERS_00 = (byte) 0x6A;
	public static final byte SW1_WRONG_PARAMETERS = (byte) 0x6B;
	public static final byte SW1_WRONG_LE_FIELD_00 = (byte) 0x6C;
	public static final byte SW1_INS_NOT_SUPPORTED = (byte) 0x6D;
	public static final byte SW1_CLASS_NOT_SUPPORTED = (byte) 0x6E;
	public static final byte SW1_NO_PRECISE_DIAGNOSIS = (byte) 0x6F;
	public static final byte SW1_ALREADY_PERSONALIZED = (byte) 0x70;

	public static final byte SW1_AUTH_EXCEPTION = (byte) 0xAE;
	public static final byte SW1_CRYPTO_EXCEPTION = (byte) 0xCE;
	public static final byte SW1_PERS_EXCEPTION = (byte) 0xDE;

	public static final byte SW2_LC_INCORRECT = (byte) 0x10;
	public static final byte SW2_CHAINING_WRONG_INS = (byte) 0x11;
	public static final byte SW2_RESP_NO_CHUNK_TO_SEND = (byte) 0x12;
	public static final byte SW2_RESP_CHAING_WRONG_INS = (byte) 0x13;
	public static final byte SW2_RESP_CHAING_WRONG_LEN = (byte) 0x14;
	public static final byte SW2_WRONG_INS = (byte) 0x15;
	public static final byte SW2_READ_TOO_SHORT = (byte) 0x16;

	public static final byte SW2_CREDITS_WRONG_LENGTH = (byte) 0xE0;
	public static final byte SW2_CREDITS_INSUFFICIENT = (byte) 0xE1;
	public static final byte SW2_CREDITS_NEGATIVE = (byte) 0xE2;
	public static final byte SW2_CREDITS_TOO_MANY = (byte) 0xE3;

	public static final byte SW2_AUTH_OTHER_ERROR = (byte) 0xA0;
	public static final byte SW2_AUTH_STEP_INCORRECT = (byte) 0xA1;
	public static final byte SW2_AUTH_WRONG_NONCE = (byte) 0xA2;
	public static final byte SW2_AUTH_WRONG_PARTNER = (byte) 0xA4;
	public static final byte SW2_AUTH_WRONG_2 = (byte) 0xA5;
	public static final byte SW2_AUTH_PARTNER_KEY_NOT_INIT = (byte) 0xA6;
	public static final byte SW2_NO_AUTH_PERFORMED = (byte) 0xA7;
	public static final byte SW2_AUTH_ALREADY_PERFORMED = (byte) 0xA8;
	public static final byte SW2_AUTH_INCORRECT_MESSAGE_LENGTH = (byte) 0xA9;
	public static final byte SW2_AUTH_CARD_KEY_NOT_INIT = (byte) 0xAA;
	public static final byte SW2_WRONG_HASH = (byte) 0xAB;

	public static final byte SW2_SESSION_ENCRYPT_ERR = (byte) 0xC2;
	public static final byte SW2_CIPHERTEXT_NOT_ALIGNED = (byte) 0xC5;
	public static final byte SW2_UNSUPPORTED_CRYPTO_MODE = (byte) 0xC6;

	public static final byte SW2_ALREADY_ISSUED = (byte) 0xB0;
	public static final byte SW2_CARD_REVOKED = (byte) 0xB1;

	public static final byte SW2_INTERNAL_ERROR = (byte) 0x6F;

	public static final short APDU_SIZE_MAX = (short) 255;
	public static final short APDU_DATA_SIZE_MAX = (short) 236;
	public static final short APDU_MESSAGE_CRYPTO_OVERHEAD = (short) 3;
	public static final short APDU_MESSAGE_SIZE_MAX = APDU_DATA_SIZE_MAX + APDU_MESSAGE_CRYPTO_OVERHEAD;
	public static final short DATA_SIZE_MAX = (short) 1024;

	public static final short NONCE_LENGTH = (short) 8;
	public static final short ID_LENGTH = (short) 4;
	public static final short SEQ_LENGTH = (short) 4;
	public static final short DATE_LENGTH = (short) 4;
	public static final short CREDITS_LENGTH = (short) 2;
	public static final short MAC_LENGTH = (short) 20;
	public static final short CREDITS_MAX = (short) 25000;

	public static final short AES_IV_LENGTH = (short) 16;
	public static final short AES_KEY_LENGTH = (short) 16;
	public static final short RSA_KEY_MOD_LENGTH = (short) 64;
	public static final short RSA_KEY_PUBEXP_LENGTH = (short) 3;
	public static final short RSA_KEY_PRIVEXP_LENGTH = (short) 64;

	public static final short RSA_PUBKEY_OFFSET_ID = (short) 0;
	public static final short RSA_PUBKEY_OFFSET_MOD = (short) (RSA_PUBKEY_OFFSET_ID + ID_LENGTH);
	public static final short RSA_PUBKEY_OFFSET_EXP = (short) (RSA_PUBKEY_OFFSET_MOD + RSA_KEY_MOD_LENGTH);
	public static final short RSA_PUBKEY_LENGTH = (short) (RSA_PUBKEY_OFFSET_EXP + RSA_KEY_PUBEXP_LENGTH);

	public static final short AUTH_MSG_1_OFFSET_NAME_TERM = (short) 0;
	public static final short AUTH_MSG_1_TOTAL_LENGTH = (short) (AUTH_MSG_1_OFFSET_NAME_TERM + NAME_LENGTH);

	public static final short AUTH_MSG_2_OFFSET_NAME_CARD = (short) 0;
	public static final short AUTH_MSG_2_OFFSET_NAME_TERM = (short) (AUTH_MSG_2_OFFSET_NAME_CARD + NAME_LENGTH);
	public static final short AUTH_MSG_2_OFFSET_NC = (short) (AUTH_MSG_2_OFFSET_NAME_TERM + NAME_LENGTH);
	public static final short AUTH_MSG_2_TOTAL_LENGTH = (short) (AUTH_MSG_2_OFFSET_NC + NONCE_LENGTH);

	public static final short AUTH_MSG_3_OFFSET_NAME_TERM = (short) 0;
	public static final short AUTH_MSG_3_OFFSET_NAME_CARD = (short) (AUTH_MSG_3_OFFSET_NAME_TERM + NAME_LENGTH);
	public static final short AUTH_MSG_3_OFFSET_NC = (short) (AUTH_MSG_3_OFFSET_NAME_CARD + NONCE_LENGTH);
	public static final short AUTH_MSG_3_OFFSET_NT = (short) (AUTH_MSG_3_OFFSET_NC + NONCE_LENGTH);
	public static final short AUTH_MSG_3_TOTAL_LENGTH = (short) (AUTH_MSG_3_OFFSET_NT + NONCE_LENGTH);

	public static final short AUTH_MSG_4_OFFSET_NAME_CARD = (short) 0;
	public static final short AUTH_MSG_4_OFFSET_NAME_TERM = (short) (AUTH_MSG_4_OFFSET_NAME_CARD + NAME_LENGTH);
	public static final short AUTH_MSG_4_OFFSET_NT = (short) (AUTH_MSG_4_OFFSET_NAME_TERM + NAME_LENGTH);
	public static final short AUTH_MSG_4_OFFSET_SESSION_KEY = (short) (AUTH_MSG_4_OFFSET_NT + NONCE_LENGTH);
	public static final short AUTH_MSG_4_TOTAL_LENGTH = (short) (AUTH_MSG_4_OFFSET_SESSION_KEY + AES_KEY_LENGTH);

	public static final short PUB_KEY_CARD_EXP_OFF = (short) 0;
	public static final short PUB_KEY_CARD_MOD_OFF = (short) (PUB_KEY_CARD_EXP_OFF + RSA_KEY_PUBEXP_LENGTH);
}
final class SupermarketRSAKey {

	private static final byte[] pubExp = { (byte) 0x01, (byte) 0x00, (byte) 0x01 };
	private static final byte[] pubMod = { 
		(byte) 0x9f, (byte) 0x71, (byte) 0x4d, (byte) 0x9e, (byte) 0xe6, (byte) 0xbf, (byte) 0xce, (byte) 0x4a,
		(byte) 0xd7, (byte) 0xb9, (byte) 0xd6, (byte) 0xdb,	(byte) 0x0f, (byte) 0xb9, (byte) 0x4b, (byte) 0x0d,
		(byte) 0xe1, (byte) 0x12, (byte) 0x60, (byte) 0x59, (byte) 0x95, (byte) 0xa3, (byte) 0x7c, (byte) 0xa8, 
		(byte) 0x47, (byte) 0xf5, (byte) 0xfa, (byte) 0x69, (byte) 0x39, (byte) 0xb0, (byte) 0x7e, (byte) 0xb0,
		(byte) 0x2b, (byte) 0xfc, (byte) 0xc5, (byte) 0x5d, (byte) 0x9e, (byte) 0xa8, (byte) 0x62, (byte) 0x52, 
		(byte) 0xd6, (byte) 0x9a, (byte) 0x54, (byte) 0x30, (byte) 0x5c, (byte) 0x70, (byte) 0xa9, (byte) 0x76,
		(byte) 0xf2, (byte) 0xda, (byte) 0x63, (byte) 0x70, (byte) 0xb9, (byte) 0x72, (byte) 0x5b, (byte) 0xee,
		(byte) 0x4f, (byte) 0x74, (byte) 0xea, (byte) 0x0a, (byte) 0xd5, (byte) 0xc8, (byte) 0xfa, (byte) 0xd1
		};

	static byte[] getExponent() {
		return pubExp;
	}

	static byte[] getModulus() {
		return pubMod;
	}

}
