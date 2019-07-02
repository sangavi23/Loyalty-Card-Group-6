package posterminal;
import java.security.*;
import java.io.*;
import java.util.*;
import java.math.*;
import java.lang.System.*;
import javax.smartcardio.*;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import javax.crypto.*;
import java.security.KeyPair;
import java.io.IOException;
import java.security.Security;
import java.security.interfaces.RSAPrivateKey;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.io.Serializable;
import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.util.Arrays;
import java.math.BigInteger;
import java.security.KeyFactory;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.RSAPublicKeySpec;
import javax.smartcardio.CardException;
import javax.smartcardio.CardTerminal;
import javax.smartcardio.CardTerminals;
import javax.smartcardio.CommandAPDU;
import javax.smartcardio.ResponseAPDU;
import javax.smartcardio.TerminalFactory;
import javax.smartcardio.CardChannel;
import java.io.FileNotFoundException;
import java.security.KeyFactory;
import java.security.KeyPairGenerator;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.SecureRandom;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

/**
 * This is the POS terminal application for the Loyalty Card Project by:
 * @author Sangavi Vijayakumar
 * @author Sashaank Pejathaya Murali
 * The application is loosely based on previous work as framework by Geert Smelt and Robin Oostrum
*/

public class POSTerminal {
	AppComm com;
	AppSession session;
	CryptoTerminal crypto;
	RSAPublicKey supermarketPublicKey;
	RSAPrivateKey supermarketPrivKey;
	int cardId;
	public POSTerminal(){
		System.out.println("Welcome to POS"); 
		loadKeyFiles();
		System.out.println("Loading Terminal's keys for authentication...");
		session = new AppSession(supermarketPrivKey);
		com = new AppComm(session);
		crypto = new CryptoTerminal();
		while (true) {
			main();
			try{
				System.in.read();
			}
			catch(Exception e)
			{
				e.printStackTrace();
			}
		}
	}
	
	private void loadKeyFiles() {
		try {
			supermarketPrivKey = (RSAPrivateKey) KeyManager.loadKeyPair().getPrivate();
			supermarketPublicKey = (RSAPublicKey) KeyManager.loadKeyPair().getPublic();
		} catch (Exception e) {
			e.printStackTrace();
		}
	}

	private void main() {
		System.out.println("Waiting for card...");
		System.out.println("Card is being read...");
		com.waitForCard();
		System.out.println("Authenticating card...");
		if (!session.authenticate(CONSTANTS.NAME_TERM)) {
			System.err.println("Authentication error.");
			return;
		}
		cardId = session.getCardIdAsInt();
		
		System.out.println("Card "+cardId+" authenticated successfully...");
		
		mainmenu: while (true) {
			String command = "0";
			try {
				Thread.sleep(1000);
			} catch (Exception e) {
				System.err.println("Operation interrupted...");
			}
			
			command = IO.prompt("\n1. Add points \n " +
					"2. Reduce points from card \n 3. Check balance on card \n 4. Exit \n");
			
			if (Integer.parseInt(command) == 1) {
				String addpoints = "";
				
				while (true) {
					String correct = "";
					addpoints = IO.prompt("Enter the points to be added to the card... ");
					
					System.out.println("Points to be added: " + addpoints);
						correct = IO.prompt("Proceed with the operation? (Y/N)");
		
					if (correct.equals("Y")) {
						break;
					}
				continue mainmenu;
				}
				
				try {
					Short c = Short.parseShort(addpoints);
				} catch (Exception e) {
					System.out.println("Invalid points! Please enter a valid number...");
				}
				addPoints(Short.parseShort(addpoints));
			} else if (Integer.parseInt(command) == 2) {
				String reducePoints = "";
				
				while (true) {
					String correct = "";
					reducePoints = IO.prompt("Enter the points to be reduced from the card...");
					
					System.out.println("Points to be reduced... " + reducePoints);
						correct = IO.prompt("Proceed with the operation? (Y/N)");

					if (correct.equals("Y")) {
						break;
					}
					continue mainmenu;
				}
				
				try {
					Short c = Short.parseShort(reducePoints);
				} catch (Exception e) {
					System.out.println("Invalid points! Please enter a valid number...");
				}
				reducePoints(Short.parseShort(reducePoints));
				
			} else if (Integer.parseInt(command) == 3) {	
				getPoints();
			}
			else if (Integer.parseInt(command) == 4) {
				System.exit(0);
				
			} else {
				System.err.println("Invalid command!");
			}
		}
		
	}
	
	//Check balance
	private void getPoints() {
		if (!session.isAuthenticated()) {
			System.err.println(
					"Cannot view balance, authentication failed!");
		}
		Response resp = com.sendCommand(CONSTANTS.INS_BAL_CHECK);
		if (resp == null) {
			System.err.println("Cannot view balance, operation failed!");
		}
		if (!resp.success()) {
			System.err.println("Error checking balance...");
		}

		short b = (short) FormatData.byteArrayToShort(resp.getData());
		System.out.println("Balance is " + b);
	}

	//Decrease points
	private void reducePoints(short points) {
		if (!session.isAuthenticated()) {
			System.err.println(
					"Cannot reduce points, authentication failed!");
		}
		byte[] pointsData = FormatData.toByteArray(points);

		Response resp = com.sendCommand(CONSTANTS.INS_BAL_DEC,
				pointsData);
		if (resp == null) {
			System.err.println("Cannot remove points, operation failed!");
		}
		if (!resp.success()) {
			System.err.println("Error reducing points.");
		}
		System.out.println("Points reduced from balance: " + points);
	}

	//Increase points
	private void addPoints(short points) {
		if (!session.isAuthenticated()) {
			System.err.println(
					"Cannot add points, authentication failed!");
		}

		byte[] pointsData = FormatData.toByteArray(points);

		Response resp = com.sendCommand(CONSTANTS.INS_BAL_INC,
				pointsData);
		if (resp == null) {
			System.err.println("Cannot add points, operation failed!");
		}
		if (!resp.success()) {
			System.err.println("Error adding points.");
		}
		System.out.println("Points added to balance: " + points);
	}

	
	public static void main(String[] arg) {
		new POSTerminal();
		try {
			KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
			generator.initialize(512);
			KeyPair keypair;
			
			CryptoTerminal pk = new CryptoTerminal();

		} catch (Exception e) {
			e.printStackTrace();
		}
}
}

class AppComm {

	static final byte[] APPLET_AID = { (byte)0x12, (byte)0x34, (byte) 0x56, (byte) 0x78, (byte) 0x90, (byte) 0xab };

	static final CommandAPDU SELECT_APDU = new CommandAPDU((byte) 0x00, (byte) 0xA4, (byte) 0x04, (byte) 0x00, APPLET_AID);

	private Card card;
	private CardChannel applet;
	private CryptoTerminal crypto;
	private AppSession session;

	public AppComm(AppSession session) {
		this.session = session;
		this.session.setAppComm(this);
		this.crypto = new CryptoTerminal();
	}
	public void waitForCard() {
		System.out.print("Waiting for card...");
		while (!connect()) {
		}
		System.out.println();
		System.out.println("Card found: " + applet.getCard());
	}
	
	//Connects card to terminal
	public boolean connect() {
		try {
			if (connectToCard()) {
				if (selectApplet()) {
					this.session.reset();
					return true;
				}
			}
		} catch (Exception e) {
			System.err.println();
			System.err.println("Exception: " + e.getMessage());
			System.out.print("Waiting for card...");
		}
		return false;
	}

	private boolean requireCard() {
		if (connectToCard()) {
			return true;
		}
		return false;
	}

	
	//Checks whether card is present in the terminal
	private boolean connectToCard() {
		TerminalFactory tf = TerminalFactory.getDefault();
		CardTerminals ct = tf.terminals();
		try {
			List<CardTerminal> cs = ct.list(CardTerminals.State.CARD_PRESENT);
			if (cs.isEmpty()) {
				return false;
			}
			CardTerminal t = cs.get(0);
			if (t.isCardPresent()) {
				card = t.connect("*");
				applet = card.getBasicChannel();
				return true;
			}
			return false;
		} catch (Exception e) {
			System.err.println(e.getMessage());
			return false;
		}
	}

	private boolean selectApplet() {
		ResponseAPDU resp;
		try {
			resp = applet.transmit(SELECT_APDU);
			System.out.println(resp);
		} catch (Exception e) {
			System.err.println(e.getMessage());
			return false;
		}
		if (resp.getSW() != 0x9000) {
			throw new SecurityException();
		}
		return true;
	}

	
	//Sends a CommandAPDU to card and returns the response from it
	public ResponseAPDU sendCommandAPDU(CommandAPDU capdu) {
		ResponseAPDU rapdu;	
		try {
			if (requireCard()) {
				rapdu = applet.transmit(capdu);
				return rapdu;
			} else {
				return null;
			}
		} catch (Exception e) {
			System.err.println(e.getMessage());
			return null;
		}
	}

	public Response sendCommand(byte instruction, byte p1, byte p2, byte[] data) {
		try {
			Response response = processCommand(instruction, p1, p2, data);
			if (response == null) {
				return null;
			}
			return response;
		} catch (Exception e) {
			session.reset();
			System.err.println(e.getMessage());
		}
		return null;
	}

	public Response sendCommand(byte instruction, byte[] data) {
		return sendCommand(instruction, (byte) 0, (byte) 0, data);
	}

	public Response sendCommand(byte instruction, byte p1, byte p2) {
		byte[] data = new byte[1];
		data[0] = instruction;
		return sendCommand(instruction, p1, p2, data);
	}

	public Response sendCommand(byte instruction) {
		return sendCommand(instruction, (byte) 0, (byte) 0);
	}

	private Response processCommand(byte instruction, byte p1, byte p2, byte[] data) {
		ResponseAPDU rapdu;

		int bytesToSend = data.length;

		if (bytesToSend > CONSTANTS.DATA_SIZE_MAX) {
			throw new SecurityException();
		}
		
		if (bytesToSend > CONSTANTS.APDU_DATA_SIZE_MAX) {
			throw new SecurityException();
		}

		rapdu = sendSessionCommand(CONSTANTS.CLA_DEF, instruction, p1, p2, data);
		return processResponse(rapdu);
	}

	
	//Adds hash and encrypts the entire command with AES session key
	private ResponseAPDU sendSessionCommand(int cla, int ins, int p1, int p2, byte[] data) {
		byte[] buffer = new byte[data.length + CONSTANTS.MAC_LENGTH];
		if (session.isAuthenticated()) {
			System.arraycopy(data, 0, buffer, 0, data.length);
			System.arraycopy(crypto.hash(data), 0, buffer, data.length, CONSTANTS.MAC_LENGTH);
			buffer = crypto.encryptAES(buffer, session.getSessionKey());
		}
		else {
			buffer = data;
		}
		CommandAPDU apdu = new CommandAPDU(cla, ins, p1, p2, buffer);
		return sendCommandAPDU(apdu);
	}

	private Response processResponse(ResponseAPDU rapdu) {
		if (rapdu == null) {
			return null;
		}

		Response resp;
		byte[] data = rapdu.getData();

		if (data.length > 0) {
			data = processSessionResponse(data);
			resp = new Response((byte) rapdu.getSW1(), (byte) rapdu.getSW2(), data);
		} else {
			System.out.println("Response APDU is empty!");
			resp = new Response((byte) rapdu.getSW1(), (byte) rapdu.getSW2());
		}

		return resp;
	}

	private byte[] processSessionResponse(byte[] data) {
		if (session.isAuthenticated()) {
			data = crypto.decryptAES(data, session.getSessionKey());
		}
		return data;
	}
}

class AppSession {

	private CryptoTerminal crypto;
	private AppComm com;

	private RSAPublicKey pubKeyCard;
	private RSAPrivateKey privKey;

	private byte[] cardId;
	
	private byte[] sessionKey;
	private boolean authenticationSuccess;

	public AppSession(RSAPrivateKey privKey) {
		this.privKey = privKey;
		this.crypto = new CryptoTerminal();
		this.reset();
	}

	public void setAppComm(AppComm com) {
		this.com = com;
	}

	public byte[] getCardId() {
		return cardId;
	}
	
	public int getCardIdAsInt() {
		return FormatData.byteArrayToInt(cardId);
	}

	public RSAPublicKey getCardPublicKey() {
		return pubKeyCard;
	}

	public RSAPrivateKey getPrivateKey() {
		return privKey;
	}

	public boolean isAuthenticated() {
		return authenticationSuccess;
	}

	public byte[] getSessionKey() {
		return sessionKey;
	}

	
	//Resets current session
	public void reset() {
		this.cardId = null;
		this.pubKeyCard = null;
		this.authenticationSuccess = false;
		this.sessionKey = null;
	}

	
	//Handshake protocol authenticating the terminal to the card and vice versa
	public boolean authenticate(byte[] from) {
		try {
			setPubKeyCard();
			byte[] nonceCard = authStep1(from);
			if (nonceCard != null) {
				byte[] nonceTerminal = crypto.generateRandomNonce(CONSTANTS.NONCE_LENGTH);
				byte[] sessionKey = authStep3(from, cardId, nonceCard, nonceTerminal);
				if (sessionKey != null) {
						authenticationSuccess = true;
						return true;
					} else {
						System.out.println("Authentication failure!");
					}
				}
		} catch (Exception e) {
			reset();
			System.err.println(e.getMessage());
		}
		return false;
	}
	
	
	//Get public key of card
	private byte[] setPubKeyCard() {
		Response response;
		try {
			response = com.sendCommand(CONSTANTS.INS_GET_PUBKEY);
		
		if (response == null) {
			System.err.println("No response!");
		}
		
		if (!response.success()) {
			System.err.println("Response failed!");
		}
		
		byte[] data = response.getData();
		
		if (data == null) {
			System.err.println("No data!");
		}

		BigInteger exponent = new BigInteger(1, Arrays.copyOfRange(data,
				CONSTANTS.PUB_KEY_CARD_EXP_OFF, CONSTANTS.PUB_KEY_CARD_EXP_OFF
				+ CONSTANTS.RSA_KEY_PUBEXP_LENGTH));
		BigInteger modulus = new BigInteger(1, Arrays.copyOfRange(data,
				CONSTANTS.PUB_KEY_CARD_MOD_OFF, CONSTANTS.PUB_KEY_CARD_MOD_OFF
				+ CONSTANTS.RSA_KEY_MOD_LENGTH));
		RSAPublicKeySpec pubKeySpec = new RSAPublicKeySpec(modulus, exponent);
		
		KeyFactory factory = KeyFactory.getInstance("RSA");
			this.pubKeyCard = (RSAPublicKey) factory.generatePublic(pubKeySpec);
		
		return data;
	}
	catch (Exception e) {
			System.err.println(e.getMessage());
			return null;
		}
	}

	//Authentication protocol
	private byte[] authStep1 (byte[] from) {	
		byte[] sendData = new byte[CONSTANTS.AUTH_MSG_1_TOTAL_LENGTH];
		System.arraycopy(from, 0, sendData, CONSTANTS.AUTH_MSG_1_OFFSET_NAME_TERM, 
				CONSTANTS.NAME_LENGTH);
		
		Response response;
		try {
			response = com.sendCommand(CONSTANTS.INS_AUTHENTICATE, 
					CONSTANTS.P1_AUTHENTICATE_CARD, CONSTANTS.P2_AUTHENTICATE_STEP1, sendData);
		
		if (response == null) {
			System.err.println("No response!");
		}

		if (!response.success()) {
			System.err.println("Operation unsuccessful!");
		}
		
		byte[] data = crypto.decryptRSA(response.getData(), this.privKey);
		
		if (data == null) {
			System.err.println("No data!");
		}

		this.cardId = Arrays.copyOfRange(data, CONSTANTS.AUTH_MSG_2_OFFSET_NAME_CARD, 
				CONSTANTS.AUTH_MSG_2_OFFSET_NAME_TERM);
		byte[] cardNonce = Arrays.copyOfRange(data, CONSTANTS.AUTH_MSG_2_OFFSET_NC, 
				CONSTANTS.AUTH_MSG_2_OFFSET_NC + CONSTANTS.NONCE_LENGTH);
		byte[] receivedTerminalName = Arrays.copyOfRange(data, CONSTANTS.AUTH_MSG_2_OFFSET_NAME_TERM,
				CONSTANTS.AUTH_MSG_2_OFFSET_NAME_TERM + CONSTANTS.NAME_LENGTH);
		
		if (!(Arrays.equals(receivedTerminalName,CONSTANTS.NAME_TERM))) {
			System.err.println("Terminal name on card does not match the registered terminal name!");
		}
				
		return cardNonce;
	}
	 catch (Exception e) {
			System.err.println(e.getMessage());
			return null;
		}
	}


	private byte[] authStep3(byte[] from, byte[] nameCard, byte[] nonceCard, 
			byte[] nonceTerminal) {
		byte[] data = new byte[CONSTANTS.AUTH_MSG_3_TOTAL_LENGTH];
		System.arraycopy(from, 0, data, CONSTANTS.AUTH_MSG_3_OFFSET_NAME_TERM, 
				CONSTANTS.NAME_LENGTH);
		System.arraycopy(nameCard, 0, data, CONSTANTS.AUTH_MSG_3_OFFSET_NAME_CARD, 
				CONSTANTS.NAME_LENGTH);
		System.arraycopy(nonceCard, 0, data, CONSTANTS.AUTH_MSG_3_OFFSET_NC, 
				CONSTANTS.NONCE_LENGTH);
		System.arraycopy(nonceTerminal, 0, data, CONSTANTS.AUTH_MSG_3_OFFSET_NT, 
				CONSTANTS.NONCE_LENGTH);

		data = crypto.encryptRSA(data, this.pubKeyCard);

		Response response;
		try {
			response = com.sendCommand(CONSTANTS.INS_AUTHENTICATE,
					CONSTANTS.P1_AUTHENTICATE_CARD, CONSTANTS.P2_AUTHENTICATE_STEP2, data);
		if (!response.success()) {
			throw new Exception();
		}

		data = crypto.decryptRSA(response.getData(), this.privKey);

		if (data == null) {
			throw new Exception();
		}

		byte[] nonceReceived = Arrays.copyOfRange(data, CONSTANTS.AUTH_MSG_4_OFFSET_NT, 
				CONSTANTS.AUTH_MSG_4_OFFSET_NT + CONSTANTS.NONCE_LENGTH);

		if (nonceReceived != null) {

			if (authenticateCard(nonceReceived, nonceTerminal)) {
				System.out.println("Authenticated.");
				sessionKey = new byte[CONSTANTS.AES_KEY_LENGTH];
				System.arraycopy(data, CONSTANTS.AUTH_MSG_4_OFFSET_SESSION_KEY, 
						sessionKey, 0, CONSTANTS.AES_KEY_LENGTH);				
			} else {
				System.out.println("Authentication failed!");
			}
		}
		
		return sessionKey;
	} catch (Exception e) {
			e.printStackTrace();
			return null;
		}

	}

	private boolean authenticateCard(byte[] nonceReceived, byte[] nonceTerminal) {
		return Arrays.equals(nonceReceived, nonceTerminal);
	}
	
}

final class IO {
	private static BufferedReader in = new BufferedReader(
			new InputStreamReader(System.in));

	public static String prompt(String prompt) {
		String input = "";
		try {
			System.out.print(prompt);
			input = in.readLine();
		} catch (Exception e) {
			e.printStackTrace();
			input = "";
		}
		return input;
	}

	public static int promptInt(String prompt) {
		while (true) {
			String correct = "";
			String id = IO.prompt(prompt);

			System.out.println("ID is " + id);
				correct = IO.prompt("Proceed with the operation? (Y/N) ");

			if (correct.equals("Y")) {
				try {
					return Integer.parseInt(id);
				} catch (Exception e) {
					System.out.println(e.getMessage());
				}
			}
		}
	}
	
	public static int checkInt(int input) {
		while (true) {
			String correct = "";
				correct = IO.prompt("Proceed with the operation? (Y/N) ");

			 if (correct.equals("Y")) {
				try {
					return input;
				} catch (Exception e) {
					System.out.println(e.getMessage());
				}
			}
		}
	}
}

class CONSTANTS {
	public static final int KEY_SIZE = 512;
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

final class FormatData {

	public static final String toHexString(byte[] bytes) {
		StringBuilder sb = new StringBuilder();
		for (byte b : bytes) {
			sb.append("0x");
			int v = b & 0xff;
			if (v < 16) {
				sb.append('0');
			}
			sb.append(Integer.toHexString(v));
			sb.append(" ");
		}
		return sb.toString();
	}

	public static final String toHexString(short val) {
		return toHexString(toByteArray(val));
	}

	public static final byte[] toByteArray(short value) {
		return new byte[] { (byte) (value >> 8 & 0xff), (byte) (value & 0xff) };
	}


	public static final byte[] toByteArray(int value) {
		return new byte[] { (byte) (value >>> 24), (byte) (value >> 16 & 0xff),
				(byte) (value >> 8 & 0xff), (byte) (value & 0xff) };
	}

	public static final long byteArrayToLong(byte[] b) {
		long value = 0;
		for (int i = 0; i < b.length; i++) {
			value = (value << 8) + (b[i] & 0xff);
		}
		return value;
	}

	public static final int byteArrayToInt(byte[] b) {
		return (b[0] << 24) + ((b[1] & 0xFF) << 16) + ((b[2] & 0xFF) << 8)
				+ (b[3] & 0xFF);
	}

	public static final int byteArrayToShort(byte[] b) {
		return ((b[0] & 0xFF) << 8) | (b[1] & 0xFF);
	}
}

class KeyManager {
	private String path;
	public static final String PUBKEY_BASENAME = "PubKeyPOS";
	public static final String PRIVKEY_BASENAME = "PrivKeyPOS";

	public KeyManager() {
		this.path = "/root/Desktop/lc/posterminal/src/posterminal/";
	}
	
	public KeyManager(String path) {
		this.path = path + '/';
	}
	
	public KeyPair loadKeys() throws NoSuchAlgorithmException,
			InvalidKeySpecException, FileNotFoundException, IOException {
		KeyFactory factory = KeyFactory.getInstance("RSA");
		
		String publicPath = path + PUBKEY_BASENAME;
		String privatePath = path + PRIVKEY_BASENAME;
		X509EncodedKeySpec publicKeyEncoded = new X509EncodedKeySpec(
				loadKey(publicPath));
		PKCS8EncodedKeySpec privateKeyEncoded = new PKCS8EncodedKeySpec(
				loadKey(privatePath));
		
		RSAPublicKey publicKey = (RSAPublicKey) factory
				.generatePublic(publicKeyEncoded);
		RSAPrivateKey privateKey = (RSAPrivateKey) factory
				.generatePrivate(privateKeyEncoded);
		return new KeyPair(publicKey, privateKey);
	}
	
	private byte[] loadKey(String path) throws FileNotFoundException,
			IOException {
		FileInputStream file = new FileInputStream(path);
		byte[] bytes = new byte[file.available()];
		file.read(bytes);
		file.close();
		return bytes;
	}	
	public void save(KeyPair keypair, String identifier)
			throws FileNotFoundException, IOException {
		FileOutputStream file = new FileOutputStream(path + PUBKEY_BASENAME
				+ identifier);
		file.write(keypair.getPublic().getEncoded());
		file.close();
		
		file = new FileOutputStream(path + PRIVKEY_BASENAME + identifier);
		file.write(keypair.getPrivate().getEncoded());
		file.close();
	}

	public static KeyPair loadKeyPair()
			throws NoSuchAlgorithmException, InvalidKeySpecException,
			FileNotFoundException, IOException {
		KeyManager m = new KeyManager();
		return m.loadKeys();
	}
}

class Response {
	byte[] data;
	byte sw1;
	byte sw2;
	int length = 0;

	public Response(byte sw1, byte sw2, byte[] data) {
		this.length = data.length;
		this.data = Arrays.copyOf(data, data.length);
		this.sw1 = sw1;
		this.sw2 = sw2;
	}

	public Response(byte sw1, byte sw2) {
		this.sw1 = sw1;
		this.sw2 = sw2;
	}

	public boolean success() {
		return (sw1 == CONSTANTS.SW1_SUCCESS);
	}

	public byte getStatus1() {
		return sw1;
	}

	public byte getStatus2() {
		return sw2;
	}

	public short getStatus() {
		return (short) (((sw1 & 0xff) << 8) | (sw2 & 0xff));
	}

	public int getNr() {
		return data.length;
	}

	public byte[] getData() {
		return data;
	}

	public void setData(byte[] data) {
		this.data = data;
	}
}

class CryptoTerminal {
	private Cipher RSACipher;
	private Cipher AESCipher;
	private KeyGenerator AESKeyGen;
	private IvParameterSpec AESIvSpec;
	private MessageDigest digest;
	
	public CryptoTerminal() {
		try {
			RSACipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
			AESCipher = Cipher.getInstance("AES/CBC/NoPadding");
			AESKeyGen = KeyGenerator.getInstance("AES");
			AESKeyGen.init(128);
			AESIvSpec = new IvParameterSpec(new byte[16]);
			digest = MessageDigest.getInstance("SHA-1");
		} catch (Exception e) {
			e.printStackTrace();
		}
	}
	

	//Encrypt data with public RSA key

	public byte[] encrypt(byte[] data, RSAPublicKey pubKey) {
		SecretKey skey = AESKeyGen.generateKey();
		byte[] AESKey = skey.getEncoded();
		data = encryptAES(data, AESKey);
		byte[] encryptedAESKey = encryptRSA(AESKey, pubKey);
		data = Arrays.copyOf(data, data.length + 128);
		System.arraycopy(encryptedAESKey, 0, data, data.length - 128, 128);
		return data;
	}
	

	//Decrypt data with private RSA key
	public byte[] decrypt(byte[] data, RSAPrivateKey privKey) {
		byte[] encryptedAESKey = Arrays.copyOfRange(data, data.length - 128,
				data.length);
		data = Arrays.copyOfRange(data, 0, data.length - 128);
		byte[] AESKey = decryptRSA(encryptedAESKey, privKey);
		data = decryptAES(data, AESKey);
		return data;
	}
	

	//Generate random nonce
	public byte[] generateRandomNonce(int n) {
		SecureRandom random = new SecureRandom();
		byte[] nonce = new byte[n];
		random.nextBytes(nonce);
		return nonce;
	}
	

	public byte[] encryptRSA(byte[] data, RSAPublicKey pubKey) {
		try {
			RSACipher.init(Cipher.ENCRYPT_MODE, pubKey);
			return RSACipher.doFinal(data);
		} catch (Exception e) {
			e.printStackTrace();
		} 
		return null;
	}

	public byte[] decryptRSA(byte[] data, RSAPrivateKey privKey) {
		try {
			RSACipher.init(Cipher.DECRYPT_MODE, privKey);
			return RSACipher.doFinal(data);
		} catch (Exception e) {
			e.printStackTrace();
		} 
		return null;
	}
	

	//Decrypt data with AES key
	public byte[] decryptAES(byte[] data, byte[] AESKey) {
		try {
			SecretKeySpec AESKeySpec = new SecretKeySpec(AESKey, "AES");
			AESCipher.init(Cipher.DECRYPT_MODE, AESKeySpec, AESIvSpec);
			data = AESCipher.doFinal(data);
			return stripPaddingAES(data);
		} catch (Exception e) {
			e.printStackTrace();
		}
		return null;
	}
	

	//Encrypt data with AES key
	public byte[] encryptAES(byte[] data, byte[] AESKey) {
		try {
			data = padAES(data);
			SecretKeySpec AESKeySpec = new SecretKeySpec(AESKey, "AES");
			AESCipher.init(Cipher.ENCRYPT_MODE, AESKeySpec, AESIvSpec);
			return AESCipher.doFinal(data);
		} catch (Exception e) {
			e.printStackTrace();
		} 
		return null;
	}


	//Pad plaintext for encryption with AES
	private byte[] padAES(byte[] data) {
		int cipherLen = data.length + 2;
		cipherLen += (16 - (cipherLen % 16));
		byte[] newData = new byte[cipherLen];
		System.arraycopy(FormatData.toByteArray((short) data.length), 0,
				newData, 0, 2);
		System.arraycopy(data, 0, newData, 2, data.length);
		return newData;
	}
	
	//Strip padding
	private byte[] stripPaddingAES(byte[] data) {
		byte[] pad = Arrays.copyOfRange(data, 0, 2);
		int padding = FormatData.byteArrayToShort(pad);
		return Arrays.copyOfRange(data, 2, 2 + padding);
	}
	
	//Hash input data
	public byte[] hash(byte[] data) {
		digest.update(data);
		return digest.digest();
	}

}
