import java.util.*;
import java.io.ByteArrayOutputStream;
import java.io.ObjectOutputStream;
import java.security.*;
import javax.crypto.*;
import javax.crypto.spec.*;
import java.nio.charset.StandardCharsets;
import java.math.BigInteger;
import java.security.KeyFactory;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.RSAPrivateKeySpec;
import java.security.spec.RSAPublicKeySpec;
import java.nio.charset.StandardCharsets;


/**
 * Standardizes the format of information sent between client and server. This
 * implements Serlializable so that it can automatically be converted to a
 * string form.
 */
public class Envelope implements java.io.Serializable {
	private static final long serialVersionUID = -7726335089122193103L;
	private String msg;
	private ArrayList<Object> objContents = new ArrayList<Object>();
	private double seqNum;
	private byte[] mac;

	/**
	 * Standard constructor.
	 * 
	 * @param text The title of the envelope that informs the server of the
	 * desired operation and the client of the success or errors of the
	 * operation.
	 */
	public Envelope(String text, double seq) {
		msg = text;
		seqNum = seq;
	}

	/**
	 * Returns the envelope's message.
	 *
	 * @return The envelope's message.
	 */
	public String getMessage() {
		return msg;
	}

	/**
	 * Returns the contents of the message. These contents are in the form of
	 * an ArrayList of Objects, so they may take any type depending on the
	 * exchange.
	 *
	 * @return The ArrayList of Objects stored in this envelope.
	 */
	public ArrayList<Object> getObjContents() {
		return objContents;
	}

	/**
	 * Add an object to the envelope's contents. These are stored and later
	 * returned in the order in which they were added.
	 *
	 * @param object The object to store in contents.
	 */
	public void addObject(Object object) {
		objContents.add(object);
	}

	public double getSeqNum() {
		return seqNum;
	}

	//before sending an evnelope, this function must be called to generate and set the mac for it
	public void genAndSetMac() {
		mac = generateMAC();
	}

	//get bytes of the env contents and then get hash of that
	private byte[] generateMAC() {
		byte[] ret_arr = null;

		byte[] msg_bytes = msg.getBytes();
		byte[] obj_con_bytes = getObjBytes(objContents);
		byte[] seq_bytes = doubleToByteArray(seqNum);

		int byte_arr_length = 0;
		byte_arr_length += msg_bytes.length;
		byte_arr_length += seq_bytes.length;


		ret_arr = new byte[byte_arr_length];

		int arr_index = 0;
		for (int i = 0; i < msg_bytes.length; i++) {
			ret_arr[arr_index++] = msg_bytes[i];
		}
		for (int i = 0; i < seq_bytes.length; i++) {
			ret_arr[arr_index++] = seq_bytes[i];
		}

		
		
		return getMACHash(ret_arr);
	}

	private byte[] getObjBytes(Object obj) {
		try {
			ByteArrayOutputStream bos = new ByteArrayOutputStream();
			ObjectOutputStream oos = new ObjectOutputStream(bos);
			oos.writeObject(obj);
			oos.flush();
			byte[] data = bos.toByteArray();
			Byte[] ba = new Byte[data.length];
			int i=0;
			return data;
		} catch(Exception e) {
			System.out.println("Exception on getting getObjBytes");
			return null;
		}
	}

	//get hash of all the bytes in the env for a MAC
	private byte[] getMACHash(byte[] mac_bytes) {
		try{
			MessageDigest md = MessageDigest.getInstance("SHA-256");
			md.update(mac_bytes);
			byte[] digest = md.digest();
			return digest;
		} catch(Exception e) {
			System.out.println("Exception in gen iv");
			return null;
		}

	}

	public static final byte[] intToByteArray(int value) {
	    return new byte[] {
		    (byte)(value >>> 24),
		    (byte)(value >>> 16),
		    (byte)(value >>> 8),
		    (byte)value
	    };
	}

	public static final byte[] doubleToByteArray(double value) {
		byte[] seq_bytes = new byte[8];
		long lng = Double.doubleToLongBits(value);
		for(int i = 0; i < 8; i++) {
			seq_bytes[i] = (byte)((lng >> ((7 - i) * 8)) & 0xff);
		}
		return seq_bytes;
	}
	
	//after receiving an envelope, this function must be called to verfify the mac
	public boolean verifyMAC() {
		if (mac == null) {
			System.out.println("No MAC found on envelope");
			return false;
		}
		byte[] new_mac = generateMAC();
		return Arrays.equals(new_mac,mac);
	}


}
