import java.util.*;
import java.io.ObjectOutputStream;
import javax.crypto.SealedObject;
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

public class ExchangeFunctions {
	
	//using cipher from shared secret, get an envelope from a sealed object
	public static Envelope decryptEnvelopeUsingAES(SealedObject sealed_object, Cipher cipher) {
		try {
			Envelope plainText = (Envelope)sealed_object.getObject(cipher);
			return plainText;
		} catch(Exception e) {
			System.out.println("Exception on AES decrypt");
			e.printStackTrace();
			return null;
		}
	}

	//using cipher from shared secret, make a sealed object from an envelope
	public static SealedObject encryptEnvelopeUsingAES(Envelope env, Cipher cipher) {
		try {
			SealedObject cipherText = new SealedObject(env, cipher);
			return cipherText;
		} catch(Exception e) {
			System.out.println("Exception on AES encrypt");
			e.printStackTrace();
			return null;
		}
	}

	//get the cipher to keep around for a single socket session
	public static Cipher get_aes_cipher(byte[] shared_secret) {
		Key aes_key = generate_aes_key(shared_secret);
		IvParameterSpec iv_spec = generate_iv(shared_secret);
		try {
			Cipher cipher = Cipher.getInstance("AES/CTR/NoPadding", "BC");//do we need no padding for ctr
			cipher.init(Cipher.ENCRYPT_MODE, aes_key, iv_spec);
			return cipher;
		} catch(Exception e) {
			System.out.println("Exception in aes cipher init");
			e.printStackTrace();
			return null;
		}
	}

	//takes in the shared DH key and hashes it into a 256 bit aes key
	public static SecretKeySpec generate_aes_key(byte[] shared_secret) {
		try{
			MessageDigest md = MessageDigest.getInstance("SHA-256");
			md.update(shared_secret);
			byte[] digest = md.digest();
			SecretKeySpec key = new SecretKeySpec(digest, "AES");
			return key;
		} catch(Exception e) {
			System.out.println("Exception in gen aes");
			return null;
		}
	}

	//generates an 8byte iv based on the md5 hash of the shared secret
	public static IvParameterSpec generate_iv(byte[] shared_secret) {
		try{
			MessageDigest md = MessageDigest.getInstance("MD5");
			md.update(shared_secret);
			byte[] digest = md.digest();
			byte[] iv_bytes = new byte[8];
			for(int i=0; i<8; i++) {
				iv_bytes[i] = digest[i];
			}
			return new IvParameterSpec(iv_bytes);
		} catch(Exception e) {
			System.out.println("Exception in gen iv");
			return null;
		}
		
	}
	
	//group from:
	//https://tools.ietf.org/html/rfc2409#section-6.1
	//makes a keypair(pub/priv) from the specified group
	public static KeyPair generate_single_dh_keypair() {
		try {
			BigInteger p = new BigInteger("FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1" + 
							"29024E088A67CC74020BBEA63B139B22514A08798E3404DD" +
							"EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245" +
							"E485B576625E7EC6F44C42E9A63A3620FFFFFFFFFFFFFFFF", 16);
			BigInteger g = BigInteger.valueOf(2);
			KeyPairGenerator keyGen = KeyPairGenerator.getInstance("DH", "BC");
			DHParameterSpec dhParams = new DHParameterSpec(p, g);
			keyGen.initialize(dhParams, new SecureRandom());
			KeyPair aPair = keyGen.generateKeyPair();
			return aPair;
		} catch (Exception e) {
			System.out.println("Exception in gen both dh keypair");
			e.printStackTrace();
			return null;
		}
	}

	//given our private and the other nodes public, return the shared secret
	public static byte[] generate_shared_key(Key a_priv, Key b_public) {
		try{
			KeyAgreement aKeyAgree = KeyAgreement.getInstance("DH", "BC");
			aKeyAgree.init(a_priv);
			aKeyAgree.doPhase(b_public, true);
			byte[] shared_secret = aKeyAgree.generateSecret();
			return shared_secret;
		} catch (Exception e) {
			System.out.println("Exception in gen_shared_key");
			e.printStackTrace();
			return null;
		}
	}

	//given a sealed object encrypted with RSA, decrypt it into an envelope using our priv key
	public static Envelope decryptEnvUsingRSA(SealedObject sealed_key, RSAPrivateKey RSAPrivKey){
		try {
			Cipher cipher = Cipher.getInstance("RSA/None/OAEPWithSHA1AndMGF1Padding", "BC");
			cipher.init(Cipher.DECRYPT_MODE, RSAPrivKey);
			Envelope plainText = (Envelope)sealed_key.getObject(cipher);
			return plainText;
		} catch(Exception e) {
			System.out.println("Exception on RSA decrypt");
			e.printStackTrace();
			return null;
		}
	}

	//take an key and turn it into a sealed object of an envelope encrypted with RSA
	public static SealedObject encryptEnvUsingRSA(Envelope env, RSAPublicKey RSAPubKey){
		try {
			Cipher cipher = Cipher.getInstance("RSA/None/OAEPWithSHA1AndMGF1Padding", "BC");
			cipher.init(Cipher.ENCRYPT_MODE, RSAPubKey);
			SealedObject cipherText = new SealedObject(env, cipher);
			return cipherText;
		} catch(Exception e) {
			System.out.println("Exception on RSA encrypt");
			e.printStackTrace();
			return null;
		}
	}

	public static void sendEncryptedMessage(ObjectOutputStream output, Cipher c, Envelope env){
		try{
			SealedObject sealed_object = encryptEnvelopeUsingAES(env, c);
			output.writeObject(sealed_object);
		} catch(Exception e) {
			e.printStackTrace();
			System.out.println("Exception in sending encrypted env as sealed object");
		}
	}
}
