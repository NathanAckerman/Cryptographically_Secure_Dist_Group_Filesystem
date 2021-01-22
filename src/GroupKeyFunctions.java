import java.util.*;
import javax.crypto.SealedObject;
import java.security.*;
import javax.crypto.*;
import javax.crypto.spec.*;

public class GroupKeyFunctions {

	// Encrypts chunks using AES
	public static byte[] encrypt( byte[] data, byte[] ss ) throws Exception {

		Cipher c = getCipher( ss, "e" );
		return c.doFinal( data );

	}

	// Decrypts chunks using AES
	public static byte[] decrypt( byte[] data, byte[] ss ) throws Exception {

		Cipher c = getCipher( ss, "d" );
		return c.doFinal( data );

	}

	// Get Cipher from Shared Secret
	private static Cipher getCipher( byte[] ss, String mode ) throws Exception {

		Key key = getKey( ss );
		IvParameterSpec iv = getIV( ss );
		Cipher c = Cipher.getInstance( "AES/CTR/NoPadding", "BC" );
		if ( mode.equals( "e" ) ) { c.init( Cipher.ENCRYPT_MODE, key, iv ); }
		else { c.init( Cipher.DECRYPT_MODE, key, iv ); }
		return c;

	}

	// Get specific IV from Shared Secret
	private static Key getKey( byte[] ss ) throws Exception {

		return new SecretKeySpec( hash( ss ), "AES" );

	}

	// Get specific IV from Shared Secret
	private static IvParameterSpec getIV( byte[] ss ) throws Exception {

		byte[] iv_bytes = new byte[8];
		byte[] ss_hash = hash( ss );
		for ( int i = 0; i < 8; i++ ) {
			iv_bytes[i] = ss_hash[i];
		}
		return new IvParameterSpec( iv_bytes );

	}

	// Generates a shared secret, basically a key in a way, of size 32 bytes (256 bits), used to get key and IV
	public static byte[] getSharedSecret() throws Exception {

		byte[] ss = new byte[32];
		new SecureRandom().nextBytes( ss );
		return ss; 

	}

	// Plain old SHA-256 hash function made easy
	public static byte[] hash( byte[] input ) throws Exception {

		MessageDigest md = MessageDigest.getInstance( "SHA-256" );
		md.update( input );
		return md.digest();

	}

}