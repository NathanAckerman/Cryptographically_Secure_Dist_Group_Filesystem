import java.io.File;
import java.net.Socket;
import java.security.Key;
import java.io.IOException;
import javax.crypto.Cipher;
import java.security.KeyPair;
import java.security.Security;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.io.FileNotFoundException;
import java.security.KeyPairGenerator;
import java.security.spec.RSAPublicKeySpec;
import javax.crypto.NoSuchPaddingException;
import java.security.spec.RSAPrivateKeySpec;
import java.security.interfaces.RSAPublicKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.NoSuchAlgorithmException;

public abstract class Server {
	// port to connect to this server
	protected int port;
	// name of this server; not used for much right now
	public String name;
	protected RSAPublicKey pubKey;
	protected RSAPrivateKey prvKey;

	abstract void start();

	public Server(int _SERVER_PORT, String _serverName) {
		// Add security provider
		Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());

		String pubKeyFileName = _serverName + ".pub.bin";
		String prvKeyFileName = _serverName + ".prv.bin";

		// check if a key pair already exists for this server
		File pubKeyFile = new File(pubKeyFileName);
		File prvKeyFile = new File(prvKeyFileName);
		if(!pubKeyFile.exists() || !prvKeyFile.exists()) {
			System.out.println("Missing private and/or public keys, generating new ones...");
			
			try {
				// generate key pair
				Cipher c = Cipher.getInstance("RSA/None/OAEPWithSHA1AndMGF1Padding");
				KeyPairGenerator g = KeyPairGenerator.getInstance("RSA");
				g.initialize(8192);
				KeyPair kpair = g.generateKeyPair();
				pubKey = (RSAPublicKey)kpair.getPublic();
				prvKey = (RSAPrivateKey)kpair.getPrivate();

				// save key pair to disk
				ObjectOutputStream savePub = new ObjectOutputStream(
					new FileOutputStream(pubKeyFile));
				savePub.writeObject(pubKey);
				ObjectOutputStream savePrv = new ObjectOutputStream(
					new FileOutputStream(prvKeyFile));
				savePrv.writeObject(prvKey);

				// close files
				savePub.close();
				savePrv.close();
			} catch(NoSuchAlgorithmException e) {
				System.err.println("Missing specified algorithm.");
				e.printStackTrace();
				System.exit(1);
			} catch(NoSuchPaddingException e) {
				System.err.println("Missing specified padding scheme.");
				e.printStackTrace();
				System.exit(1);
			} catch(FileNotFoundException e) {
				System.err.println("Somehow I'm getting a file not found exception while *creating* a file...");
				e.printStackTrace();
				System.exit(1);
			} catch(IOException e) {
				System.err.println("Wasn't able to write the keypair object.");
				e.printStackTrace();
				System.exit(1);
			}
		} else {
			System.out.println("Private and public keys found, loading...");

			try {
				ObjectInputStream loadPub = new ObjectInputStream(
					new FileInputStream(pubKeyFile));
				pubKey = (RSAPublicKey)loadPub.readObject();
				ObjectInputStream loadPrv = new ObjectInputStream(
					new FileInputStream(prvKeyFile));
				prvKey = (RSAPrivateKey)loadPrv.readObject();

				// close files
				loadPub.close();
				loadPrv.close();
			} catch(FileNotFoundException e) {
				System.err.println("Didn't find the file that I already checked for...");
				e.printStackTrace();
				System.exit(1);
			} catch(IOException e) {
				System.out.println("Wasn't able to read the keypair object.");
				e.printStackTrace();
				System.exit(1);
			} catch(ClassNotFoundException e) {
				System.out.println("The object wasn't a keypair.");
				e.printStackTrace();
				System.exit(1);
			}
		}

		port = _SERVER_PORT;
		name = _serverName;
	}


	public int getPort() {
		return port;
	}

	public String getName() {
		return name;
	}
	
	public Key getPrivateKey() {
		return this.prvKey;
	}
	public Key getPublicKey() {
		return this.pubKey;
	}
}
