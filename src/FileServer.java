/* FileServer loads files from FileList.bin.  Stores files in shared_files directory. */

import java.io.File;
import java.net.Socket;
import java.util.Arrays;
import java.security.Key;
import java.util.Scanner;
import java.io.IOException;
import javax.crypto.Cipher;
import java.net.ServerSocket;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.security.MessageDigest;
import java.io.FileNotFoundException;
import javax.crypto.BadPaddingException;
import java.security.InvalidKeyException;
import javax.crypto.NoSuchPaddingException;
import java.security.NoSuchAlgorithmException;
import javax.crypto.IllegalBlockSizeException;

public class FileServer extends Server {

	public static FileList fileList;
	private Key gsPubKey;
	private String name;
	private String fL_FileName;

	public FileServer(String _name, int _port) {
		super(_port, _name);
		fL_FileName = _name + ".FileList.bin";
	}

	public void start() {
		ObjectInputStream fileStream;
		Scanner in = new Scanner(System.in);

		//This runs a thread that saves the lists on program exit
		Runtime runtime = Runtime.getRuntime();
		Thread catchExit = new Thread(new ShutDownListenerFS());
		runtime.addShutdownHook(catchExit);

		// Demand a public key for the group server for startup
		File gsPubKeyFile = new File("");
		while(!gsPubKeyFile.exists()) {
			System.out.print("Enter the path to the public key for the trusted Group Server: ");
			gsPubKeyFile = new File(in.next());
			if(!gsPubKeyFile.exists()) {
				System.out.println("Key file not found.");
			}
		}

		// attempt to load in the specified public key
		try {
			ObjectInputStream loadPubKey = new ObjectInputStream(new FileInputStream(gsPubKeyFile));
			gsPubKey = (Key)loadPubKey.readObject();
			loadPubKey.close();
		} catch(FileNotFoundException e) {
			System.err.println("Specified public key is missing.");
			e.printStackTrace();
			System.exit(1);
		} catch(IOException e) {
			System.err.println(e);
			e.printStackTrace();
			System.exit(1);
		} catch(ClassNotFoundException e) {
			System.err.println(e);
			e.printStackTrace();
			System.exit(1);
		} catch(ClassCastException e) {
			System.err.println("Unable to parse file as a Key. Shutting down.");
			System.exit(1);
		}

		//Open user file to get user list
		try {
			FileInputStream fis = new FileInputStream(fL_FileName);
			fileStream = new ObjectInputStream(fis);
			fileList = (FileList)fileStream.readObject();
		} catch(FileNotFoundException e) {
			System.out.println("FileList Does Not Exist. Creating FileList...");

			fileList = new FileList();

		} catch(IOException e) {
			System.out.println("Error reading from FileList file");
			System.exit(-1);
		} catch(ClassNotFoundException e) {
			System.out.println("Error reading from FileList file");
			System.exit(-1);
		}

		File file = new File("shared_files");
		if (file.mkdir()) {
			System.out.println("Created new shared_files directory");
		} else if (file.exists()) {
			System.out.println("Found shared_files directory");
		} else {
			System.out.println("Error creating shared_files directory");
		}

		//Autosave Daemon. Saves lists every 5 minutes
		AutoSaveFS aSave = new AutoSaveFS();
		aSave.setDaemon(true);
		aSave.start();

		//This block listens for connections and creates threads on new connections
		try {
			final ServerSocket serverSock = new ServerSocket(port);
			System.out.printf("%s up and running\n", this.getClass().getName());

			Socket sock = null;
			Thread thread = null;

			while(true) {
				sock = serverSock.accept();
				thread = new FileThread(sock, this);
				thread.start();
			}
		} catch(Exception e) {
			System.err.println("Error: " + e.getMessage());
			e.printStackTrace(System.err);
		}
	}

	/**
	 * Check that the given token's signature is untampered with.
	 *
	 * @param token The user's token.
	 * @return True if the token is valid (i.e. the signature string matches the actual signature).
	 */
	public boolean validateSignature(UserToken token) {
		try {
			Cipher c = Cipher.getInstance("RSA/None/OAEPWithSHA1AndMGF1Padding");
			c.init(Cipher.DECRYPT_MODE, this.gsPubKey);
			MessageDigest h = MessageDigest.getInstance("SHA-256");
			h.update(token.toSignatureString().getBytes());
			byte[] signedHash = c.doFinal(token.getSignature());
			byte[] currentHash = h.digest();
			return Arrays.equals(signedHash, currentHash);
		} catch(NoSuchAlgorithmException e) {
			System.err.println("Could not validate signature: NoSuchAlgorithmException");
			e.printStackTrace();
			return false;
		} catch(InvalidKeyException e) {
			System.err.println("Could not validate signature: InvalidKeyException");
			e.printStackTrace();
			return false;
		} catch(IllegalBlockSizeException e) {
			System.err.println("Could not validate signature: IllegalBlockSizeException");
			e.printStackTrace();
			return false;
		} catch(NoSuchPaddingException e) {
			System.out.println("Could not validate signature: NoSuchPaddingException");
			e.printStackTrace();
			return false;
		} catch(BadPaddingException e) {
			System.out.println("Could not validate signature: BadPaddingException");
			e.printStackTrace();
			return false;
		}
	}
	
	//This thread saves user and group lists
	class ShutDownListenerFS implements Runnable {
		public void run() {
			System.out.println("Shutting down server");
			ObjectOutputStream outStream;

			try {
				outStream = new ObjectOutputStream(new FileOutputStream(fL_FileName));
				outStream.writeObject(FileServer.fileList);
			} catch(Exception e) {
				System.err.println("Error: " + e.getMessage());
				e.printStackTrace(System.err);
			}
		}
	}

	class AutoSaveFS extends Thread {
		public void run() {
			do {
				try {
					Thread.sleep(300000); //Save group and user lists every 5 minutes
					System.out.println("Autosave file list...");
					ObjectOutputStream outStream;
					try {
						outStream = new ObjectOutputStream(new FileOutputStream(fL_FileName));
						outStream.writeObject(FileServer.fileList);
					} catch(Exception e) {
						System.err.println("Error: " + e.getMessage());
						e.printStackTrace(System.err);
					}
				} catch(Exception e) {
					System.out.println("Autosave Interrupted");
				}
			} while(true);
		}
	}
}
