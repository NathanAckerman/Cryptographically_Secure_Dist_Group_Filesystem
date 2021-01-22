/* Group server. Server loads the users from UserList.bin and the groups from
 * GroupList.bin.
 * If user list does not exist, it creates a new list and makes the user the
 * server administrator. Similarly, if the group list doesn't exist, it
 * creates a new list and makes the administrative user from the user list
 * initialization. If the group list is lost without losing the user list,
 * then the group list will require input to designate a new administrating
 * user. 
 * On exit, the server saves the user and group lists to files.
 */

import java.net.Socket;
import java.util.Arrays;
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

public class GroupServer extends Server {

	public UserList userList;
	public GroupList groupList;
	public PasswordList passwordList;

	public GroupServer(int _port) {
		super(_port, "alpha");
	}

	public void start() {
		// Overwrote server.start() because if no user file exists, initial admin account needs to be created

		String userFile = "UserList.bin";
		String groupFile = "GroupList.bin";
		String passwordFile = "PasswordList.bin";
		Scanner console = new Scanner(System.in);
		ObjectInputStream userStream;
		ObjectInputStream groupStream;
		ObjectInputStream passwordStream;
		String newAdmin = null;

		//This runs a thread that saves the lists on program exit
		Runtime runtime = Runtime.getRuntime();
		runtime.addShutdownHook(new ShutDownListener(this));

		//Open user file to get user list
		try {
			FileInputStream fis = new FileInputStream(userFile);
			userStream = new ObjectInputStream(fis);
			userList = (UserList)userStream.readObject();

			fis = new FileInputStream(passwordFile);
			passwordStream = new ObjectInputStream(fis);
			passwordList = (PasswordList)passwordStream.readObject();
		} catch(FileNotFoundException e) {
			System.out.println("UserList File Does Not Exist. Creating UserList...");
			System.out.println("No users currently exist. Your account will be the administrator.");
			System.out.print("Enter your username: ");
			String username = console.next();
			console.nextLine();
			newAdmin = username;

			System.out.print("Enter your password: ");
			String password = console.next();
			console.nextLine();

			//Create a new list, add current user to the ADMIN group. They now own the ADMIN group.
			userList = new UserList();
			userList.addUser(username);
			userList.addGroup(username, "ADMIN");
			userList.addOwnership(username, "ADMIN");

			//Create a new PasswordList
			passwordList = new PasswordList();
			passwordList.addEntry(username, password, userList.getSalt(username));
		} catch(IOException e) {
			System.out.println("Error reading from UserList file");
			System.exit(-1);
		} catch(ClassNotFoundException e) {
			System.out.println("Error reading from UserList file");
			System.exit(-1);
		}

		// Open group file to get group list
		try {
			FileInputStream fis = new FileInputStream(groupFile);
			groupStream = new ObjectInputStream(fis);
			groupList = (GroupList)groupStream.readObject();
		} catch(FileNotFoundException e) {
			System.out.println("GroupList File Does Not Exist. Creating GroupList...");
			System.out.println("No groups currently exist.");
			System.out.println("Adding group ADMIN");
			
			groupList = new GroupList();
			groupList.addGroup("ADMIN");

			// newAdmin is the name of the administrator account created when
			// the UserList.bin file isn't present. But the GroupList.bin file
			// might be missing independent of the UserList.bin, so if the
			// newAdmin wasn't updated from its initial null value, we don't
			// know who to designate as the owning administrator.
			if(newAdmin == null) {
				System.out.println("`ADMIN` currently has no owner. The System Administrator should take action immediately.");
			} else {
				groupList.addOwner("ADMIN", newAdmin);
			}
		} catch(IOException e) {
			System.out.println("Error reading from GroupList file");
			System.exit(-1);
		} catch(ClassNotFoundException e) {
			System.out.println("Error reading from GroupList file");
			System.exit(-1);
		}

		//Autosave Daemon. Saves lists every 5 minutes
		AutoSave aSave = new AutoSave(this);
		aSave.setDaemon(true);
		aSave.start();

		//This block listens for connections and creates threads on new connections
		try {
			final ServerSocket serverSock = new ServerSocket(port);
			System.out.printf("%s up and running\n", this.getClass().getName());

			Socket sock = null;
			GroupThread thread = null;

			while(true) {
				sock = serverSock.accept();
				thread = new GroupThread(sock, this);
				thread.start();
			}
		} catch(Exception e) {
			System.err.println("Error: " + e.getMessage());
			e.printStackTrace(System.err);
		}
	}

	/**
	 * Signs a byte array object using this server's private key.
	 *
	 * @param raw The unsigned byte array to sign.
	 * @return A signed byte array.
	 */
	public byte[] signBytes(byte[] raw) {
		try {
			Cipher c = Cipher.getInstance("RSA/None/OAEPWithSHA1AndMGF1Padding");
			c.init(Cipher.ENCRYPT_MODE, this.prvKey);
			byte[] sig = c.doFinal(raw);
			return sig;
		} catch(NoSuchAlgorithmException e) {
			System.err.println("Could not sign: NoSuchAlgorithmException");
			e.printStackTrace();
			return null;
		} catch(InvalidKeyException e) {
			System.err.println("Could not sign: InvalidKeyException");
			e.printStackTrace();
			return null;
		} catch(IllegalBlockSizeException e) {
			System.err.println("Could not sign: IllegalBlockSizeException");
			e.printStackTrace();
			return null;
		} catch(NoSuchPaddingException e) {
			System.out.println("Could not sign: NoSuchPaddingException");
			e.printStackTrace();
			return null;
		} catch(BadPaddingException e) {
			System.out.println("Could not sign: BadPaddingException");
			e.printStackTrace();
			return null;
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
			c.init(Cipher.DECRYPT_MODE, this.pubKey);
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
}

//This thread saves the user list
class ShutDownListener extends Thread {
	public GroupServer my_gs;

	public ShutDownListener (GroupServer _gs) {
		my_gs = _gs;
	}

	public void run() {
		System.out.println("Shutting down server");
		ObjectOutputStream outStream;
		try {
			outStream = new ObjectOutputStream(new FileOutputStream("UserList.bin"));
			outStream.writeObject(my_gs.userList);
			
			outStream = new ObjectOutputStream(new FileOutputStream("GroupList.bin"));
			outStream.writeObject(my_gs.groupList);

			outStream = new ObjectOutputStream(new FileOutputStream("PasswordList.bin"));
			outStream.writeObject(my_gs.passwordList);
		} catch(Exception e) {
			System.err.println("Error: " + e.getMessage());
			e.printStackTrace(System.err);
		}
	}
}

class AutoSave extends Thread {
	public GroupServer my_gs;

	public AutoSave (GroupServer _gs) {
		my_gs = _gs;
	}

	public void run() {
		do {
			try {
				Thread.sleep(300000); //Save group and user lists every 5 minutes
				System.out.println("Autosave group, user, and password lists...");
				ObjectOutputStream outStream;
				try {
					outStream = new ObjectOutputStream(new FileOutputStream("UserList.bin"));
					outStream.writeObject(my_gs.userList);
				} catch(Exception e) {
					System.err.println("Error: " + e.getMessage());
					e.printStackTrace(System.err);
				}

				try {
					outStream = new ObjectOutputStream(new FileOutputStream("GroupList.bin"));
					outStream.writeObject(my_gs.groupList);
				} catch(Exception e) {
					System.err.println("Error: " + e.getMessage());
					e.printStackTrace(System.err);
				}

				try {
					outStream = new ObjectOutputStream(new FileOutputStream("PasswordList.bin"));
					outStream.writeObject(my_gs.passwordList);
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
