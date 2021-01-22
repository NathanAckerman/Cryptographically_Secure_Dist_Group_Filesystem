import java.util.*;
import java.security.*;
import java.io.*;

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

public class CLI {

	static Scanner scanner = new Scanner(System.in);
	static String username;
	static String password;
	static UserToken current_token;
	static KeyChain keys;
	static String gci_ip;
	static String gci_port;
	static RSAPublicKey gci_public_key;

	public static void main(String[] args) {

		java.security.Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
		System.out.println("Starting command line interface.\n");
		System.out.print( "Please enter your username: " );
		username = scanner.nextLine();
		System.out.print( "Please enter your password: " );
		password = scanner.nextLine();
		System.out.println("\nPlease enter the connection details for the group server.");
		ArrayList<Object> conn = getServerInfo();
		try {
			Integer.parseInt((String)conn.get(1));
		} catch(Exception e) {
			System.out.println("Specified port was not an integer.");
			System.out.println("Connection failed.");
			System.exit(1);
		}
		gci_public_key = (RSAPublicKey)conn.get(2);
		current_token = getUserToken( (String)conn.get(0),(String)conn.get(1) );
		if(current_token == null) {
			System.out.println("Connection to group server could not be established.");
			System.exit(1);
		}
		gci_ip = (String)conn.get(0);
		gci_port = (String)conn.get(1);
		gci_public_key = (RSAPublicKey)conn.get(2);


		while (true) {
				
			System.out.println("\nWould you like to: ");
			System.out.println("1 - Connect to group server");
			System.out.println("2 - Connect to a file server");
			System.out.println("3 - Exit");
			System.out.print("\n> ");
			String input = scanner.nextLine();
			if(input.equals("1")) {
				useGroupServer();
			} else if(input.equals("2")) {
				useFileServer(current_token);
			} else if(input.equals("3")) {
				break;
			} else {
				System.out.println("Invalid input, please try again.");
			}
		}
		System.out.println("\nGoodbye!");
	}

	public static void useGroupServer() {

		GroupClientInterface gci = new GroupClient(gci_public_key);
		boolean proceed = true;

		//current_token = getUserToken(gci_ip, gci_port, password);
		if(current_token == null) {
			System.out.println("Connection could not be established with the Group Server.");
			return;
		} else {
			gci.connect(gci_ip, Integer.parseInt(gci_port));
			System.out.println("Connection to Group Server established.");
			keys = getKeyChain( gci );
		}

		while (proceed) {
			System.out.println("\nWould you like to: ");
			System.out.println( "1 - Create a new User" );
			System.out.println( "2 - Delete a User" );
			System.out.println( "3 - Create a Group" );
			System.out.println( "4 - Delete a Group" );
			System.out.println( "5 - Add a User to a Group" );
			System.out.println( "6 - Remove a User from a Group" );
			System.out.println( "7 - List members of a Group" );
			System.out.println( "8 - Exit" );
			System.out.print("\n> ");
			String input = scanner.nextLine();

			switch( input ) {
				case "1":
					createUser(gci);
					break;

				case "2":
					deleteUser(gci);
					break;

				case "3":
					createGroup(gci);
					break;

				case "4":
					deleteGroup(gci);
					break;

				case "5":
					addUserToGroup(gci);
					break;

				case "6":
					removeUserFromGroup(gci);
					break;

				case "7":
					listGroupMembers(gci);
					break;

				case "8":
					groupExit(gci);
					proceed = false;
					break;

				default:
					System.out.println("Invalid input.");
			}
		}
	}

	public static void useFileServer(UserToken token) {

		FileClientInterface fci = null;
		boolean proceed = true;
		RSAPublicKey fci_pub_key = null;

		System.out.println( "\nPlease provide the IP address and port number for the file server you wish to connect to:" );
		ArrayList<Object> serverInfo = getServerInfo();
		try {
			int port_num = Integer.parseInt((String)serverInfo.get(1));
			fci_pub_key = (RSAPublicKey)serverInfo.get(2);
			fci = new FileClient(fci_pub_key);

			// set this file server as the recipient for the user's token
			GroupClientInterface gci = new GroupClient(gci_public_key);
			gci.connect(gci_ip, Integer.parseInt(gci_port));
			UserToken new_token = gci.setRecipient(current_token, fci_pub_key);
			gci.disconnect();

			if(new_token != null) {
				current_token = new_token;
			} else {
				System.out.println("Connection to the file server was not a success");
				return;
			}

			if(!fci.connect( (String)serverInfo.get( 0 ), port_num )) {
				System.out.println("Connection to file server was not a success");
				return;
			}
			System.out.println( "Connection established" );
		} catch(Exception e) {
			e.printStackTrace();
			System.out.println( "Connection not established" );
			return;
		}

		while (proceed) {
			System.out.println("\nWould you like to: ");
			System.out.println( "1 - List all available Files" );
			System.out.println( "2 - Upload a File" );
			System.out.println( "3 - Download a File" );
			System.out.println( "4 - Delete a File" );
			System.out.println( "5 - Exit" );
			System.out.print("\n> ");
			String input = scanner.nextLine();

			switch( input ) {
				case "1": 
					listFiles( fci );
					break;

				case "2":
					uploadFile(fci);
					break;

				case "3":
					downloadFile(fci);
					break;

				case "4":
					deleteFile(fci);
					break;

				case "5":
					fileExit(fci);
					proceed = false;
					break;

				default:
					System.out.println("Invalid input.");
					break;
			}

		}
	}

	public static UserToken getUserToken( String ip, String port ) {
		GroupClientInterface gci = new GroupClient(gci_public_key);
		if(!gci.connect( ip, Integer.parseInt( port ) )){
			return null;
		}
		UserToken t = gci.getToken( username, password );
		keys = gci.getKeyChain( t );
		gci.disconnect();
		return t;
	}

	public static KeyChain getKeyChain( GroupClientInterface gci ) {
		return gci.getKeyChain( current_token );
	}

	public static ArrayList<Object> getServerInfo() { // 0 is IP, 1 is port
		System.out.print( "IP address: " );
		String ip = scanner.nextLine();
		if(ip.equals(".")) {
			ip = "localhost";
		}
		System.out.print( "Port #: " );
		String port = scanner.nextLine();

		System.out.print( "Server Pub Key Filepath: " );
		String pubKeyFileName = scanner.nextLine();

		File pubKeyFile = new File(pubKeyFileName);
		RSAPublicKey pub_key = loadKey(pubKeyFile);
		if(pub_key == null) {
			System.out.println("Unable to connect to server without a valid public key.");
			ArrayList<Object> temp = getServerInfo();
			return temp;
		} else {
			ArrayList<Object> temp = new ArrayList<Object>();
			temp.add( ip );
			temp.add( port );
			temp.add( pub_key );
			return temp;
		}

	}

	public static RSAPublicKey loadKey(File pubKeyFile) {

		try {
			ObjectInputStream loadPub = new ObjectInputStream(
				new FileInputStream(pubKeyFile));
			RSAPublicKey pubKey = (RSAPublicKey)loadPub.readObject();
			return pubKey;
		} catch(FileNotFoundException e) {
			System.err.println("Couldn't read from that file");
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
		return null;
	}

	public static void createUser(GroupClientInterface gci) {
		System.out.print("Enter a username to create: ");
		String inp_username = scanner.nextLine();
		System.out.print("Enter a password for the user: ");
		String inp_password = scanner.nextLine();
		boolean success = gci.createUser(inp_username, inp_password, current_token);
		if(success) {
			System.out.println("User successfully created");
		} else {
			System.out.println("User creation has failed");
		}
	}

	public static void deleteUser(GroupClientInterface gci) {
		System.out.print("Enter a username to delete: ");
		String inp_username = scanner.nextLine();
		boolean success = gci.deleteUser(inp_username, current_token);
		if(success) {
			System.out.println("User successfully deleted");
		} else {
			System.out.println("User deletion has failed");
		}

		keys = getKeyChain( gci );

	}

	public static void createGroup( GroupClientInterface gci ) {
		System.out.print( "Enter the name of the group to create: " );
		String inp_groupname = scanner.nextLine();
		boolean success = gci.createGroup( inp_groupname, current_token );
		if ( success ) {
			System.out.println( "Group "+ inp_groupname +" successfully created" );
		} 
		else {
			System.out.println( "Group "+ inp_groupname +" could not be created" );
		}

		current_token = gci.getToken( username, password );
		keys = getKeyChain( gci );

	}

	public static void deleteGroup( GroupClientInterface gci ) {
		System.out.print( "Enter the name of the group to delete: " );
		String inp_groupname = scanner.nextLine();
		boolean success = gci.deleteGroup( inp_groupname, current_token );
		if ( success ) {
			System.out.println( "Group "+ inp_groupname +" successfully deleted" );
		} 
		else {
			System.out.println( "Group "+ inp_groupname +" could not be deleted" );
		}

		current_token = gci.getToken( username, password );
		keys = getKeyChain( gci );

	}

	public static void groupExit(GroupClientInterface gci) {
		System.out.println("Disconnecting from group server.");
		current_token = gci.getToken( username, password );
		keys = getKeyChain( gci );
		gci.disconnect();
	}

	public static void addUserToGroup(GroupClientInterface gci) {
		System.out.print("Enter a username to add: ");
		String inp_username = scanner.nextLine();
		System.out.print("Enter the group name to add to: ");
		String inp_groupname = scanner.nextLine();
		boolean success = gci.addUserToGroup(inp_username, inp_groupname, current_token);
		if(success) {
			System.out.println("User successfully added to group");
		} else {
			System.out.println("User addition has failed");
		}

		keys = getKeyChain( gci );

	}

	public static void removeUserFromGroup(GroupClientInterface gci) {
		System.out.print("Enter a username to remove: ");
		String inp_username = scanner.nextLine();
		System.out.print("Enter the group name to remove from: ");
		String inp_groupname = scanner.nextLine();
		boolean success = gci.deleteUserFromGroup(inp_username, inp_groupname, current_token);
		if(success) {
			System.out.println("Group sucessfully removed from user");
		} else {
			System.out.println("Group removal was unsuccessful");
		}

		keys = getKeyChain( gci );

	}

	public static void listGroupMembers( GroupClientInterface gci ) {
		System.out.print( "Enter a group name to list the members of: " );
		String inp_groupname = scanner.nextLine();
		List<String> members = gci.listMembers( inp_groupname, current_token );
		if ( members != null ) {

			if ( members.size() > 0 ) {

				System.out.println( "Group "+ inp_groupname +" contains member(s):" );
				for(String member : members) { System.out.println( member ); }

			} else {
				System.out.println( "Group "+ inp_groupname +" does not contain any members." );
			}
		}
		else {
			System.out.println("Cannot list members for group "+inp_groupname);
		}
	}

	public static void listFiles( FileClientInterface fci ) {
		List<String> files = fci.listFiles( current_token );
		if ( files != null ) {

			if ( files.size() > 0 ) {
				System.out.println( "Available files:" );
				for ( String file : files ) { System.out.println( file ); }
			}
			else {
				System.out.println( "No files currently available to user `"+current_token.getSubject()+"`" );
			}

		}
		else {
			System.out.println( "Unable to list files visible to user `"+current_token.getSubject()+"`" );
		}
	}

	public static void fileExit(FileClientInterface fci) {
		System.out.println("Disconnecting from file server.");
		fci.disconnect();
	}

	public static void deleteFile(FileClientInterface fci) {
		int choice = -1;
		ArrayList<String> files = (ArrayList<String>)fci.listFiles(current_token);
		if(files == null || files.size() == 0) {
			System.out.println("No files present to delete.");
			return;
		}

		while(choice < 0 || choice > files.size()) {
			System.out.println("\nWhich file would you like to delete? Please type only the number or nothing if you would like to cancel the deletion.");
			for(int i=0; i < files.size(); i++) {
				System.out.printf("(%d) - `%s`\n", i, files.get(i));
			}
			System.out.print("> ");
			String s = scanner.nextLine();
			if(s.equals("")) {
				System.out.println("Deletion cancelled.");
				return;
			}
			try {
				choice = Integer.parseInt(s);
			} catch(NumberFormatException e) {
				System.err.println("Input invalid.");
				choice = -1;
			}
		}

		fci.delete(files.get(choice), current_token);
	}

	public static void uploadFile(FileClientInterface fci) {
		System.out.println("To upload a file, please enter the path to the file on your machine followed by the intended path to the file on the server, then the Group you wish to store the file under.");
		System.out.print("Local file path: ");
		String source = scanner.nextLine();
		System.out.print("Remote file path: ");
		String dest = scanner.nextLine();
		System.out.print("Group name: ");
		String group = scanner.nextLine();

		if(fci.upload(source, dest, group, current_token, keys.get( group ))) {
			System.out.println("Upload successful!");
		}
	}

	public static void downloadFile(FileClientInterface fci) {
		System.out.println("To download a file, please enter the path to the file on the server then the intended path to the file on your machine.");
		System.out.print("Remote file path: ");
		String source = scanner.nextLine();
		System.out.print("Local file path: ");
		String dest = scanner.nextLine();
		System.out.print( "Group name: " );
		String group = scanner.nextLine();

		if(source.equals("") || dest.equals("") || group.equals("")) {
			System.err.println("Invalid inputs. Download aborted.");
		} else if(fci.download(source, dest, current_token, keys.get( group ) )) {
			System.out.println("Download successful!");
		}
	}
}
