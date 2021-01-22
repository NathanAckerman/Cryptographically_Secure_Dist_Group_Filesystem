/* Driver program for FileSharing File Server */

public class RunFileServer {

	public static void main(String[] args) {
		if (args.length == 0) {
			System.out.println("You must provide a name for this server.");
			System.exit(1);
		} else if (args.length == 2) {
			String name = args[0];
			String port = args[1];
			try {
				Integer.parseInt(name.substring(0,1));
				System.out.println("Name cannot start with a number.");
				System.exit(1);
			} catch(NumberFormatException e) { /*This was the desired outcome.*/ }
			try {
				FileServer server = new FileServer(name, Integer.parseInt(port));
				server.start();
			} catch (NumberFormatException e) {
				System.out.println("Enter a valid port number or pass no arguments to use a random port");
				System.exit(1);
			}
		} else if(args.length == 1) {
			java.util.Random rand = new java.util.Random();
			String name = args[0];
			try {
				Integer.parseInt(name.substring(0,1));
				System.out.println("Name cannot start with a number.");
				System.exit(1);
			} catch(NumberFormatException e) { /*This was the desired outcome.*/ }

			int port = rand.nextInt(5000) + 10000;
			System.out.printf("Starting file server \"%s\" on random port: %d\n", name, port);
			FileServer server = new FileServer(name, port);
			server.start();
		}
	}

}
