import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.Socket;

public class ClientSocket
{

	public static void main(String[] args) 
	{
		String serverName = args[0];
	    int port = Integer.parseInt(args[1]);
	    System.out.println("The serverName is = " + serverName + " the port on which the server is listening is " + port);
	    try
	      {
	         System.out.println("Connecting to " + serverName +
			 " on port " + port);
	         Socket client = new Socket(serverName, port);
	         System.out.println("Just connected to " 
			 + client.getRemoteSocketAddress());
	         OutputStream outToServer = client.getOutputStream();
	         DataOutputStream out = new DataOutputStream(outToServer);
	         out.writeUTF("Hello from "
	                      + client.getLocalSocketAddress());
	         InputStream inFromServer = client.getInputStream();
	         DataInputStream in =
	                        new DataInputStream(inFromServer);
	         System.out.println("Server says " + in.readUTF());
	         client.close();
	      }
	    catch(IOException e)
	    {
	    	e.printStackTrace();
	    }
	}

}
