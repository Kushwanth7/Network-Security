
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.KeyStore;
import java.util.Scanner;

import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManagerFactory;

public class server extends Thread 
{

	private ServerSocket serverSocket;
	public static String keyStorePassPhrase;
	public static String trustStorePassPhrase;
	public static String serverKeyStore;
	public static String trustStore;
	
	static String status;
	static String fileName;
	static String encryptionStatus;
	static String password;
	
	public server(int port) throws IOException
	{
		/*
		 * Create a new server socket and set the timeout of the socket to 10000000
		 */
		serverSocket = new ServerSocket(port);
	    serverSocket.setSoTimeout(10000000);
	}
	
	public void run()
	{
	    while(true)
	    {
	    	try
	        {
	    		System.out.println("Waiting for client on port " + serverSocket.getLocalPort() + "...");
	    		
	    		Socket server = serverSocket.accept();
	    		
	    		InputStream serverKeyStoreResource = new FileInputStream(serverKeyStore);
	    		char[] serverKeyStorePassphrase = keyStorePassPhrase.toCharArray();
	    		KeyStore serverKeys = KeyStore.getInstance("JKS");
	    		serverKeys.load(serverKeyStoreResource, serverKeyStorePassphrase);
	    		
	    		KeyManagerFactory serverKMF = KeyManagerFactory.getInstance("SunX509");
	    		serverKMF.init(serverKeys, serverKeyStorePassphrase);
	    		
	    		//Trust store
	    		InputStream serverTrustStore = new FileInputStream(trustStore);
	    		char[] serverTrustStorePassphrase = trustStorePassPhrase.toCharArray();
	    		KeyStore serverTrust = KeyStore.getInstance("JKS");
	    		serverTrust.load(serverTrustStore, serverTrustStorePassphrase);
	    		
	    		TrustManagerFactory serverTMF = TrustManagerFactory.getInstance("SunX509");
	    		serverTMF.init(serverTrust);
	    		
	    		SSLContext sslContext = SSLContext.getInstance("TLS");
	    		sslContext.init(serverKMF.getKeyManagers(), serverTMF.getTrustManagers(), null);
	    		SSLSocketFactory sf = sslContext.getSocketFactory();
	 
	    		
	    		InetSocketAddress serverSocketAddress = (InetSocketAddress) server.getRemoteSocketAddress();
	    		SSLSocket serverSSL = (SSLSocket) (sf.createSocket(server, serverSocketAddress.getHostName(), server.getPort(),true));
	    		serverSSL.setUseClientMode(false);
	    		serverSSL.setNeedClientAuth(true);
	    		serverSSL.setEnabledCipherSuites(serverSSL.getSupportedCipherSuites());
	    		serverSSL.setEnabledProtocols(serverSSL.getSupportedProtocols());
	    		serverSSL.startHandshake();
	    		server = serverSSL;
	    		
	    		System.out.println("Just connected to " + server.getRemoteSocketAddress());
	            DataInputStream in = new DataInputStream(server.getInputStream());
	            DataOutputStream out = new DataOutputStream(server.getOutputStream());
	            String userInput;
	    		while(true)
	    		{
	    			userInput = in.readUTF();
	    			if(userInput == "" || userInput == null)
	    				continue;
	    			if(userInput.equals("stop"))
	    			{
	    				break;
	    			}
	    			parseUserParameters(userInput);
	    			handleClientRequests(server);
	    		}
	            server.close();
	        }
	    	catch(Exception e)
	    	{
	    		System.out.println("An exception has occurred : " + e.getMessage());
	    	}
	    	
	}
}
	
	public static void handleClientRequests(Socket server)
	{
		if(status.equals("put"))
		{
			handlePut(server);
		}
		else if(status.equals("get"))
		{
			handleGet(server);
		}
	}
	
	public static void handleGet(Socket server)
	{
		InputStream is = null;
        DataInputStream dis = null;
        byte[] file = null; // the contents of the file are read into the byte array plaintext
        byte[] hash = null;
        
        try
        {
        	is = new FileInputStream(fileName + ".sha256");
        	dis = new DataInputStream(is);
        	hash = new byte[dis.available()];
        	dis.readFully(hash);
        	
        	is = new FileInputStream(fileName);
        	dis = new DataInputStream(is);
        	file = new byte[dis.available()];
        	dis.readFully(file);
        	
        	OutputStream outToClient = server.getOutputStream();
        	DataOutputStream out = new DataOutputStream(outToClient);
        	
        	// write the hash to the socket
        	for(int i=0;i<hash.length;i++)
        	{
        		out.write(hash[i]);
        	}
        	
        	// write the file length to the socket
        	out.writeInt(file.length);
        	
        	
        	for(int i=0;i<file.length;i++)
        	{
        		out.write(file[i]);
        	}
        }
		catch (Exception e)
		{
			System.out.println("An exception has occurred : " + e.getMessage());
			return;
		}
	}
	
	public static void handlePut(Socket server)
	{
		byte[] hash = new byte[64];
		byte[] fileBytes = new byte[1024000];
		byte readByte;
		//first 64 bytes are the signature that is received from the client
		try 
		{
			DataInputStream in = new DataInputStream(server.getInputStream());
        	
			int count = 0;
            while(count < 64)
            {
            	readByte = in.readByte();
            	hash[count] = readByte;
            	count ++;
            }
            
            int fileByteCount = in.readInt();
            //read the file bytes that is sent by the client
            count = 0;
            while(count < fileByteCount)
            {
            	readByte = in.readByte();
            	fileBytes[count] = readByte;
            	count++;
            	
            }
            
            //Write the hash to a file named filename.sha256
            DataOutputStream dataOut = new DataOutputStream(new FileOutputStream(fileName + ".sha256"));
            dataOut.write(hash);
            dataOut.close();
            dataOut = new DataOutputStream(new FileOutputStream(fileName));
            byte[] actualFile = new byte[fileByteCount];
            for(int i=0;i<fileByteCount;i++)
            {
            	actualFile[i] = fileBytes[i];
            }
            dataOut.write(actualFile);
            dataOut.close();
		} 
		catch (IOException e) 
		{
			System.out.println("An exception has occurred : " + e.getMessage());
		}
		catch (Exception e) 
		{
			System.out.println("An exception has occurred : " + e.getMessage());
		}
		
	}
	
	
	public static void parseUserParameters(String userInput)
	{
		try
		{
			String[] splits = userInput.split("\\s+");
			status = splits[0];
			if(status.equals("get"))
			{
				fileName = splits[1];
				encryptionStatus = splits[2];
				if(encryptionStatus.equals("E"))
				{
					password = splits[3];
				}
			}
			else if(status.equals("put"))
			{
				fileName = splits[1];
				encryptionStatus = splits[2];
				if(encryptionStatus.equals("E"))
				{
					password = splits[3];
				}
			}
		}
		catch(Exception e)
		{
			System.out.println("An exception has occurred : " + e.getMessage());
		}
	}
	
	
	
	public static void main(String[] args) 
	{
		int port=6066; //default port on which the server listens on
		
		try
		{
			port = Integer.parseInt(args[0]);
		}
		catch(Exception e)
		{
			System.out.println("An exception has ocurred : " + e.getMessage() + " The server will start on port 6066");
		}
		
		/*
		 * 1 - port
		 * 2 - server key store
		 * 3 - server trust store
		 * 4 - server key store password
		 * 5 - server trust store password
		 */
		
		serverKeyStore = args[1];
		trustStore = args[2];
		keyStorePassPhrase = args[3];
		trustStorePassPhrase = args[4];
		
		
		try
	    {
			Thread t = new server(port);
	        t.start(); // Start the server thread so that it continuously listens to client requests
	    }
		catch(IOException e)
	    {
			System.out.println("An exception has ocurred : " + e.getMessage());
	    }
		catch(Exception e)
    	{
    		System.out.println("An exception has ocurred : " + e.getMessage());
    	}
		
	}

}
