
import java.util.Random;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.security.KeyStore;
import java.security.MessageDigest;
import java.util.Scanner;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManagerFactory;
import javax.xml.bind.DatatypeConverter;

public class client 
{
	static String status;
	static String fileName;
	static String encryptionStatus;
	static String password;
	

	public static String generateAESKey(String password)
	{
		int seed = 0;
		for(int i=0;i<password.length();i++)
		{
			seed = seed + password.charAt(i);
		}
		Random rand = new Random(seed);
		StringBuilder sb = new StringBuilder();
		for(int i=0;i<16;i++)
		{
			int n = rand.nextInt(27);
			sb.append((char) ('`'+n));
		}
		return sb.toString();
	}
	
	public static String acceptUserParameters()
	{
		String userInput = null;
		System.out.println("Enter the parameters");
		try
		{
			Scanner terminalInput = new Scanner(System.in);
			userInput = terminalInput.nextLine();
			String[] splits = userInput.split("\\s+");
			status = splits[0];
			if(status.equals("stop"))
			{
				System.out.println("Exiting");
			}
			else if(status.equals("get"))
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
		return userInput;
	}
	
	public static void performActionOnUserParameters(Socket client)
	{
		if(status.equals("get") && encryptionStatus.equals("E"))
		{
			doAGetWithDecryption(client);
		}
		else if(status.equals("get") && encryptionStatus.equals("N"))
		{
			doAGetWithOutDecryption(client);
		}
		else if(status.equals("put") && encryptionStatus.equals("E"))
		{
			doAPutWithEncryption(client);
		}
		else if(status.equals("put") && encryptionStatus.equals("N"))
		{
			doAPutWithoutEncryption(client);
		}
	}
	
	public static void doAGetWithOutDecryption(Socket client)
	{
		/*
		 * first read the hash from the server
		 * then read the file from the server
		 * generate the hash for the server
		 * compare the generated hash and the hash received
		 * if the hashes match write the file else do not write the file
		 */
		byte[] hash = new byte[64];
		byte[] fileBytes = new byte[1024000];
		byte readByte;
		try 
		{
			DataInputStream in = new DataInputStream(client.getInputStream());
        	int count = 0;
            while(count < 64)
            {
            	readByte = in.readByte();
            	hash[count] = readByte;
            	count ++;
            }
            
            String hashHex = new String(hash);
            
            int fileByteCount = in.readInt();
            //read the file bytes that is sent by the server
            
            count = 0;
            while(count < fileByteCount)
            {
            	readByte = in.readByte();
            	fileBytes[count] = readByte;
            	count++;
            }
            byte[] actualFile = new byte[fileByteCount];
            for(int i=0;i<fileByteCount;i++)
            {
            	actualFile[i] = fileBytes[i];
            }
            
            MessageDigest digest = MessageDigest.getInstance("SHA-256"); //Using SHA-256 for generating the hash
			byte[] hashValue = digest.digest(actualFile);
			String hashGenerated = DatatypeConverter.printHexBinary(hashValue); //Converting the hash value bytes to HEX
			if(hashGenerated.equals(hashHex))
			{
				//hashes match so write to a file
				System.out.println("Hash verification passed");
				DataOutputStream dataOut = new DataOutputStream(new FileOutputStream(fileName));
	            dataOut.write(actualFile);
			}
			else
			{
				System.out.println("Hash verification failed");
			}
		}
		catch(Exception e)
		{
			System.out.println("An exception has occurred : " + e.getMessage());
		}
	}
	
	public static void doAGetWithDecryption(Socket client)
	{
		byte[] hash = new byte[64];
		byte[] fileBytes = new byte[1024000];
		byte readByte;
		try 
		{
			DataInputStream in = new DataInputStream(client.getInputStream());
        	if(in.available() == 0)
        		Thread.sleep(1000);
        	int count = 0;
            while(count < 64)
            {
            	readByte = in.readByte();
            	hash[count] = readByte;
            	count ++;
            }
            
            String hashHex = new String(hash);
            
            int fileByteCount = in.readInt();
            //read the file bytes that is sent by the server
            /*
             * First 16 bytes are that of the initialization vector,
             * the remaining bytes are that of the file
             */
            byte[] initBytes = new byte[16];
            count = 0;
            while(count < 16)
            {
            	readByte = in.readByte();
            	initBytes[count] = readByte;
            	count++;
            }
            fileByteCount = fileByteCount-16;
            count = 0;
            while(count < fileByteCount)
            {
            	readByte = in.readByte();
            	fileBytes[count] = readByte;
            	count++;
            }
            byte[] actualFile = new byte[fileByteCount];
            for(int i=0;i<fileByteCount;i++)
            {
            	actualFile[i] = fileBytes[i];
            }
            String key = generateAESKey(password);
            // decrypt the file that is received from the server
            Cipher cipher;
    		String initVector = new String(initBytes);
    		cipher = Cipher.getInstance("AES/CBC/PKCS5PADDING");
			IvParameterSpec iv = new IvParameterSpec(initVector.getBytes("UTF-8"));
			SecretKeySpec skeySpec = new SecretKeySpec(key.getBytes("UTF-8"), "AES");
			cipher.init(Cipher.DECRYPT_MODE, skeySpec, iv);
			byte[] originalText = cipher.doFinal(actualFile);
			
			MessageDigest digest = MessageDigest.getInstance("SHA-256"); //Using SHA-256 for generating the hash
			byte[] hashValue = digest.digest(originalText);
			String hashGenerated = DatatypeConverter.printHexBinary(hashValue); //Converting the hash value bytes to HEX
			
			if(hashGenerated.equals(hashHex))
			{
				//hashes match so write to a file
				System.out.println("Hash verification passed");
				DataOutputStream dataOut = new DataOutputStream(new FileOutputStream(fileName));
	            dataOut.write(originalText);
			}
			else
			{
				System.out.println("Hash verification failed");
			}
            
		}
		catch(Exception e)
		{
			System.out.println("An exception has occurred : " + e.getMessage());
		}
	}
	
	public static void doAPutWithoutEncryption(Socket client)
	{
		InputStream is = null;
        DataInputStream dis = null;
        byte[] plainText = null; // the contents of the file are read into the byte array plaintext 
        
        try
        {
        	is = new FileInputStream(fileName);
        	dis = new DataInputStream(is);
        	plainText = new byte[dis.available()];
        	dis.readFully(plainText);
        }
		catch (Exception e)
		{
			System.out.println("An exception has occurred : " + e.getMessage());
			return;
		}
        
        byte[] hashBytes;
		try 
	    {
			MessageDigest digest = MessageDigest.getInstance("SHA-256"); //Using SHA-256 for generating the hash
			byte[] hashValue = digest.digest(plainText);
			String hashHex = DatatypeConverter.printHexBinary(hashValue); //Converting the hash value bytes to HEX
			hashBytes = hashHex.getBytes();
	    }
		catch (Exception e)
		{
			System.out.println("An exception has occurred : " + e.getMessage());
			return;
		}
        
        OutputStream outToServer;
		try 
		{ 
			outToServer = client.getOutputStream();
			DataOutputStream out = new DataOutputStream(outToServer);
			// The length of the hashbytes is 64, first 64 bytes will be the hash of the file
			for(int i=0;i<hashBytes.length;i++)
			{
				out.write(hashBytes[i]);
			}
			
			out.writeInt(plainText.length);
			
			for(int i=0;i<plainText.length;i++)
	        {
	        	 out.write(plainText[i]);
	        }
		} 
		catch (IOException e) 
		{
			System.out.println("An exception has occurred : " + e.getMessage());
			return;
		}
		catch (Exception e)
		{
			System.out.println("An exception has occurred : " + e.getMessage());
			return;
		}
        
	}
	
	
	public static void doAPutWithEncryption(Socket client)
	{
		/*
		 * Generate the Aes key using the password as a seed to the random number generator and 
		 * get a 16 byte key from that
		 */
		InputStream is = null;
        DataInputStream dis = null;
        byte[] plainText = null; // the contents of the file are read into the byte array plaintext 
        
        try
        {
        	is = new FileInputStream(fileName);
        	dis = new DataInputStream(is);
        	plainText = new byte[dis.available()];
        	dis.readFully(plainText);
        }
		catch (Exception e)
		{
			System.out.println("An exception has occurred : " + e.getMessage());
			return;
		}
        
        byte[] hashBytes;
		try 
	    {
			MessageDigest digest = MessageDigest.getInstance("SHA-256"); //Using SHA-256 for generating the hash
			byte[] hashValue = digest.digest(plainText);
			String hashHex = DatatypeConverter.printHexBinary(hashValue); //Converting the hash value bytes to HEX
			hashBytes = hashHex.getBytes();
	    }
		catch (Exception e)
		{
			System.out.println("An exception has occurred : " + e.getMessage());
			return;
		}
        
        String key = generateAESKey(password);
	    String initVector = "RandomInitVector"; //The initilaization Vector used is RandomInitVector, it is of 16 bytes in length and both client and the server have agreed upon the same
	    Cipher cipher;
	    byte[] encrypted = null; // the plain text bytes encrypted are stored in the byte array encrypted
	    try 
		{
			IvParameterSpec iv = new IvParameterSpec(initVector.getBytes("UTF-8"));
			SecretKeySpec skeySpec = new SecretKeySpec(key.getBytes("UTF-8"), "AES");
			cipher = Cipher.getInstance("AES/CBC/PKCS5PADDING"); //Encrypting using AES in CBC mode, also Padding is done if the plaintext is bytes is not an integral number of 16
            cipher.init(Cipher.ENCRYPT_MODE, skeySpec, iv);
            encrypted = cipher.doFinal(plainText); // encrypt the plaintext bytes and store it in the byte array encrypted
		}
	    catch(Exception e)
	    {
	    	System.out.println("An exception has occurred : " + e.getMessage());
	    	return;
	    }
	    byte[] initVectorBytes = initVector.getBytes();
	    OutputStream outToServer;
		try 
		{ 
			// Remember you have to add the functionality of appending a iv to the cipher text before sending
			outToServer = client.getOutputStream();
			DataOutputStream out = new DataOutputStream(outToServer);
			
			// The length of the hashbytes is 64, first 64 bytes will be the hash of the file
			for(int i=0;i<hashBytes.length;i++)
			{
				out.write(hashBytes[i]);
			}
			
			out.writeInt(initVectorBytes.length + encrypted.length);
			for(int i=0;i<initVectorBytes.length;i++)
			{
				out.write(initVectorBytes[i]);
			}
			for(int i=0;i<encrypted.length;i++)
	        {
				out.write(encrypted[i]);
	        }
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

	public static void main(String[] args) 
	{
		/*
		 * 1 - servername
		 * 2 - port
		 * 3 - client key store
		 * 4 - client trust store
		 * 5 - client key store pass phrase
		 * 6 - client trust store pass phrase
		 */
		
		String serverName = args[0];
		int port = 6066; // default port
		
		try
		{
			port = Integer.parseInt(args[1]);
		}
		catch(Exception e)
		{
			System.out.println("An exception has ocurred : " + e.getMessage() + " The server will start on port 6066");
		}
		
		String clientKeyStore = args[2];
		String trustStore = args[3];
		String clientStorePassPhrase = args[4];
		String trustStorePassPhrase = args[5];
		
		
		
		try
	      {
			 System.out.println("Connecting to " + serverName + " on port " + port);
			 
			 InputStream clientKeyStoreResource = new FileInputStream(clientKeyStore);
			 char[] clientKeyStorePassphrase = clientStorePassPhrase.toCharArray();
			 KeyStore clientKeys = KeyStore.getInstance("JKS");
			 clientKeys.load(clientKeyStoreResource, clientKeyStorePassphrase);
				
			 KeyManagerFactory clientKMF = KeyManagerFactory.getInstance("SunX509");
			 clientKMF.init(clientKeys, clientKeyStorePassphrase);
			 
			//Trust store
			InputStream clientTrustStore = new FileInputStream(trustStore);
			char[] clientTrustStorePassphrase = trustStorePassPhrase.toCharArray();
			KeyStore clientTrust = KeyStore.getInstance("JKS");
			clientTrust.load(clientTrustStore, clientTrustStorePassphrase);
			
			TrustManagerFactory clientTMF = TrustManagerFactory.getInstance("SunX509");
			clientTMF.init(clientTrust);
			
			SSLContext sslContext = SSLContext.getInstance("TLS");
			sslContext.init(clientKMF.getKeyManagers(), clientTMF.getTrustManagers(), null);
			SSLSocketFactory sf = sslContext.getSocketFactory();
			
			Socket client = new Socket(serverName, port);
			
			InetSocketAddress clientSocketAddress = (InetSocketAddress) client.getRemoteSocketAddress();
    		SSLSocket clientSSL = (SSLSocket) (sf.createSocket(client, clientSocketAddress.getHostName(), client.getPort(),true));
    		clientSSL.setUseClientMode(true);
    		clientSSL.setEnabledCipherSuites(clientSSL.getSupportedCipherSuites());
    		clientSSL.setEnabledProtocols(clientSSL.getSupportedProtocols());
    		client = clientSSL;
    		
    		OutputStream outToServer = client.getOutputStream();
    		DataOutputStream out = new DataOutputStream(outToServer);
    		
    		//Connection has been established with the server, accept the input from the user
    		/*
    		 * Put a while true here
    		 * Then first write to the server as write utf, all the commands passed by the user
    		 * Only doubt part is the key generation for AES
    		 * In server also put a while true, this thread should stop when the 
    		 * user enters stop
    		 */
    		String userInput;
    		while(true)
    		{
    			userInput = acceptUserParameters();
    			if(userInput ==  null || userInput == "")
    			{
    				System.out.println("Please provide the input");
    				continue;
    			}
    			if(status.equals("stop"))
    			{
    				client.close();
    				break;
    			}
    			out.writeUTF(userInput);
    			performActionOnUserParameters(client);
    		}
	    }
		catch(Exception e)
		{
			System.out.println("An exception has ocurred : " + e.getMessage());
		}
	    
	}

}
