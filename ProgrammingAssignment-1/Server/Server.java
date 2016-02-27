import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.ObjectInputStream;
import java.io.UnsupportedEncodingException;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.SocketTimeoutException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import javax.xml.bind.DatatypeConverter;

public class Server extends Thread 
{
	
	public static Key clientPublicKey;
	public static Key serverPrivateKey;
	public static Key serverPublicKey;
	public static String serverMode;
	
	private ServerSocket serverSocket;
	
	public Server(int port) throws IOException
	{
		/*
		 * Create a new server socket and set the timeout of the socket to 10000000
		 */
		serverSocket = new ServerSocket(port);
	    serverSocket.setSoTimeout(10000000);
	}
	
	public void decrypt(byte receivedBytes[][], int encryptedByteCount) throws UnsupportedEncodingException
	{
		/*
		 * Initially decrypt the key using the server private key 
		 * Then decrypt the file using the secret key decrypted before
		 * Then decrypt the signature using client public key
		 * Generate the hash for the decrypted file 
		 * compare the hash with the decrypted signature
		 * if the hashes match then signature verification passed
		 * else it failed
		 */
		
		Cipher cipher;
		String initVector = "RandomInitVector"; //This is the common random initialization vector that is shared between the client and the server
		try 
		{
			/*
			 * Decrypt the symmetric key using the server private key
			 */
			cipher = Cipher.getInstance("RSA");
			cipher.init(Cipher.DECRYPT_MODE, serverPrivateKey);
			byte[] key = null;
			key = cipher.doFinal(receivedBytes[0]);
			String symmetricKey = new String(key);
			
			/*
			 * Decrypt the contents of the file using AES algorithm in CBC mode
			 * by using the symmetric key decrypted above
			 */
			
			//copy the encrypted bytes received into the byte array encryptedBytes
			
			byte[] encryptedBytes = new byte[encryptedByteCount];
			for(int i=0;i<encryptedByteCount;i++)
			{
				encryptedBytes[i] = receivedBytes[2][i]; 
			}
			
			cipher = Cipher.getInstance("AES/CBC/PKCS5PADDING");
			IvParameterSpec iv = new IvParameterSpec(initVector.getBytes("UTF-8"));
			SecretKeySpec skeySpec = new SecretKeySpec(symmetricKey.getBytes("UTF-8"), "AES");
			cipher.init(Cipher.DECRYPT_MODE, skeySpec, iv);
			byte[] originalText = cipher.doFinal(encryptedBytes);
			
			//write the plaintext that was decrypted to a file named decryptedfile
			
			DataOutputStream dataOut = new DataOutputStream(new FileOutputStream("decryptedfile"));
            dataOut.write(originalText);
			
			/*
			 * Check if the mode entered by the user is untrusted mode
			 * If it is untrusted mode then read from the fakefile stored in the
			 * same directory, decrypt it using the symmetric key decrypted before.
			 */
			
            //u means the server is running in untrusted mode
            
			if(serverMode.equals("u"))
			{
		    	InputStream is = null;
		        DataInputStream dis = null;
		        byte[] fakeText = null;
		        //put the decrypted contents into the same byte array originalText
				try
		        {
		        	is = new FileInputStream("fakefile");
		        	dis = new DataInputStream(is);
		        	fakeText = new byte[dis.available()];
		        	dis.readFully(fakeText);
		        	cipher = Cipher.getInstance("AES/CBC/PKCS5PADDING");
					iv = new IvParameterSpec(initVector.getBytes("UTF-8"));
					skeySpec = new SecretKeySpec(symmetricKey.getBytes("UTF-8"), "AES");
					cipher.init(Cipher.DECRYPT_MODE, skeySpec, iv);
					originalText = cipher.doFinal(fakeText);
		        }
				catch(Exception e)
				{
					System.out.println("An exception has ocurred : " + e.getMessage());
					System.out.println("Verification failed");
					return;
				}
			}
						
			/*
			 *The originalText byte array now contains the plaintext bytes that were decrypted,
			 *if the server was running in untrusted mode then the originaltext byte array contains 
			 *the bytes decrypted from the fakefile.
			 *If the server was running in trusted mode then  originaltext byte array contains 
			 *the bytes decrypted from the encrypted bytes received from the client.
			 */
			
			//Decrypt the signature using the client public key
			
			cipher = Cipher.getInstance("RSA");
			cipher.init(Cipher.DECRYPT_MODE, clientPublicKey);
			byte[] signatureBytes = null;
			signatureBytes = cipher.doFinal(receivedBytes[1]);
			String hexSignatureDecrypted = new String(signatureBytes);
			
			
			//Generate the hash for the plaintext decrypted
			
			MessageDigest digest = MessageDigest.getInstance("SHA-256");
			byte[] hashValue = digest.digest(originalText);
			String hashHex = DatatypeConverter.printHexBinary(hashValue);

			//compare the hash decrypted with the hash generated
			
			if(hashHex.equals(hexSignatureDecrypted))
			{
				System.out.println("Verification Passed");
			}
			else
			{
				System.out.println("Verification failed");
			}
			
		} 
		catch (NoSuchAlgorithmException e) 
		{
			System.out.println("An exception has ocurred : " + e.getMessage());
		} 
		catch (NoSuchPaddingException e)
		{
			System.out.println("An exception has ocurred : " + e.getMessage());
		}
		catch (InvalidKeyException e) 
		{
			System.out.println("An exception has ocurred : " + e.getMessage());
		} 
		catch (IllegalBlockSizeException e) 
		{
			System.out.println("An exception has ocurred : " + e.getMessage());
		} 
		catch (BadPaddingException e) 
		{
			System.out.println("An exception has ocurred : " + e.getMessage());
		} 
		catch (InvalidAlgorithmParameterException e) 
		{
			System.out.println("An exception has ocurred : " + e.getMessage());
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
	
	public void run()
	{
		byte readByte;
		byte[][] receivedBytes = new byte[3][];
    	receivedBytes[0] = new byte[256];
		receivedBytes[1] = new byte[256];
		receivedBytes[2] = new byte[1024000];
		/*
		 * receivedBytes[0] stores the encrypted key
		 * receivedBytes[1] stores the signature
		 * receivedBytes[2] stores the encrypted text
		 */
	    while(true)
	    {
	    	try
	        {
	    		System.out.println("Waiting for client on port " + serverSocket.getLocalPort() + "...");
	            Socket server = serverSocket.accept();
	            System.out.println("Just connected to " + server.getRemoteSocketAddress());
	            DataInputStream in = new DataInputStream(server.getInputStream());
	            DataOutputStream out = new DataOutputStream(server.getOutputStream());
	            
	            /*
	             * To prevent the server from reading the bytes from the socket faster than the client writing
	             * to the socket, sleep the server for one second 
	             * after the socket connection has been established with the client
	             */
	            
            	if(in.available() == 0)
            		Thread.sleep(1000);
	            
            	//Read the bytes of the encrypted key into receivedbytes[0]
	            
            	int count = 0;
	            while(in.available() > 0 && count < 256)
	            {
	            	readByte = in.readByte();
	            	receivedBytes[0][count] = readByte;
	            	count ++;
	            	/*
	            	 * Sometimes the speed at which the server reads from the socket is
	            	 * faster than the client writing to the socket, so to sync the client and 
	            	 * and the server, sleep the server for 0.5 seconds when ever the number of available bytes 
	            	 * in the socket is zero.
	            	 */
	            	if(in.available() == 0)
	            		Thread.sleep(500);
	            }
	           
	            /*If the count was 256 then the key was read successfully into the 
	             * received bytes array else the reading was incomplete so print the appropriate message
	             * to the client and close the socket connection
	             */
	            if(count == 256)
	            {
	            	System.out.println("Key received successfully");
	            	count =0;
	            }
	            else
	            {
	            	System.out.println("Key not received successfully, closing the connection");
	            	out.writeUTF("Key not received successfully, closing the connection");
	            	server.close();
	            	continue;
	            }
	            
	            //Read the signature into receivedBytes[1]
	            while(in.available() > 0 && count < 256)
	            {
	            	readByte = in.readByte();
	            	receivedBytes[1][count] = readByte;
	            	count ++;
	            	/*
	            	 * Sometimes the speed at which the server reads from the socket is
	            	 * faster than the client writing to the socket, so to sync the client and 
	            	 * and the server, sleep the server for 0.5 seconds when ever the number of available bytes 
	            	 * in the socket is zero.
	            	 */
	            	if(in.available() == 0)
	            		Thread.sleep(500);
	            }
	            

	            /*If the count was 256 then the signature was read successfully into the 
	             * received bytes array else the reading was incomplete so print the appropriate message
	             * to the client and close the socket connection
	             */
	            
	            if(count == 256)
	            {
	            	System.out.println("Signature received successfully");
	            	count = 0;
	            }
	            else
	            {
	            	System.out.println("Signature not received successfully, closing the connection");
	            	out.writeUTF("Signature not received successfully, closing the connection, expected signature length of size 256, but received " + count);
	            	server.close();
	            	continue;
	            }
	            
	            //Read the encrypted file and store it in receivedBytes[2]
	            
	            count = 0;
	            while(in.available() > 0)
	            {
	            	readByte = in.readByte();
	            	receivedBytes[2][count] = readByte;
	            	count++;
	            	/*
	            	 * Sometimes the speed at which the server reads from the socket is
	            	 * faster than the client writing to the socket, so to sync the client and 
	            	 * and the server, sleep the server for 0.5 seconds when ever the number of available bytes 
	            	 * in the socket is zero.
	            	 */
	            	if(in.available() == 0)
	            		Thread.sleep(500);
	            }
	         
	            //Tell the client that all the bytes was received successfully and it is being processed
	            
	            out.writeUTF("All the bytes have been received: processing in progress, Goodbye");
	            decrypt(receivedBytes,count);
	            server.close(); //close the socket connection
	         }
	         catch(SocketTimeoutException s)
	         {
	            System.out.println("Socket timed out!");
	            break;
	         }
	         catch(IOException e)
	         {
	        	 System.out.println("An exception has ocurred : " + e.getMessage());
	            break;
	         }
	    	catch(Exception e)
	    	{
	    		System.out.println("An exception has ocurred : " + e.getMessage());
	    	}
	      }
	   }


	public static void main(String[] args) 
	{
		if(args.length < 5)
		{
			System.out.println("Number of parameters entered is less, expected number of parameters=5, received = " + args.length);
			return;
		}
		int port=6066; //default listening port for the server is 6066
		try
		{
			port = Integer.parseInt(args[0]);
		}
		catch(Exception e)
		{
			System.out.println("An exception has ocurred : " + e.getMessage() + " The server will start on port 6066");
		}
		String mode = args[1]; //t is for trusted mode, u is for un trusted mode
		String serverPrivateKeyName = args[2]; //Name of the server private key file
		String serverPublicKeyName = args[3]; //Name of the server public key file
		String clientPublicKeyName = args[4]; //Name of the client public key file
		
		File serverPrivateKeyFile = new File(serverPrivateKeyName);
		File serverPublicKeyFile = new File(serverPublicKeyName);
		File clientPublicKeyFile = new File(clientPublicKeyName);
		if(!serverPrivateKeyFile.exists())
		{
			System.out.println("The server private key file is not present in the current directory, Please place the server private key file in the current directory before starting the server to proceed with verification and decryption process");
			return;
		}
		if(!serverPublicKeyFile.exists())
		{
			System.out.println("The server public key file is not present in the current directory, Please place the server public key file in the current directory before starting the server to proceed with verification and decryption process");
			return;
		}
		if(!clientPublicKeyFile.exists())
		{
			System.out.println("The client public key file is not present in the current directory, Please place the client public key file in the current directory before starting the server to proceed with verification and decryption process");
			return;
		}
		if(!mode.equals("t"))
		{
			if(!mode.equals("u"))
			{
				System.out.println("Please enter t or u for mode, t is for running the server in trusted mode and u is for running the server in untrusted mode ");
				return;
			}
		}
		if(port > 65535 || port <= 0)
		{
			System.out.println("Enter a valid port number in the range 1 to 65536");
			return;
		}
		
		serverMode = mode;
    	ObjectInputStream inputStream = null;
    	
    	try 
    	{
			inputStream = new ObjectInputStream(new FileInputStream(serverPublicKeyName));
	    	serverPublicKey = (PublicKey) inputStream.readObject();
	    	inputStream = new ObjectInputStream(new FileInputStream(clientPublicKeyName));
	    	clientPublicKey = (PublicKey) inputStream.readObject();
	    	inputStream = new ObjectInputStream(new FileInputStream(serverPrivateKeyName));
	    	serverPrivateKey = (PrivateKey) inputStream.readObject();
		}
    	
    	catch (IOException e) 
    	{
			System.out.println("An exception has occurred: " + e.getMessage());
		} 
    	catch (ClassNotFoundException e) 
    	{
    		System.out.println("An exception has occurred: " + e.getMessage());
		}
		
		try
	    {
			Thread t = new Server(port);
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
