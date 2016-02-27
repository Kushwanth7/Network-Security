import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.io.UnsupportedEncodingException;
import java.io.FileNotFoundException;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.SocketTimeoutException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.ArrayList;

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
		String initVector = "RandomInitVector"; //This the common random init vector that is shared between the client and the server
		try 
		{
			cipher = Cipher.getInstance("RSA");
			cipher.init(Cipher.DECRYPT_MODE, serverPrivateKey);
			byte[] key = null;
			key = cipher.doFinal(receivedBytes[0]);
			String symmetricKey = new String(key);
			//System.out.println("The key decrypted by the server is = " + symmetricKey);
			
			//decrypt the contents of the file using the key decrypted above
			
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
			String plainText = new String(originalText);
			
			//write the plaintext to a file named decryptedfile
			File file = new File("decryptedfile");
			
			// if file doesnt exists, then create it
			if (!file.exists()) 
			{
				file.createNewFile();
			}
			
			FileWriter fw = new FileWriter(file.getAbsoluteFile());
			BufferedWriter bw = new BufferedWriter(fw);
			bw.write(plainText);
			bw.close();
			
			/*
			 * Check if the mode entered by the user is untrusted mode
			 * If it is untrusted mode then read from the fakefile stored in the
			 * same directory and produce the hash for the same
			 */
			String fakeCipherText;
			if(serverMode.equals("u"))
			{
				BufferedReader br = null;
			    StringBuffer plaintextBuilder = new StringBuffer();
			    
			    String currentLine;
				br = new BufferedReader(new FileReader("fakefile"));
				while((currentLine = br.readLine())!=null)
				{
					plaintextBuilder.append(currentLine);
					if(!currentLine.equals("\n"))
					{
						plaintextBuilder.append("\n");
					}
				}
				fakeCipherText = plaintextBuilder.toString();
				cipher = Cipher.getInstance("AES/CBC/PKCS5PADDING");
				iv = new IvParameterSpec(initVector.getBytes("UTF-8"));
				skeySpec = new SecretKeySpec(symmetricKey.getBytes("UTF-8"), "AES");
				cipher.init(Cipher.DECRYPT_MODE, skeySpec, iv);
				try
				{
					originalText = cipher.doFinal(fakeCipherText.getBytes());
					plainText = new String(originalText);
				}
				catch(Exception e)
				{
					System.out.println("An exception has ocurred : " + e.getMessage());
					System.out.println("Verification failed");
					return;
				}
			}

						
			//verify the signature
			
			//Decrypt the signature using the client public key
			cipher = Cipher.getInstance("RSA");
			cipher.init(Cipher.DECRYPT_MODE, clientPublicKey);
			byte[] signatureBytes = null;
			signatureBytes = cipher.doFinal(receivedBytes[1]);
			String hexSignatureDecrypted = new String(signatureBytes);
			
			//System.out.println("The hex signature decrypted by the server = " + hexSignatureDecrypted);
			
			//Generate the hash for the plaintext decrpted
			
			MessageDigest digest = MessageDigest.getInstance("SHA-256");
			byte[] hashValue = digest.digest(plainText.getBytes());
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
		 * receivedBytes[0] is encrypted key
		 * receivedBytes[1] is signature
		 * receivedBytes[2] is encrypted text
		 */
		
		int j = 0;
		int c =0;
	    while(true)
	    {
	    	try
	        {
	    		System.out.println("Waiting for client on port " + serverSocket.getLocalPort() + "...");
	            Socket server = serverSocket.accept();
	            System.out.println("Just connected to " + server.getRemoteSocketAddress());
	            DataInputStream in = new DataInputStream(server.getInputStream());
	            DataOutputStream out = new DataOutputStream(server.getOutputStream());
	            
	            //Read the bytes of the encrypted key into receivedbytes[0]
	            int count = 0;
            	if(in.available() == 0)
            		Thread.sleep(1000);
	            while(in.available() > 0 && count < 256)
	            {
	            	readByte = in.readByte();
	            	receivedBytes[0][count] = readByte;
	            	count ++;
	            	if(in.available() == 0)
	            		Thread.sleep(500);
	            }
	           
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
	            	if(in.available() == 0)
	            		Thread.sleep(500);
	            }
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
	            
	            //Get the encrypted file and store it in receivedBytes[2]
	            
	            count = 0;
	            while(in.available() > 0)
	            {
	            	readByte = in.readByte();
	            	receivedBytes[2][count] = readByte;
	            	count++;
	            	if(in.available() == 0)
	            		Thread.sleep(500);
	            }
	         
	            //Tell the client that all the bytes was received successfully and it is being processed
	            
	            out.writeUTF("All the bytes have been received: processing in progress, Goodbye");
	            decrypt(receivedBytes,count);
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
		int port = Integer.parseInt(args[0]);
		String mode = args[1]; //t is for trusted mode, u is for un trusted mode
		String serverPrivateKeyName = args[2];
		String serverPublicKeyName = args[3];
		String clientPublicKeyName = args[4];
		
		File serverPrivateKeyFile = new File(serverPrivateKeyName);
		File serverPublicKeyFile = new File(serverPublicKeyName);
		File clientPublicKeyFile = new File(clientPublicKeyName);
		if(!serverPrivateKeyFile.exists() || !serverPublicKeyFile.exists() || !clientPublicKeyFile.exists())
		{
			System.out.println("Some of the RSA components are missing, please place the files in the appropriate directory and start the server again");
			return;
		}
		
		/*
		if(!serverPrivateKeyFile.exists() || !serverPublicKeyFile.exists())
		{
			KeyPairGenerator kpg;
			try 
			{
				kpg = KeyPairGenerator.getInstance("RSA");
				kpg.initialize(2048);
				serverPrivateKeyFile.createNewFile();
				serverPublicKeyFile.createNewFile();
				KeyPair kp = kpg.generateKeyPair();
				serverPublicKey = kp.getPublic();
				serverPrivateKey = kp.getPrivate();
				
				// Write the public and the private keys generated above to the file
				
				ObjectOutputStream publicKeyOS = new ObjectOutputStream(new FileOutputStream(serverPublicKeyFile));
				publicKeyOS.writeObject(serverPublicKey);
				publicKeyOS.close();
				
				ObjectOutputStream privateKeyOS = new ObjectOutputStream(new FileOutputStream(serverPrivateKeyFile));
	            privateKeyOS.writeObject(serverPrivateKey);
	            privateKeyOS.close();
			} 
			catch (NoSuchAlgorithmException e) 
			{
				e.printStackTrace();
			} 
			catch (IOException e) 
			{	
				e.printStackTrace();
			}
			
		}
		*/
		
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
			e.printStackTrace();
		} 
    	catch (ClassNotFoundException e) 
    	{
			e.printStackTrace();
		}
		
		try
	    {
			Thread t = new Server(port);
	        t.start();
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
