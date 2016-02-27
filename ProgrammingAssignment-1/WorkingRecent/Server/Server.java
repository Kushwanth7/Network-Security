import java.io.BufferedWriter;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.FileWriter;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.io.UnsupportedEncodingException;
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

import jdk.internal.jfr.events.FileWriteEvent;

public class Server extends Thread 
{
	
	public static Key clientPublicKey;
	public static Key serverPrivateKey;
	public static Key serverPublicKey;
	
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
		 * Then decrypt the signature using vlient public key
		 * Generate the hash for the decrypted file 
		 * compare the hash with the decrypted signature
		 * if the hashes match then signature verification passed
		 * else it failed
		 */
		Cipher cipher;
		String initVector = "RandomInitVector";
		try 
		{
			cipher = Cipher.getInstance("RSA");
			cipher.init(Cipher.DECRYPT_MODE, serverPrivateKey);
			byte[] key = null;
			key = cipher.doFinal(receivedBytes[0]);
			String symmetricKey = new String(key);
			System.out.println("The key decrypted by the server is = " + symmetricKey);
			
			//decrypt the contents of the file
			
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
			System.out.println("Plaintext decrypted by the server = " + plainText);
			
			//write the plaintext to a file
			File file = new File("PlaintextDecrypted");
			
			// if file doesnt exists, then create it
			if (!file.exists()) 
			{
				file.createNewFile();
			}
			
			FileWriter fw = new FileWriter(file.getAbsoluteFile());
			BufferedWriter bw = new BufferedWriter(fw);
			bw.write(plainText);
			bw.close();
			
			//verify the signature
			cipher = Cipher.getInstance("RSA");
			cipher.init(Cipher.DECRYPT_MODE, clientPublicKey);
			byte[] signatureBytes = null;
			signatureBytes = cipher.doFinal(receivedBytes[1]);
			String hexSignatureDecrypted = new String(signatureBytes);
			
			System.out.println("The hex signature decrypted by the server = " + hexSignatureDecrypted);
			
			MessageDigest digest = MessageDigest.getInstance("SHA-256");
			byte[] hashValue = digest.digest(plainText.getBytes());
			String hashHex = DatatypeConverter.printHexBinary(hashValue);
			
			if(hashHex.equals(hexSignatureDecrypted))
			{
				System.out.println("Signature verification passed");
			}
			else
			{
				System.out.println("Signature verification failed");
			}
			
		} 
		catch (NoSuchAlgorithmException | NoSuchPaddingException e) 
		{
			e.printStackTrace();
		} 
		catch (InvalidKeyException e) 
		{
			e.printStackTrace();
		} 
		catch (IllegalBlockSizeException e) 
		{
			e.printStackTrace();
		} 
		catch (BadPaddingException e) 
		{
			e.printStackTrace();
		} 
		catch (InvalidAlgorithmParameterException e) 
		{
			e.printStackTrace();
		}
		catch(IOException e)
	    {
	    	e.printStackTrace();
	    }
		
	}
	
	public void run()
	   {
		byte[] delimeters = new byte[] {(byte)0xe0, (byte)0x4f, (byte)0xd0};
		
		byte readByte;
		byte[][] receivedBytes = new byte[3][];
		receivedBytes[0] = new byte[256];
		receivedBytes[1] = new byte[256];
		receivedBytes[2] = new byte[1024000];
		
		/*
		 * 0 is encrypted key
		 * 1 is signature
		 * 2 is encrypted text
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
	            int count = 0;
	            
	            
	            while(in.available() > 0 && count < 256)
	            {
	            	readByte = in.readByte();
	            	receivedBytes[0][count] = readByte;
	            	count ++;
	            }
	            
	            
	           
	            if(count == 256)
	            {
	            	System.out.println("Key received successfully");
	            	count =0;
	            }
	            else
	            {
	            	System.out.println("Key not received succeefully, closing the connection");
	            	out.writeUTF("Key not received succeefully, closing the connection");
	            	server.close();
	            	continue;
	            }
	            
	            
	            while(in.available() > 0 && count < 256)
	            {
	            	readByte = in.readByte();
	            	receivedBytes[1][count] = readByte;
	            	count ++;
	            }
	            if(count == 256)
	            {
	            	System.out.println("Signature received successfully");
	            	count = 0;
	            }
	            else
	            {
	            	System.out.println("Signature not received successfully, closing the connection");
	            	out.writeUTF("Signature not received successfully, closing the connection, expected signature length of size 64, but received " + count);
	            	server.close();
	            	continue;
	            }
	            
	            //Get the encrypted file
	            count = 0;
	            while(in.available() > 0)
	            {
	            	readByte = in.readByte();
	            	receivedBytes[2][count] = readByte;
	            	count++;
	            }
	         
	            //Tell the client that all the bytes was received successfully and it is being processed
	            out.writeUTF("All the bytes have been received, Goodbye");
	            decrypt(receivedBytes,count);
	         
	         }
	         catch(SocketTimeoutException s)
	         {
	            System.out.println("Socket timed out!");
	            break;
	         }
	         catch(IOException e)
	         {
	            e.printStackTrace();
	            break;
	         }
	      }
	   }


	public static void main(String[] args) 
	{
		int port = Integer.parseInt(args[0]);
		int mode = Integer.parseInt(args[1]); //0 is for trusted mode, 1 is for un trusted mode
		String serverPrivateKeyName = args[2];
		String serverPublicKeyName = args[3];
		String clientPublicKeyName = args[4];
		
		File serverPrivateKeyFile = new File(serverPrivateKeyName);
		File serverPublicKeyFile = new File(serverPublicKeyName);
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
		else
	    {
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
	    }
		
		try
	    {
			Thread t = new Server(port);
	        t.start();
	    }
		catch(IOException e)
	    {
			e.printStackTrace();
	    }
	}

}
