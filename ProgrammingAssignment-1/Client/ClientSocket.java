import java.io.BufferedReader;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.FileReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.io.OutputStream;
import java.net.Socket;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.io.BufferedWriter;
import java.io.FileWriter;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import javax.xml.bind.DatatypeConverter;

public class ClientSocket
{	
	public static void main(String[] args) 
	{
		if(args.length < 7)
		{
			System.out.println("Number of parameters entered is less, expected number of parameters=7, received = " + args.length);
			return;
		}
		String password = args[0]; //16 character password is the first parameter
		String plaintextFilePath = args[1]; //The path of the file to be encrypted is the second parameter
		String serverName = args[2]; //Name of the server the client connects to is the third parameter
	    int port = 6066; // default port connection  is 6066
	    String clientPrivateKeyName = args[4]; //The name of the client private key, the client private key should be in the same directory as the ClientSocket.java file
	    String clientPublicKeyName = args[5]; //The name of the client public key, the client public key  should be in the same directory as the ClientSocket.java file
	    String serverPublicKeyName = args[6]; //The name of the server public key, the server public key  should be in the same directory as the ClientSocket.java file
	    try
	    {
	    	port = Integer.parseInt(args[3]); //The port number on which the server is listening is the third parameter
	    }
	    catch (Exception e)
	    {
	    	System.out.println("An exception has ocurred : " + e.getMessage() + "The client will attempt to connect the specified server on port 6066");
	    }
	    
	    /* 
	     * Check for  existence of the RSA keys
	    */
	    
	    File serverPublicKeyFile = new File(serverPublicKeyName);
	    File clientPrivateKeyFile = new File(clientPrivateKeyName);
	    File clientPublicKeyFile = new File(clientPublicKeyName);
	    if(!serverPublicKeyFile.exists())
	    {
	    	System.out.println("The server public key file is not present in the current directory, Please place the server public key file in the current directory before starting the client to proceed with encryption process");
	    	return;
	    }
	    if(!clientPrivateKeyFile.exists())
	    {
	    	System.out.println("The client private key file is not present in the current directory, Please place the client private key file in the current directory before starting the client to proceed with encryption process");
	    	return;
	    }
	    if(!clientPublicKeyFile.exists())
	    {
	    	System.out.println("The client public key file is not present in the current directory, Please place the client public key file in the current directory before starting the client to proceed with encryption process");
	    	return;
	    }
	    if(password.length() != 16)
	    {
	    	System.out.println("Please enter a password of length equal to 16");
	    	return;
	    }
	    
	    
	    Key clientPublicKey;
	    Key clientPrivateKey = null;
	    Key serverPublicKey = null;
	    
    	ObjectInputStream inputStream = null;
    	
    	/*
    	 * Read the relevant keys from the file names entered by the user
    	 */
    	
    	try 
    	{
			inputStream = new ObjectInputStream(new FileInputStream(serverPublicKeyName));
	    	serverPublicKey = (PublicKey) inputStream.readObject();
	    	inputStream = new ObjectInputStream(new FileInputStream(clientPublicKeyName));
	    	clientPublicKey = (PublicKey) inputStream.readObject();
	    	inputStream = new ObjectInputStream(new FileInputStream(clientPrivateKeyName));
	    	clientPrivateKey = (PrivateKey) inputStream.readObject();
		} 
    	catch (IOException e) 
    	{
    		System.out.println("An exception has occurred : " + e.getMessage());
    		return;
		} 
    	catch (ClassNotFoundException e) 
    	{
    		System.out.println("An exception has occurred : " + e.getMessage());
    		return;
		}
    	catch (Exception e)
    	{
    		System.out.println("An exception has occurred : " + e.getMessage());
    		return;
    	}
	    
	    
	    /*
	     * Read from the plaintext file entered by the user and encrypt the contents of the file using AES in CBC mode
	     * by using password as the key.
	     */
	    
	    
    	InputStream is = null;
        DataInputStream dis = null;
        byte[] plainText = null; // the contents of the file are read into the byte array plaintext 
        
        try
        {
        	is = new FileInputStream(plaintextFilePath);
        	dis = new DataInputStream(is);
        	plainText = new byte[dis.available()];
        	dis.readFully(plainText);
        }
		catch (Exception e)
		{
			System.out.println("An exception has occurred : " + e.getMessage());
			return;
		}
	    
        if(plainText.length == 0)
        {
        	System.out.println("It is an empty file, empty file will not be encrypted, closing the socket");
        	return;
        }
        
	    //Encrypt the plaintext bytes using AES in CBC mode
	    
	    String key = password;
	    String initVector = "RandomInitVector"; //The initilaization Vector used is RandomInitVector, it is of 16 bytes in length and both client and the server have agreed upon the same
	    Cipher cipher;
	    byte[] encrypted = null; // the plaint text bytes encrypted are stored in the byte array encrypted
	    try 
		{
			IvParameterSpec iv = new IvParameterSpec(initVector.getBytes("UTF-8"));
			SecretKeySpec skeySpec = new SecretKeySpec(key.getBytes("UTF-8"), "AES");
			cipher = Cipher.getInstance("AES/CBC/PKCS5PADDING"); //Encrypting using AES in CBC mode, also Padding is done if the plaintext is bytes is not an integral number of 16
            cipher.init(Cipher.ENCRYPT_MODE, skeySpec, iv);
            encrypted = cipher.doFinal(plainText); // encrypt the plaintext bytes and store it in the byte array encrypted

            /*
             * Write the encrypted file into the file encrypted
             * 
             */
            
            DataOutputStream dataOut = new DataOutputStream(new FileOutputStream("encryptedFile"));
            dataOut.write(encrypted);
		}
	    catch (NoSuchAlgorithmException e) 
	    {
	    	System.out.println("An exception has occurred : " + e.getMessage());
		}
	    catch(NoSuchPaddingException e)
	    {
	    	System.out.println("An exception has occurred : " + e.getMessage());
	    }
		catch(Exception e)
		{
			System.out.println("An exception has occurred : " + e.getMessage());
		}
	    
	    /*Producing the digital signature
	     * Generate the hash for the plaintext
	     * sign the hash using the client private key
	    */
	    
	    byte[] signature = null;
	    try 
	    {
			MessageDigest digest = MessageDigest.getInstance("SHA-256"); //Using SHA-256 for generating the hash
			byte[] hashValue = digest.digest(plainText);
			String hashHex = DatatypeConverter.printHexBinary(hashValue); //Converting the hash value bytes to HEX
			
			
			//Encrypt the generated hash using client private key
			
			cipher = Cipher.getInstance("RSA");
			cipher.init(Cipher.ENCRYPT_MODE, clientPrivateKey); //Encrypting the hex hash using the client private key, this produces the digital signature
			signature = cipher.doFinal(hashHex.getBytes()); //The signature generated is stored in the byte array signature
		} 
	    catch (NoSuchAlgorithmException e) 
	    {
	    	System.out.println("An exception has occurred : " + e.getMessage());
		} 
	    catch (NoSuchPaddingException e) 
	    {
	    	System.out.println("An exception has occurred : " + e.getMessage());
		} 
	    catch (InvalidKeyException e) 
	    {
	    	System.out.println("An exception has occurred : " + e.getMessage());
		} 
	    catch (IllegalBlockSizeException e) 
	    {
	    	System.out.println("An exception has occurred : " + e.getMessage());
		}
	    catch (BadPaddingException e) 
	    {
	    	System.out.println("An exception has occurred : " + e.getMessage());
		}
	    catch (Exception e)
	    {
	    	System.out.println("An exception has occurred : " + e.getMessage());
	    }
	    
	    /*
	     * Encrypt the password  using the server public key
	     * The password entered by the user is encrypted using the server public key
	     * so that only the server can decrypt password and use that as the key for 
	     * decrypting using AES
	     */
	    
	    byte[] keyEncrypted = null;
	    try 
	    {
			cipher = Cipher.getInstance("RSA");
			cipher.init(Cipher.ENCRYPT_MODE, serverPublicKey);
			keyEncrypted = cipher.doFinal(key.getBytes()); //Decrypting the password(key) using the server public key
		} 
	    catch (NoSuchPaddingException e) 
	    {
	    	System.out.println("An exception has occurred : " + e.getMessage());
		} 
	    catch (NoSuchAlgorithmException e)
	    {
	    	System.out.println("An exception has occurred : " + e.getMessage());
	    }
	    catch (InvalidKeyException e) 
	    {
	    	System.out.println("An exception has occurred : " + e.getMessage());
		} 
	    catch (IllegalBlockSizeException e) 
	    {
	    	System.out.println("An exception has occurred : " + e.getMessage());
		}
	    catch (BadPaddingException e) 
	    {
	    	System.out.println("An exception has occurred : " + e.getMessage());
		}
	    catch (Exception e)
	    {
	    	System.out.println("An exception has occurred : " + e.getMessage());
	    }
	    
	    /*
	     * Socket connections to the server
	     * First send the key
	     * Then send the signature of the file
	     * Then send the encrypted file
	     */
	    
	    try
	      {
	         System.out.println("Connecting to " + serverName + " on port " + port);
	         Socket client = new Socket(serverName, port);
	         System.out.println("Just connected to " + client.getRemoteSocketAddress());
	         OutputStream outToServer = client.getOutputStream();
	         DataOutputStream out = new DataOutputStream(outToServer);//Using the output stream out to write to the socket 
	         

	         /*
	          * Write to the socket byte by byte
	          */
	         
	         /*
	          * Sending the key encrypted using server public key byte by byte
	          */
	         
	         for(int i=0;i<keyEncrypted.length;i++)
	         {
	        	 out.write(keyEncrypted[i]);
	         }
	         
	         /*
	          * Sending the signature of the file
	          * byte by byte
	          */

	         
	         for(int i=0;i<signature.length;i++)
	         {
	        	 out.write(signature[i]);
	         }
	         
	         /*
	          * Sending the encrypted file byte by byte
	          */
	         
	         for(int i=0;i<encrypted.length;i++)
	         {
	        	 out.write(encrypted[i]);
	         }
	         
	         
	         InputStream inFromServer = client.getInputStream();
	         DataInputStream in = new DataInputStream(inFromServer);
	         System.out.println("Server: " + in.readUTF());
	         client.close();
	      }
	    catch(IOException e)
	    {
	    	System.out.println("An exception has ocurred : " + e.getMessage());
	    }
	    catch (Exception e)
	    {
	    	System.out.println("An exception has occurred : " + e.getMessage());
	    }
	}

}
