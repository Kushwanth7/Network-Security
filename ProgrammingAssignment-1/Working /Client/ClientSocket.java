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
		String password = args[0];
		String plaintextFilePath = args[1];
		String serverName = args[2];
	    int port = Integer.parseInt(args[3]);
	    String clientPrivateKeyName = args[4];
	    String clientPublicKeyName = args[5];
	    String serverPublicKeyName = args[6];
	    
	    /* Key Generation
	     * Check in the present directory whether there is a key with the specified 
	     * filename , if it is not there, then generate only the client private
	     * and the public key pair. 
	     * For the server check whether the public key file is there in the
	     * present path, if it is not there then print to the console stating that 
	     * the Server public key is not present and exit
	    */
	    
	    File serverPublicKeyFile = new File(serverPublicKeyName);
	    if(!serverPublicKeyFile.exists())
	    {
	    	System.out.println("The server public key file is not present in the current directory, Please place the server public key file in the current directory before starting the client to proceed with encryption process");
	    	return;
	    }
	    if(password.length() != 16)
	    {
	    	System.out.println("Please enter a password of length equal to 16");
	    	return;
	    }
	    
	    File clientPrivateKeyFile = new File(clientPrivateKeyName);
	    File clientPublicKeyFile = new File(clientPublicKeyName);
	    Key clientPublicKey;
	    Key clientPrivateKey = null;
	    Key serverPublicKey = null;
	    
	    /*
	    if(!clientPrivateKeyFile.exists() || !clientPublicKeyFile.exists())
	    {
	    	try 
	    	{
				KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
				kpg.initialize(2048);
				clientPrivateKeyFile.createNewFile();
				clientPublicKeyFile.createNewFile();
				KeyPair kp = kpg.generateKeyPair();
				clientPublicKey = kp.getPublic();
				clientPrivateKey = kp.getPrivate();
				
				// Write the public and the private keys generated above to the file
				
				ObjectOutputStream publicKeyOS = new ObjectOutputStream(new FileOutputStream(clientPublicKeyFile));
				publicKeyOS.writeObject(clientPublicKey);
				publicKeyOS.close();
				
				ObjectOutputStream privateKeyOS = new ObjectOutputStream(new FileOutputStream(clientPrivateKeyFile));
	            privateKeyOS.writeObject(clientPrivateKey);
	            privateKeyOS.close();
				
			} 
	    	catch (NoSuchAlgorithmException e) 
	    	{
				System.out.println("No such algorithm exception thrown");
				e.printStackTrace();
			} 
	    	catch (IOException e) 
	    	{
	    		System.out.println("An IO exception thrown");
				e.printStackTrace();
			}
	    	
	    }
	    
	    */
	    
    	ObjectInputStream inputStream = null;
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
		} 
    	catch (ClassNotFoundException e) 
    	{
    		System.out.println("An exception has occurred : " + e.getMessage());
		}
    	catch (Exception e)
    	{
    		System.out.println("An exception has occurred : " + e.getMessage());
    	}
	    
	    
	    /*
	     * Read from the file and encrypt the contents of the file using AES
	     * by using password as the key.
	     */
	    
	    //Read the contents of the file into a string
	    
	    BufferedReader br = null;
	    StringBuffer plaintextBuilder = new StringBuffer();
	    try
		{
	    	String currentLine;
			br = new BufferedReader(new FileReader(plaintextFilePath));
			while((currentLine = br.readLine())!=null)
			{
				plaintextBuilder.append(currentLine);
				if(!currentLine.equals("\n"))
				{
					plaintextBuilder.append("\n");
				}
			
			}
		}
		catch(IOException e)
		{
			System.out.println(e.getMessage());
		}
	    catch (Exception e)
    	{
    		System.out.println("An exception has occurred : " + e.getMessage());
    	}
	    
	    String plainText = plaintextBuilder.toString();
	    
	    if(plainText.length() == 0 || plaintextBuilder.length() == 0)
	    {
	    	System.out.println("It is an empty file, Nothing to encrypt returning");
	    	return;
	    }
	    //Encrypt the plaintext using AES in CBC mode
	    
	    String key = password;
	    String initVector = "RandomInitVector";
	    Cipher cipher;
	    byte[] encrypted = null;
	    try 
		{
			IvParameterSpec iv = new IvParameterSpec(initVector.getBytes("UTF-8"));
			SecretKeySpec skeySpec = new SecretKeySpec(key.getBytes("UTF-8"), "AES");
			cipher = Cipher.getInstance("AES/CBC/PKCS5PADDING");
            cipher.init(Cipher.ENCRYPT_MODE, skeySpec, iv);
            encrypted = cipher.doFinal(plainText.getBytes());
            
            File file = new File("encryptedfile");
			
			// if file doesnt exists, then create it
			if (!file.exists()) 
			{
				file.createNewFile();
			}
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
			MessageDigest digest = MessageDigest.getInstance("SHA-256");
			byte[] hashValue = digest.digest(plainText.getBytes());
			String hashHex = DatatypeConverter.printHexBinary(hashValue);
			
			
			//Encrypt the generated hash using client private key
			
			cipher = Cipher.getInstance("RSA");
			cipher.init(Cipher.ENCRYPT_MODE, clientPrivateKey);
			signature = cipher.doFinal(hashHex.getBytes());
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
	     */
	    
	    byte[] keyEncrypted = null;
	    try 
	    {
			cipher = Cipher.getInstance("RSA");
			cipher.init(Cipher.ENCRYPT_MODE, serverPublicKey);
			keyEncrypted = cipher.doFinal(key.getBytes());
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
	         DataOutputStream out = new DataOutputStream(outToServer);
	         
	         
	         for(int i=0;i<keyEncrypted.length;i++)
	         {
	        	 out.write(keyEncrypted[i]);
	         }
	         
	         //Send the signature of the file

	         
	         for(int i=0;i<signature.length;i++)
	         {
	        	 out.write(signature[i]);
	         }
	         
	         //Send the encrypted file
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
