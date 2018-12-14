import java.io.*;
import java.util.Scanner;
import java.net.Socket;
import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.security.PrivateKey;
import java.security.KeyFactory;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.GeneralSecurityException;
import java.util.Base64;

/** Client supporting simple interactionw with the server. */
public class Client {
  public static void main( String[] args ) {
    // Complain if we don't get the right number of arguments. 
    if ( args.length != 1 ) {
      System.out.println( "Usage: Client <host>" );
      System.exit( -1 );
    }

    try {
      // Try to create a socket connection to the server.
      Socket sock = new Socket( args[ 0 ], Server.PORT_NUMBER );

      // Get formatted input/output streams for talking with the server.
      DataInputStream input = new DataInputStream( sock.getInputStream() );
      DataOutputStream output = new DataOutputStream( sock.getOutputStream() );

      // Get a username from the user and send it to the server.
      Scanner scanner = new Scanner( System.in );
      System.out.print( "Username: " );
      String name = scanner.nextLine();
      output.writeUTF( name );
      output.flush();

      // Get the challenge string (really a byte array) from the server.
      byte[] challenge = Server.getMessage( input );

      // Try to read the user's private key.
      Scanner keyScanner = new Scanner( new File( name + ".txt" ) );
      String base64Key = keyScanner.nextLine();
      byte[] rawKey = Base64.getDecoder().decode( base64Key );
      keyScanner.close();
    
      // Make a key specification based on this key.
      PKCS8EncodedKeySpec privKeySpec = new PKCS8EncodedKeySpec( rawKey );
      
      // Get an RSA key based on this specification
      KeyFactory keyFactory = KeyFactory.getInstance( "RSA" );
      PrivateKey privateKey = keyFactory.generatePrivate( privKeySpec );

      // Make a cipher object that will encrypt using this key.
      Cipher RSAEncrypter = Cipher.getInstance( "RSA" );
      RSAEncrypter.init( Cipher.ENCRYPT_MODE, privateKey );

      // Make another cipher object that will decrypt using this key.
      Cipher RSADecrypter = Cipher.getInstance( "RSA" );
      RSADecrypter.init( Cipher.DECRYPT_MODE, privateKey );

      // Encrypt the challenge with our private key and send it back.
      // ...
      byte[] encryptedChallenge = RSAEncrypter.doFinal( challenge );
      Server.putMessage(output, encryptedChallenge);

      // Get the symmetric key from the server and make AES
      // encrypt/decrypt objects for it.
      // ...
      byte[] symmetricKey = RSADecrypter.doFinal( Server.getMessage(input));
      SecretKey key = new SecretKeySpec( symmetricKey, "AES" );
      // Make a cipher object that can encrypt with this key.
      Cipher encipher = Cipher.getInstance( "AES/ECB/PKCS5Padding" );
      encipher.init( Cipher.ENCRYPT_MODE, key );

      // Make a cipher object that can decrypt with this key.
      Cipher deccipher = Cipher.getInstance( "AES/ECB/PKCS5Padding" );
      deccipher.init( Cipher.DECRYPT_MODE, key );
      
      // Read commands from the user and print server responses.
      String request = "";
      System.out.print( "cmd> " );
      while ( scanner.hasNextLine() && ! ( request = scanner.nextLine() ).equals( "exit" ) ) {
        Server.putMessage( output, request.getBytes() );

        // Read and print the response.
        String response = new String( Server.getMessage( input ) );
        System.out.print( response );
        
        System.out.print( "cmd> " );
      }
      
      // Send the exit command to the server.
      Server.putMessage( output, request.getBytes() );
 
      // We are done communicating with the server.
      sock.close();
    } catch( IOException e ){
      System.err.println( "IO Error: " + e );
    } catch( GeneralSecurityException e ){
      System.err.println( "Encryption error: " + e );
    }
  }
}
