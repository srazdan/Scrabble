import java.io.*;
import java.net.ServerSocket;
import java.net.Socket;
import java.util.Scanner;
import java.util.Random;
import java.util.ArrayList;
import java.util.Arrays;
import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.security.PublicKey;
import java.security.KeyFactory;
import java.security.spec.X509EncodedKeySpec;
import java.security.GeneralSecurityException;
import java.util.Base64;

/** A server that keeps up with a public key for every user, along
    with a board for placing letters, like scrabble. */
public class Server {
  /** Port number used by the server */
  public static final int PORT_NUMBER = 26146;

  /** Original state of the board, for resetting at the start of a game. */
  private char[][] template;

  /** Current board, a 2D array of characters. */
  private char[][] board;
  
  /** Scores array for each letter. */
  private int[] scores = new int[]{1, 3, 3, 2, 1, 4, 2, 4, 1, 8, 5, 1, 3, 1, 1, 3, 10, 1, 1, 1, 1, 4, 4, 8, 4, 10};

  /** Record for an individual user. */
  private static class UserRec {
    // Name of this user.
    String name;

    // This user's public key.
    PublicKey publicKey;

    // Current score for this users.
    int score;
  }

  /** List of all the user records. */
  private ArrayList< UserRec > userList = new ArrayList< UserRec >();

  /** Set the game board back to its initial state. */
  private void reset() {
    for ( int i = 0; i < board.length; i++ ) {
      for ( int j = 0; j < board[ i ].length; j++ ) {
        board[ i ][ j ] = template[ i ][ j ]; 
      }
    }

    for ( int i = 0; i < userList.size(); i++ ) {
      userList.get( i ).score = 0;
    }
  }

  /** Read the initial board and all the users, done at program start-up. */
  private void readConfig() throws Exception {
    // First, read in the map.
    Scanner input = new Scanner( new File( "board.txt" ) );

    // Read in the initial state of the board.
    int height = input.nextInt();
    int width = input.nextInt();
    input.nextLine(); // Eat the rest of the first line.

    // Make the board state.
    template = new char [ height ][];
    for ( int i = 0; i < height; i++ )
      template[ i ] = input.nextLine().toCharArray();
    board = new char [ height ][ width ];

    // Read in all the users.
    input = new Scanner( new File( "passwd.txt" ) );
    while ( input.hasNext() ) {
      // Create a record for the next user.
      UserRec rec = new UserRec();
      rec.name = input.next();

      // Get the key as a string of hex digits and turn it into a byte array.
      String base64Key = input.nextLine().trim();
      byte[] rawKey = Base64.getDecoder().decode( base64Key );
    
      // Make a key specification based on this key.
      X509EncodedKeySpec pubKeySpec = new X509EncodedKeySpec( rawKey );

      // Make an RSA key based on this specification
      KeyFactory keyFactory = KeyFactory.getInstance( "RSA" );
      rec.publicKey = keyFactory.generatePublic( pubKeySpec );

      // Add this user to the list of all users.
      userList.add( rec );
    }
 
    // Reset the state of the game.
    reset();
  }

  /** Utility function to read a length then a byte array from the
      given stream.  TCP doesn't respect message boundaraies, but this
      is essientially a technique for marking the start and end of
      each message in the byte stream.  This can also be used by the
      client. */
  public static byte[] getMessage( DataInputStream input ) throws IOException {
    int len = input.readInt();
    byte[] msg = new byte [ len ];
    input.readFully( msg );
    return msg;
  }

  /** Function analogous to the previous one, for sending messages. */
  public static void putMessage( DataOutputStream output, byte[] msg ) throws IOException {
    // Write the length of the given message, followed by its contents.
    output.writeInt( msg.length );
    output.write( msg, 0, msg.length );
    output.flush();
  }

  /** Function to handle interaction with a client.  For a multi-threaded
      server, this should be done in a separate thread. */
  public void handleClient( Socket sock ) {
    try {
      // Get formatted input/output streams for this thread.  These can read and write
      // strings, arrays of bytes, ints, lots of things.
      DataOutputStream output = new DataOutputStream( sock.getOutputStream() );
      DataInputStream input = new DataInputStream( sock.getInputStream() );
      
      // Get the username.
      String username = input.readUTF();

      // Make a random sequence of bytes to use as a challenge string.
      Random rand = new Random();
      byte[] challenge = new byte [ 16 ];
      rand.nextBytes( challenge );

      // Make a session key for communiating over AES.  We use it later, if the
      // client successfully authenticates.
      byte[] sessionKey = new byte [ 16 ];
      rand.nextBytes( sessionKey );

      // Find this user.  We don't need to synchronize here, since the set of users never
      // changes.
      UserRec rec = null;
      for ( int i = 0; rec == null && i < userList.size(); i++ )
        if ( userList.get( i ).name.equals( username ) )
          rec = userList.get( i );

      // Did we find a record for this user?
      if ( rec != null ) {
        // Make sure the client encrypted the challenge properly.
        Cipher RSADecrypter = Cipher.getInstance( "RSA" );
        RSADecrypter.init( Cipher.DECRYPT_MODE, rec.publicKey );
          
        Cipher RSAEncrypter = Cipher.getInstance( "RSA" );
        RSAEncrypter.init( Cipher.ENCRYPT_MODE, rec.publicKey );
          
        // Send the client the challenge.
        putMessage( output, challenge );
          
        // Get back the client's encrypted challenge.
        // ...
        byte[] ch = RSADecrypter.doFinal( getMessage(input));

        // Make sure the client properly encrypted the challenge.
        // ...
        if(!(java.util.Arrays.equals(challenge, ch))) {
        	throw new GeneralSecurityException();
        }

        // Send the client the session key (encrypted with the client's public
        // key).
        // ...
        byte[] encryptedSessionKey = RSAEncrypter.doFinal( sessionKey );
        putMessage(output, encryptedSessionKey);

        // Make AES cipher objects to encrypt and decrypt with
        // the session key.
        // ...
        SecretKey key = new SecretKeySpec( sessionKey, "AES" );
        // Make a cipher object that can encrypt with this key.
        Cipher encipher = Cipher.getInstance( "AES/ECB/PKCS5Padding" );
        encipher.init( Cipher.ENCRYPT_MODE, key );

        // Make a cipher object that can decrypt with this key.
        Cipher deccipher = Cipher.getInstance( "AES/ECB/PKCS5Padding" );
        deccipher.init( Cipher.DECRYPT_MODE, key );

        // Get the first client command
        String request = new String( getMessage( input ) );

        // Until the client asks us to exit.
        while ( ! request.equals( "exit" ) ) {
          StringBuilder reply = new StringBuilder();
          for ( int i = 0; i < board.length; i++ ) {
            for ( int j = 0; j < board[ i ].length; j++ ) {
              if(board[i][j] == 'o') {
                board[i][j] = '?';//change all o's in the board to ?
              }
            }
          }
          if(request.equals("board")) {
            //if request is to board, print the board
            for ( int i = 0; i < board.length; i++ ) {
              for ( int j = 0; j < board[ i ].length; j++ ) {
                if(board[i][j] == '?') {
                  reply.append('o');//if character is ?, print o instead of ?
                } else {
                  reply.append(board[i][j]);//print other characters
                }
              }
              reply.append("\n");//new line 
            }
            for ( int i = 0; i < userList.size(); i++ ) {
              reply.append(userList.get(i).name + " : " + userList.get(i).score + "\n");//get all players and their scores 
            }
          } else if(request.contains("place")) {
            //if request is to place, place the letter if it is valid 
            String a[] = request.split(" ");//split string to parts 
            int r = Integer.parseInt(a[2]);
            int c = Integer.parseInt(a[3]);
        	if(r < 0 || r > board.length - 1 || c < 0 || c > board[r].length - 1) {
              reply.append("Invalid Command.\n");//if index not in board
        	} else if(board[r][c] == '#') {
        	  reply.append("Invalid Command.\n");//if character is #
        	} else if(board[r][c] >= 'a' && board[r][c] < 'z') {
        	  reply.append("Invalid Command.\n");//if there arlready is a letter in the index
        	} else if(!Character.isLowerCase(a[1].charAt(0))) {
              reply.append("Invalid Command.\n");//if letter is not lower case
        	} else {
              if( board[r][c] == '?' ) {
        	    board[r][c] = a[1].charAt(0);//place letter in index 
        	    reply.append(scores[(int)a[1].charAt(0) - 97] + " points" + "\n");//print number of points earned by player
                rec.score += scores[(int)a[1].charAt(0) - 97];//add points to player's score
              } else if( board[r][c] == '.' ) {
                boolean valid = false;
                if(r-1 >= 0) { 
                  if(Character.isLetter(board[r-1][c])) {
                    valid = true;//check if adjacent index exists and there is a letter
                  }
                }
                if(r+1 < board.length) { 
                  if(Character.isLetter(board[r+1][c])) {
                    valid = true;//check if adjacent index exists and there is a letter
                  }
                }
                if(c-1 >= 0) { 
                  if(Character.isLetter(board[r][c-1])) {
                    valid = true;//check if adjacent index exists and there is a letter
                  }
                }
                if(c+1 < board[r].length) { 
                  if(Character.isLetter(board[r][c+1])) {
                    valid = true;//check if adjacent index exists and there is a letter
                  }
                }
                if(valid == true) { 
                  board[r][c] = a[1].charAt(0);//place letter in index 
                  reply.append(scores[(int)a[1].charAt(0) - 97] + " points" + "\n");//print number of points earned by player
                  rec.score += scores[(int)a[1].charAt(0) - 97];//add points to player's score
                } else {
                  reply.append("Invalid Command.\n");//invalid command if not able to place letter in the index
                }
          	  } else if( board[r][c] == ':' ) {
                boolean valid = false;
                if(r-1 >= 0) { 
                  if(Character.isLetter(board[r-1][c])) {
                    valid = true;//check if adjacent index exists and there is a letter
                  }
                }
                if(r+1 < board.length) { 
                  if(Character.isLetter(board[r+1][c])) {
                    valid = true;//check if adjacent index exists and there is a letter
                  }
                }
                if(c-1 >= 0) { 
                  if(Character.isLetter(board[r][c-1])) {
                    valid = true;//check if adjacent index exists and there is a letter
                  }
                }
                if(c+1 < board[r].length) { 
                  if(Character.isLetter(board[r][c+1])) {
                    valid = true;//check if adjacent index exists and there is a letter
                  }
                }
                if(valid == true) { 
                  board[r][c] = a[1].charAt(0);//place letter in index 
                  reply.append((scores[(int)a[1].charAt(0) - 97] * 2) + " points" + "\n");//print number of points earned by player
                  rec.score += (scores[(int)a[1].charAt(0) - 97] * 2);//add points to player's score
                } else {
                  reply.append("Invalid Command.\n");//invalid command if not able to place letter in the index
                }
              } else {
        	    reply.append("Invalid Command.\n");//invalid comand if client puts some other command request
              }
            }  
          }
          // Send the reply back to our client.
          putMessage( output, reply.toString().getBytes() );
              
          // Get the next command.
          request = new String( getMessage( input ) );
        }
      }
    } catch ( IOException e ) {
      System.out.println( "IO Error: " + e );
    } catch( GeneralSecurityException e ){
      System.err.println( "Encryption error: " + e );
    } finally {
      try {
        // Close the socket on the way out.
        sock.close();
      } catch ( Exception e ) {
      }
    }
  }

  /** Esentially, the main method for our server, as an instance method
      so we can access non-static fields. */
  private void run( String[] args ) {
    ServerSocket serverSocket = null;
    
    // One-time setup.
    try {
      // Read the map and the public keys for all the users.
      readConfig();

      // Open a socket for listening.
      serverSocket = new ServerSocket( PORT_NUMBER );
    } catch( Exception e ){
      System.err.println( "Can't initialize server: " + e );
      e.printStackTrace();
      System.exit( 1 );
    }
     
    // Keep trying to accept new connections and serve them.
    while( true ){
      try {
        // Try to get a new client connection.
        Socket sock = serverSocket.accept();
        
        //Make threads and have it run the handle client method so that many clients can use the server simoultaneously. 
        Thread thread = new Thread() {
          public void run() {
            // Handle interaction with the client
            handleClient( sock );
          }
        };
        thread.start();

      } catch( IOException e ){
        System.err.println( "Failure accepting client " + e );
      }
    }
  }

  public static void main( String[] args ) {
    // Make a server object, so we can have non-static fields.
    Server server = new Server();
    server.run( args );
  }
}